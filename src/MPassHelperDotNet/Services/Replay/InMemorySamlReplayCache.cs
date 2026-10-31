// ***********************************************************************
//  Assembly         : RzR.Shared.eGovMD.MPassHelperDotNet
//  Author           : RzR
//  Created On       : 2026-09-25 16:07
// 
//  Last Modified By : RzR
//  Last Modified On : 2026-09-25 20:07
// ***********************************************************************
//  <copyright file="InMemorySamlReplayCache.cs" company="">
//   Copyright (c) RzR. All rights reserved.
//  </copyright>
// 
//  <summary>
//  </summary>
// ***********************************************************************

#region U S A G E S

using System;
using System.Collections.Concurrent;
using System.Collections.Generic;
using System.Threading;
using System.Threading.Tasks;
using MPassHelperDotNet.Abstractions.Services.Replay;
using RzR.Extensions.Domain.Primitives;

#endregion

namespace MPassHelperDotNet.Services.Replay
{
    /// <summary>
    ///     In-memory SAML message replay cache (default implementation).
    /// </summary>
    /// <remarks>
    ///     The cache is local to the current process: register a distributed <see cref="ISamlReplayCache" />
    ///     when the service runs on more than one instance.
    ///     Expired entries are purged every 1 000 additions and whenever the cache is full; only one caller purges at a time.
    ///     The cache holds at most 100 000 entries; when it is full and nothing has expired, or another caller is
    ///     already purging, <see cref="TryAddAsync" /> returns <see langword="false" /> and the message is rejected (fail closed).
    /// </remarks>
    public sealed class InMemorySamlReplayCache : ISamlReplayCache
    {
        /// <summary>
        ///     (Immutable)
        ///     Default maximum number of entries.
        /// </summary>
        internal const int DefaultMaxEntries = 100000;

        /// <summary>
        ///     (Immutable)
        ///     Default number of additions between two purges of expired entries.
        /// </summary>
        internal const int DefaultPurgeInterval = 1000;

        /// <summary>
        ///     Message ID -> expiration time
        /// </summary>

        /// <summary>
        ///     (Immutable) the entries.
        /// </summary>
        private readonly ConcurrentDictionary<string, DateTimeOffset> _entries =
            new ConcurrentDictionary<string, DateTimeOffset>(StringComparer.Ordinal);

        /// <summary>
        ///     (Immutable)
        ///     Maximum number of entries.
        /// </summary>
        private readonly int _maxEntries;

        /// <summary>
        ///     (Immutable)
        ///     Number of additions between two purges.
        /// </summary>
        private readonly int _purgeInterval;

        /// <summary>
        ///     (Immutable)
        ///     Time provider.
        /// </summary>
        private readonly TimeProvider _timeProvider;

        /// <summary>
        ///     Additions since the last purge.
        /// </summary>
        private int _addsSincePurge;

        /// <summary>
        ///     Reserved entry slots (stored entries plus additions in progress)
        /// </summary>
        private int _count;

        /// <summary>
        ///     1 while a caller purges expired entries, otherwise 0.
        /// </summary>
        private int _purging;

        /// <summary>
        ///     Initializes a new instance of the <see cref="MPassHelperDotNet.Services.Replay.InMemorySamlReplayCache" />
        ///     class.
        /// </summary>
        /// <param name="timeProvider">Required. Time provider used to decide entry expiration.</param>
        public InMemorySamlReplayCache(TimeProvider timeProvider)
            : this(timeProvider, DefaultMaxEntries, DefaultPurgeInterval)
        {
        }

        /// <summary>
        ///     Initializes a new instance of the <see cref="MPassHelperDotNet.Services.Replay.InMemorySamlReplayCache" />
        ///     class.
        /// </summary>
        /// <exception cref="ArgumentOutOfRangeException">
        ///     Thrown when one or more arguments are outside the required range.
        /// </exception>
        /// <exception cref="ArgumentNullException">
        ///     Thrown when one or more required arguments are null.
        /// </exception>
        /// <param name="timeProvider">Required. Time provider used to decide entry expiration.</param>
        /// <param name="maxEntries">Required. Maximum number of entries (greater than zero).</param>
        /// <param name="purgeInterval">
        ///     Required. Number of additions between two purges (greater than zero).
        /// </param>
        internal InMemorySamlReplayCache(TimeProvider timeProvider, int maxEntries, int purgeInterval)
        {
            if (maxEntries <= 0)
                throw new ArgumentOutOfRangeException(nameof(maxEntries));

            if (purgeInterval <= 0)
                throw new ArgumentOutOfRangeException(nameof(purgeInterval));

            _timeProvider = timeProvider ?? throw new ArgumentNullException(nameof(timeProvider));
            _maxEntries = maxEntries;
            _purgeInterval = purgeInterval;
        }

        /// <inheritdoc />
        public Task<bool> TryAddAsync(string messageId, DateTimeOffset expiresAtUtc, 
            CancellationToken cancellationToken = default)
        {
            cancellationToken.ThrowIfCancellationRequested();

            if (string.IsNullOrEmpty(messageId))
                throw new ArgumentNullException(nameof(messageId));

            var now = _timeProvider.GetUtcNow();

            var addsSincePurge = Interlocked.Increment(ref _addsSincePurge);
            if (addsSincePurge >= _purgeInterval &&
                Interlocked.CompareExchange(ref _addsSincePurge, 0, addsSincePurge) == addsSincePurge)
                TryPurgeExpired(now);

            return Task.FromResult(TryAddCore(messageId, expiresAtUtc, now));
        }

        /// <summary>
        ///     Atomic set-if-absent; an expired entry with the same ID is replaced.
        /// </summary>
        /// <param name="messageId">Message key.</param>
        /// <param name="expiresAtUtc">Entry expiration time.</param>
        /// <param name="now">Current UTC time.</param>
        /// <returns>
        ///     Return true if the entry was added, false on replay or when the cache is full.
        /// </returns>
        private bool TryAddCore(string messageId, DateTimeOffset expiresAtUtc, DateTimeOffset now)
        {
            while (true)
            {
                if (_entries.TryGetValue(messageId, out var existingExpiresAtUtc))
                {
                    if (existingExpiresAtUtc > now)
                        return false;

                    if (_entries.TryUpdate(messageId, expiresAtUtc, existingExpiresAtUtc))
                        return true;

                    continue;
                }

                if (TryReserveSlot(now).IsFalse())
                    return false;

                if (_entries.TryAdd(messageId, expiresAtUtc))
                    return true;

                Interlocked.Decrement(ref _count);
            }
        }

        /// <summary>
        ///     Reserve one entry slot, purging expired entries once when the cache is full.
        /// </summary>
        /// <param name="now">Current UTC time.</param>
        /// <returns>
        ///     Return true if a slot was reserved; false when the cache is full or another caller is
        ///     purging.
        /// </returns>
        private bool TryReserveSlot(DateTimeOffset now)
        {
            if (Interlocked.Increment(ref _count) <= _maxEntries)
                return true;

            Interlocked.Decrement(ref _count);

            if (TryPurgeExpired(now).IsFalse())
                return false;

            if (Interlocked.Increment(ref _count) <= _maxEntries)
                return true;

            Interlocked.Decrement(ref _count);

            return false;
        }

        /// <summary>
        ///     Remove every expired entry, unless another caller is already purging.
        /// </summary>
        /// <param name="now">Current UTC time.</param>
        /// <returns>
        ///     Return true if this caller ran the purge; false when another caller is purging.
        /// </returns>
        private bool TryPurgeExpired(DateTimeOffset now)
        {
            if (Interlocked.CompareExchange(ref _purging, 1, 0) != 0)
                return false;

            try
            {
                ICollection<KeyValuePair<string, DateTimeOffset>> entries = _entries;
                foreach (var entry in _entries)
                {
                    if (entry.Value <= now && entries.Remove(entry))
                        Interlocked.Decrement(ref _count);
                }
            }
            finally
            {
                Volatile.Write(ref _purging, 0);
            }

            return true;
        }
    }
}
