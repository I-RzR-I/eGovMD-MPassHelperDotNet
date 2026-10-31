using System;
using System.Collections.Concurrent;
using System.Collections.Generic;
using System.Linq;
using System.Threading;
using System.Threading.Tasks;
using MPassHelperDotNet.Abstractions.Services.Replay;

namespace MPassHelperDotNet.Tests.Helpers.Fakes
{
    internal sealed class KeyRecordingReplayCache : ISamlReplayCache
    {
        private readonly ConcurrentDictionary<string, DateTimeOffset> _entries = new ConcurrentDictionary<string, DateTimeOffset>(StringComparer.Ordinal);

        internal IReadOnlyCollection<string> Keys => _entries.Keys.ToList();

        public Task<bool> TryAddAsync(string messageId, DateTimeOffset expiresAtUtc, CancellationToken cancellationToken = default)
            => Task.FromResult(_entries.TryAdd(messageId, expiresAtUtc));
    }
}
