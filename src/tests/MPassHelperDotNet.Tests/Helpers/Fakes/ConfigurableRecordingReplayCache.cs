using System;
using System.Collections.Concurrent;
using System.Collections.Generic;
using System.Linq;
using System.Threading;
using System.Threading.Tasks;
using MPassHelperDotNet.Abstractions.Services.Replay;

namespace MPassHelperDotNet.Tests.Helpers.Fakes
{
    internal sealed class ConfigurableRecordingReplayCache : ISamlReplayCache
    {
        private readonly ConcurrentDictionary<string, DateTimeOffset> _entries = new ConcurrentDictionary<string, DateTimeOffset>(StringComparer.Ordinal);
        private readonly ConcurrentQueue<CancellationToken> _tokens = new ConcurrentQueue<CancellationToken>();

        internal Action OnAdd { get; set; }

        internal Func<Exception> Throw { get; set; }

        internal IReadOnlyCollection<string> Keys => _entries.Keys.ToList();

        internal IReadOnlyCollection<CancellationToken> Tokens => _tokens.ToList();

        public Task<bool> TryAddAsync(string messageId, DateTimeOffset expiresAtUtc, CancellationToken cancellationToken = default)
        {
            _tokens.Enqueue(cancellationToken);
            if (Throw != null)
                throw Throw();

            OnAdd?.Invoke();

            return Task.FromResult(_entries.TryAdd(messageId, expiresAtUtc));
        }
    }
}
