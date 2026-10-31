using System;
using System.Collections.Concurrent;
using System.Threading;
using System.Threading.Tasks;
using MPassHelperDotNet.Abstractions.Services.Replay;
using MPassHelperDotNet.Services.Replay;
using MPassHelperDotNet.Tests.Helpers.Runtime;
using Xunit;

namespace MPassHelperDotNet.Tests.Helpers.Fakes
{
    internal sealed class ExpiryRecordingReplayCache : ISamlReplayCache
    {
        private readonly InMemorySamlReplayCache _inner = new InMemorySamlReplayCache(TestClock.CreateFake());

        internal ConcurrentQueue<(string MessageId, DateTimeOffset ExpiresAtUtc)> Calls { get; } =
            new ConcurrentQueue<(string, DateTimeOffset)>();

        public Task<bool> TryAddAsync(string messageId, DateTimeOffset expiresAtUtc, CancellationToken cancellationToken = default)
        {
            Calls.Enqueue((messageId, expiresAtUtc));

            return _inner.TryAddAsync(messageId, expiresAtUtc, cancellationToken);
        }

        internal DateTimeOffset ExpiryOf(string messageId)
            => Assert.Single(Calls, c => string.Equals(c.MessageId, messageId, StringComparison.Ordinal)).ExpiresAtUtc;
    }
}
