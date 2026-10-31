using System;
using System.Collections.Concurrent;
using System.Threading;
using Microsoft.Extensions.Logging;

namespace MPassHelperDotNet.Tests.Helpers.Fakes
{
    internal sealed class ThrowOnceLogger<T> : ILogger<T>
    {
        private int _calls;

        internal bool Thrown => Volatile.Read(ref _calls) > 0;

        internal ConcurrentQueue<(string Message, Exception Exception)> Entries { get; } = new ConcurrentQueue<(string, Exception)>();

        public IDisposable BeginScope<TState>(TState state) => null;

        public bool IsEnabled(LogLevel logLevel) => true;

        public void Log<TState>(LogLevel logLevel, EventId eventId, TState state, Exception exception, Func<TState, Exception, string> formatter)
        {
            if (Interlocked.Increment(ref _calls) == 1)
                throw new InvalidOperationException("forced test logger failure");

            Entries.Enqueue((formatter != null ? formatter(state, exception) : Convert.ToString(state), exception));
        }
    }
}
