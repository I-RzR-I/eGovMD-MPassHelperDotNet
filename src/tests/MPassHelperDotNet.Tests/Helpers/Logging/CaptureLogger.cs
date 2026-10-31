using System;
using System.Collections.Generic;
using System.Linq;
using Microsoft.Extensions.Logging;
using MPassHelperDotNet.Tests.Models.Logging;

namespace MPassHelperDotNet.Tests.Helpers.Logging
{
    internal sealed class CaptureLogger : ILogger
    {
        private readonly LogCapture _owner;
        private readonly string _category;

        internal CaptureLogger(LogCapture owner, string category)
        {
            _owner = owner;
            _category = category;
        }

        IDisposable ILogger.BeginScope<TState>(TState state) => NoopScope.Instance;

        bool ILogger.IsEnabled(LogLevel logLevel) => logLevel != LogLevel.None;

        void ILogger.Log<TState>(LogLevel logLevel, EventId eventId, TState state, Exception exception, Func<TState, Exception, string> formatter)
        {
            if (logLevel == LogLevel.None)
                return;

            var message = formatter != null ? formatter(state, exception) : Convert.ToString(state);
            var properties = state is IEnumerable<KeyValuePair<string, object>> pairs
                ? pairs.ToList()
                : new List<KeyValuePair<string, object>>();

            _owner.Add(new LogCaptureEntry(_category, logLevel, eventId, message, exception, properties));
        }
    }
}
