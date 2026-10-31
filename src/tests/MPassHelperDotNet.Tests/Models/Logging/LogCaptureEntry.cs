using System;
using System.Collections.Generic;
using System.Text;
using Microsoft.Extensions.Logging;

namespace MPassHelperDotNet.Tests.Models.Logging
{
    internal sealed class LogCaptureEntry
    {
        internal LogCaptureEntry(string category, LogLevel level, EventId eventId, string message, Exception exception,
            IReadOnlyList<KeyValuePair<string, object>> properties)
        {
            Category = category;
            Level = level;
            EventId = eventId;
            Message = message;
            Exception = exception;
            Properties = properties;
        }

        internal string Category { get; }

        internal LogLevel Level { get; }

        internal EventId EventId { get; }

        internal string Message { get; }

        internal Exception Exception { get; }

        internal IReadOnlyList<KeyValuePair<string, object>> Properties { get; }

        internal string ToFullText()
        {
            var builder = new StringBuilder();
            builder.Append('[').Append(Level).Append("] ").Append(Category).Append(": ").Append(Message);
            foreach (var property in Properties)
                builder.Append(" | ").Append(property.Key).Append('=').Append(Convert.ToString(property.Value));

            if (Exception != null)
                builder.AppendLine().Append(Exception);

            return builder.ToString();
        }
    }
}
