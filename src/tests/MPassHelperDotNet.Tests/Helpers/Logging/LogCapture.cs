using System;
using System.Collections.Concurrent;
using System.Collections.Generic;
using System.Linq;
using Microsoft.Extensions.Logging;
using MPassHelperDotNet.Tests.Models.Logging;

namespace MPassHelperDotNet.Tests.Helpers.Logging
{
    internal sealed class LogCapture : ILoggerProvider
    {
        private readonly ConcurrentQueue<LogCaptureEntry> _entries = new ConcurrentQueue<LogCaptureEntry>();

        internal IReadOnlyList<LogCaptureEntry> Entries => _entries.ToArray();

        internal string AllText => string.Join(System.Environment.NewLine, Entries.Select(e => e.ToFullText()));

        public ILogger CreateLogger(string categoryName) => new CaptureLogger(this, categoryName);

        internal bool Contains(string fragment) => AllText.IndexOf(fragment, StringComparison.Ordinal) >= 0;

        internal IReadOnlyList<LogCaptureEntry> ForCategory(string categoryPrefix)
            => Entries.Where(e => e.Category != null && e.Category.StartsWith(categoryPrefix, StringComparison.Ordinal)).ToList();

        internal void Clear()
        {
            while (_entries.TryDequeue(out _))
            {
            }
        }

        public void Dispose()
        {
        }

        internal void Add(LogCaptureEntry entry) => _entries.Enqueue(entry);
    }
}
