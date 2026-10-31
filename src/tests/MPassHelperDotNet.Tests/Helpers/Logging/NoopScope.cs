using System;

namespace MPassHelperDotNet.Tests.Helpers.Logging
{
    internal sealed class NoopScope : IDisposable
    {
        internal static readonly NoopScope Instance = new NoopScope();

        public void Dispose()
        {
        }
    }
}
