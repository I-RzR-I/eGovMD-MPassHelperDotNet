using System;
using Microsoft.Extensions.Time.Testing;

namespace MPassHelperDotNet.Tests.Helpers.Runtime
{
    internal static class TestClock
    {
        internal static readonly DateTimeOffset Epoch = new DateTimeOffset(2026, 6, 1, 10, 0, 0, TimeSpan.Zero);

        internal static FakeTimeProvider CreateFake() => CreateFake(Epoch);

        internal static FakeTimeProvider CreateFake(DateTimeOffset start) => new FakeTimeProvider(start);
    }
}
