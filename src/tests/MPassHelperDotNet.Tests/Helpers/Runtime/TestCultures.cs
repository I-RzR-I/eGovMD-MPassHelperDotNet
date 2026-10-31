using Xunit;

namespace MPassHelperDotNet.Tests.Helpers.Runtime
{
    public static class TestCultures
    {
        public const string Turkish = "tr-TR";

        public const string Romanian = "ro-RO";

        public const string English = "en-US";

        public static TheoryData<string> All => new TheoryData<string> { Turkish, Romanian, English };
    }
}
