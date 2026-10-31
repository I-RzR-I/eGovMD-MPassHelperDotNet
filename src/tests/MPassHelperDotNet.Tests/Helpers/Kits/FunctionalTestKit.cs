using System;
using System.Collections.Generic;
using System.Linq;
using System.Text.RegularExpressions;
using System.Xml;
using RzR.ResultMessage.Abstractions;
using RzR.ResultMessage.Enums;
using MPassHelperDotNet.Tests.Helpers.Saml;
using Xunit;

namespace MPassHelperDotNet.Tests.Helpers.Kits
{
    internal static class FunctionalTestKit
    {
        internal static readonly Regex RequestIdPattern = new Regex("^_[0-9a-f]{32}$", RegexOptions.CultureInvariant);

        internal static IReadOnlyList<string> Texts(IResult result)
        {
            if (result?.Messages == null)
                return Array.Empty<string>();

            var texts = new List<string>();
            foreach (var message in result.Messages)
            {
                if (message == null)
                    continue;

                if (!string.IsNullOrEmpty(message.Code))
                    texts.Add(message.Code);
                if (!string.IsNullOrEmpty(message.Message?.Info))
                    texts.Add(message.Message.Info);
                if (message.Message?.Details != null)
                    texts.AddRange(message.Message.Details.Where(detail => !string.IsNullOrEmpty(detail)));
            }

            return texts;
        }

        internal static void AssertFailureWith(IResult result, string expectedMessage)
        {
            Assert.NotNull(result);
            Assert.False(result.IsSuccess, "Expected Failure but got Success.");
            var texts = Texts(result);
            Assert.True(texts.Any(text => text.Contains(expectedMessage, StringComparison.Ordinal)),
                $"Expected message '{expectedMessage}' not found. Actual: [{string.Join(" | ", texts)}]");
            AssertNoExceptionAttached(result);
        }

        internal static void AssertFailure(IResult result)
        {
            Assert.NotNull(result);
            Assert.False(result.IsSuccess, "Expected Failure but got Success.");
            AssertNoExceptionAttached(result);
        }

        internal static void AssertSuccess(IResult result)
        {
            Assert.NotNull(result);
            Assert.True(result.IsSuccess, "Expected Success. Messages: [" + string.Join(" | ", Texts(result)) + "]");
        }

        internal static void AssertNoExceptionAttached(IResult result)
        {
            if (result?.Messages == null)
                return;

            Assert.DoesNotContain(result.Messages, message => message != null && message.MessageType == MessageType.Exception);
            foreach (var text in Texts(result))
            {
                Assert.DoesNotContain("Exception", text, StringComparison.Ordinal);
                Assert.DoesNotContain("   at ", text, StringComparison.Ordinal);
            }
        }

        internal static XmlDocument DecodeOnceToXml(string base64)
        {
            Assert.False(string.IsNullOrEmpty(base64));
            var xml = FixtureEncoding.FromBase64(base64);
            Assert.StartsWith("<", xml.TrimStart(), StringComparison.Ordinal);

            return FixtureEncoding.LoadXml(xml);
        }

        internal static string NewRequestId() => "_" + Guid.NewGuid().ToString("N");
    }
}
