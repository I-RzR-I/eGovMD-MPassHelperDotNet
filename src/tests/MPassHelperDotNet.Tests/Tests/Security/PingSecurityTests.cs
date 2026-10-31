using System;
using System.Globalization;
using System.Threading.Tasks;
using MPassHelperDotNet.Helpers.Messages;
using MPassHelperDotNet.Tests.Helpers.Hosting;
using MPassHelperDotNet.Tests.Helpers.Http;
using MPassHelperDotNet.Tests.Helpers.Runtime;
using MPassHelperDotNet.Tests.Models.Hosting;
using Xunit;
using static MPassHelperDotNet.Tests.Helpers.Kits.SecurityTestKit;

namespace MPassHelperDotNet.Tests.Tests.Security
{
    [Trait(TestAreas.Trait, TestAreas.Security)]
    public class PingSecurityTests
    {
        [Fact]
        public async Task Ping_ClosedPort_ReturnsOnlyFixedMessage_Test()
        {
            using var port = new ClosedLoopbackPort();
            using var context = ServiceFactory.Create(new MPassTestSettings
            {
                SamlLoginDestination = port.Url("saml/login?probe=marker-value")
            });

            var result = await context.Auth.PingAsync(Ct);

            AssertAccepted(result);
            AssertNoExceptionDetails(result);
            AssertOnlyFixedMessages(result);
            Assert.NotNull(result.Response);
            Assert.False(result.Response.IsSuccess);
            Assert.Equal(DefaultMessages.PingCommunicationProblem, result.Response.Message);

            var message = result.Response.Message;
            Assert.DoesNotContain("127.0.0.1", message, StringComparison.Ordinal);
            Assert.DoesNotContain(port.Port.ToString(CultureInfo.InvariantCulture), message, StringComparison.Ordinal);
            Assert.DoesNotContain("marker-value", message, StringComparison.Ordinal);
            Assert.DoesNotContain("http", message, StringComparison.OrdinalIgnoreCase);
            Assert.DoesNotContain("Exception", message, StringComparison.OrdinalIgnoreCase);
            Assert.DoesNotContain("refused", message, StringComparison.OrdinalIgnoreCase);
            Assert.DoesNotContain("   at ", message, StringComparison.Ordinal);
            Assert.DoesNotContain(":", message, StringComparison.Ordinal);
        }

        [Fact]
        public async Task Ping_ClosedPort_RepeatedCallsSameMessage_Test()
        {
            using var port = new ClosedLoopbackPort();
            using var context = ServiceFactory.Create(new MPassTestSettings
            {
                SamlLoginDestination = port.Url()
            });

            var first = await context.Auth.PingAsync(Ct);
            var second = await context.Auth.PingAsync(Ct);

            AssertAccepted(first);
            AssertAccepted(second);
            Assert.Equal(DefaultMessages.PingCommunicationProblem, first.Response.Message);
            Assert.Equal(first.Response.Message, second.Response.Message);
            AssertOnlyFixedMessages(first);
            AssertOnlyFixedMessages(second);
        }

        [Fact]
        public void PingProblemText_FixedNoPlaceholders_Test()
        {
            Assert.Equal("Communication problem", DefaultMessages.PingCommunicationProblem);
            Assert.DoesNotContain("{", DefaultMessages.PingCommunicationProblem, StringComparison.Ordinal);
        }
    }
}
