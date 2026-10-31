using System;
using System.Globalization;
using System.Linq;
using System.Net;
using System.Threading;
using System.Threading.Tasks;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Diagnostics.HealthChecks;
using Microsoft.Extensions.Options;
using MPassHelperDotNet.Helpers.Messages;
using MPassHelperDotNet.Models.Client;
using MPassHelperDotNet.Services;
using MPassHelperDotNet.Tests.Helpers.Certificates;
using MPassHelperDotNet.Tests.Helpers.Hosting;
using MPassHelperDotNet.Tests.Helpers.Http;
using MPassHelperDotNet.Tests.Helpers.Kits;
using MPassHelperDotNet.Tests.Helpers.Runtime;
using MPassHelperDotNet.Tests.Models.Hosting;
using MPassHelperDotNet.XDependencyInjection;
using Xunit;

namespace MPassHelperDotNet.Tests.Tests.Functional
{
    [Trait(TestAreas.Trait, TestAreas.Functional)]
    public class HealthAndPingTests
    {
        [Fact]
        public async Task Health_ValidCerts_Healthy_Test()
        {
            using var context = CreateWithHealth(new MPassTestSettings(), HealthStatus.Unhealthy);

            var report = await RunHealth(context);

            Assert.Equal(HealthStatus.Healthy, report.Status);
        }

        [Fact]
        public async Task Health_IdpCertExpiringIn30Days_Degraded_Test()
        {
            var settings = new MPassTestSettings
            {
                IdentityProviderCertificate = TestCertificates.CreateRsa("CN=Expiring IdP", 2048,
                    TestClock.Epoch.AddDays(-10), TestClock.Epoch.AddDays(10))
            };
            using var context = CreateWithHealth(settings, HealthStatus.Unhealthy);

            var report = await RunHealth(context);

            Assert.Equal(HealthStatus.Degraded, report.Status);
            Assert.Contains("Identity provider certificate", report.Entries["MPass"].Description, StringComparison.Ordinal);
        }

        [Fact]
        public async Task Health_RotationCertExpiringIn30Days_Degraded_Test()
        {
            var settings = new MPassTestSettings();
            settings.IdentityProviderAdditionalCertificates.Add(TestCertificates.CreateRsa("CN=Expiring rotation", 2048,
                TestClock.Epoch.AddDays(-10), TestClock.Epoch.AddDays(20)));
            using var context = CreateWithHealth(settings, HealthStatus.Unhealthy);

            var report = await RunHealth(context);

            Assert.Equal(HealthStatus.Degraded, report.Status);
        }

        [Fact]
        public async Task Health_ClockAdvanced_DegradedThenUnhealthy_Test()
        {
            using var context = CreateWithHealth(new MPassTestSettings(), HealthStatus.Unhealthy);

            context.Time.SetUtcNow(TestCertificates.DefaultNotAfter.AddDays(-10));
            Assert.Equal(HealthStatus.Degraded, (await RunHealth(context)).Status);

            context.Time.SetUtcNow(TestCertificates.DefaultNotAfter.AddDays(1));
            Assert.Equal(HealthStatus.Unhealthy, (await RunHealth(context)).Status);
        }

        [Theory]
        [InlineData(HealthStatus.Unhealthy)]
        [InlineData(HealthStatus.Degraded)]
        public async Task Health_ExpiredCert_ReportsConfiguredStatus_Test(HealthStatus failureStatus)
        {
            var settings = new MPassTestSettings
            {
                IdentityProviderCertificate = TestCertificates.CreateRsa("CN=Expiring IdP", 2048,
                    TestClock.Epoch.AddDays(-10), TestClock.Epoch.AddDays(10))
            };
            settings.IdentityProviderAdditionalCertificates.Add(TestCertificates.CreateRsa("CN=Expired rotation", 2048,
                TestClock.Epoch.AddDays(-60), TestClock.Epoch.AddDays(-1)));
            using var context = CreateWithHealth(settings, failureStatus);

            var report = await RunHealth(context);

            var entry = report.Entries["MPass"];
            Assert.Equal(failureStatus, entry.Status);
            Assert.Contains("expired", entry.Description, StringComparison.Ordinal);
            Assert.Contains("expires in less than", entry.Description, StringComparison.Ordinal);
        }

        [Fact]
        public async Task Health_MissingServiceCert_Unhealthy_Test()
        {
            using var context = ServiceFactory.Create();
            var monitor = context.Provider.GetRequiredService<IOptionsMonitor<MPassSamlOptions>>();
            monitor.CurrentValue.ServiceCertificate = null;
            var check = new MPassSamlHealthCheck(monitor, context.Time);

            var result = await check.CheckHealthAsync(new HealthCheckContext(), TestContext.Current.CancellationToken);

            Assert.Equal(HealthStatus.Unhealthy, result.Status);
            Assert.Contains("service certificate", result.Description, StringComparison.OrdinalIgnoreCase);
        }

        [Fact]
        public async Task Health_DirectCallValidOptions_Healthy_Test()
        {
            using var context = ServiceFactory.Create();
            var check = new MPassSamlHealthCheck(context.Provider.GetRequiredService<IOptionsMonitor<MPassSamlOptions>>(), context.Time);

            var result = await check.CheckHealthAsync(new HealthCheckContext(), TestContext.Current.CancellationToken);

            Assert.Equal(HealthStatus.Healthy, result.Status);
        }

        [Fact]
        public async Task Ping_Loopback200_SucceedsResponseOk_Test()
        {
            using var server = LoopbackHttpServer.Start(HttpStatusCode.OK);
            using var context = ServiceFactory.Create(new MPassTestSettings { SamlLoginDestination = server.Url() });

            var result = await context.Auth.PingAsync(TestContext.Current.CancellationToken);

            FunctionalTestKit.AssertSuccess(result);
            Assert.True(result.Response.IsSuccess);
            Assert.Equal("Server is available.", result.Response.Message);
            Assert.False(string.IsNullOrEmpty(result.Response.Time));
            Assert.Equal(1, server.RequestCount);
        }

        [Fact]
        public async Task Ping_Loopback503_SucceedsResponseNotOk_Test()
        {
            using var server = LoopbackHttpServer.Start(HttpStatusCode.ServiceUnavailable);
            using var context = ServiceFactory.Create(new MPassTestSettings { SamlLoginDestination = server.Url() });

            var result = await context.Auth.PingAsync(TestContext.Current.CancellationToken);

            FunctionalTestKit.AssertSuccess(result);
            Assert.False(result.Response.IsSuccess);
            Assert.Equal("Communication problem. Server respond with code: ServiceUnavailable", result.Response.Message);
            FunctionalTestKit.AssertNoExceptionAttached(result);
        }

        [Fact]
        public async Task Ping_ClosedPort_SucceedsResponseNotOk_Test()
        {
            using var port = new ClosedLoopbackPort();
            using var context = ServiceFactory.Create(new MPassTestSettings { SamlLoginDestination = port.Url() });

            var result = await context.Auth.PingAsync(TestContext.Current.CancellationToken);

            FunctionalTestKit.AssertSuccess(result);
            Assert.False(result.Response.IsSuccess);
            Assert.Equal(DefaultMessages.PingCommunicationProblem, result.Response.Message);
            Assert.Equal("Communication problem", result.Response.Message);
            Assert.DoesNotContain(port.Port.ToString(CultureInfo.InvariantCulture), result.Response.Message, StringComparison.Ordinal);
            Assert.False(string.IsNullOrEmpty(result.Response.Time));
            Assert.DoesNotContain(result.Messages ?? Enumerable.Empty<RzR.ResultMessage.Abstractions.Models.IMessageModel>(),
                m => m != null && m.MessageType == RzR.ResultMessage.Enums.MessageType.Exception);
            Assert.Single(context.Logs.Entries, e => e.Message.Contains(nameof(context.Auth.PingAsync), StringComparison.Ordinal));
        }

        [Fact]
        public async Task Ping_PreCancelledToken_Throws_Test()
        {
            using var server = LoopbackHttpServer.Start(HttpStatusCode.OK);
            using var context = ServiceFactory.Create(new MPassTestSettings { SamlLoginDestination = server.Url() });
            using var cts = new CancellationTokenSource();
            cts.Cancel();

            await Assert.ThrowsAnyAsync<OperationCanceledException>(() => context.Auth.PingAsync(cts.Token));
            Assert.Equal(0, server.RequestCount);
        }

        private static MPassTestContext CreateWithHealth(MPassTestSettings settings, HealthStatus failureStatus)
            => ServiceFactory.Create(settings, configureAfter: s => s.AddHealthChecks().AddMPassCertificateHealthCheck(failureStatus));

        private static Task<HealthReport> RunHealth(MPassTestContext context)
            => context.Provider.GetRequiredService<HealthCheckService>().CheckHealthAsync(TestContext.Current.CancellationToken);
    }
}
