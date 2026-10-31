using System;
using System.Collections.Generic;
using System.Linq;
using System.Net;
using System.Security.Cryptography.X509Certificates;
using System.Threading;
using System.Threading.Tasks;
using System.Xml;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Diagnostics.HealthChecks;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;
using MPassHelperDotNet.Abstractions.Services.Replay;
using MPassHelperDotNet.Configurations.Certificate;
using MPassHelperDotNet.Helpers;
using MPassHelperDotNet.Helpers.Messages;
using MPassHelperDotNet.Helpers.SAML;
using MPassHelperDotNet.Models.Client;
using MPassHelperDotNet.Models.Dto.AuthService.ExternalLogoutRequest;
using MPassHelperDotNet.Models.Dto.AuthService.LoginResponse;
using MPassHelperDotNet.Models.Dto.RequestBuilder.LogOutResponse;
using MPassHelperDotNet.Services;
using MPassHelperDotNet.Tests.Helpers.Certificates;
using MPassHelperDotNet.Tests.Helpers.Fakes;
using MPassHelperDotNet.Tests.Helpers.Hosting;
using MPassHelperDotNet.Tests.Helpers.Http;
using MPassHelperDotNet.Tests.Helpers.Kits;
using MPassHelperDotNet.Tests.Helpers.Logging;
using MPassHelperDotNet.Tests.Helpers.Runtime;
using MPassHelperDotNet.Tests.Helpers.Saml;
using MPassHelperDotNet.Tests.Helpers.Signing;
using MPassHelperDotNet.Tests.Models.Hosting;
using MPassHelperDotNet.Tests.Models.Signing;
using MPassHelperDotNet.XDependencyInjection;
using Xunit;

namespace MPassHelperDotNet.Tests.Tests.Functional
{
    [Trait(TestAreas.Trait, TestAreas.Functional)]
    public class ValidationDiagnosticsAndCertificateRotationTests
    {
        private const string Prefix = "MPassSamlOptions.";
        private const string SessionIndex = "_session-validation-01";

        [Theory]
        [InlineData("SamlLoginDestination", " https://idp.test.local/saml/login")]
        [InlineData("SamlLogoutDestination", "https://idp.test.local/saml/logout ")]
        [InlineData("SamlServiceLoginDestination", "\thttps://sp.test.local/saml/acs")]
        [InlineData("SamlServiceLogoutDestination", "https://sp.test.local/saml/logout-response\n")]
        [InlineData("SamlServiceSingleLogoutDestination", " https://sp.test.local/saml/slo ")]
        [InlineData("SamlRequestIssuer", "https://sp.test.local/metadata ")]
        [InlineData("IdentityProviderIssuer", " https://idp.test.local/metadata")]
        public async Task HostStart_PaddedSetting_FailsNamingSetting_Test(string setting, string value)
        {
            using var files = new TestCertificateFiles();
            var settings = new MPassTestSettings();
            settings.AdditionalConfiguration[setting] = value;
            using var host = ServiceFactory.CreateHost(settings, files);

            var exception = await Assert.ThrowsAsync<OptionsValidationException>(() => host.StartAsync(TestContext.Current.CancellationToken));

            Assert.Contains(string.Format(OptionsValidationMessages.SettingHasSurroundingWhitespace, Prefix + setting), exception.Failures);
        }

        [Fact]
        public async Task HostStart_TwoPaddedOneMissing_AllReported_Test()
        {
            using var files = new TestCertificateFiles();
            var settings = new MPassTestSettings { SamlRequestIssuer = null };
            settings.AdditionalConfiguration["SamlLoginDestination"] = MPassTestSettings.DefaultIdpLoginUrl + " ";
            settings.AdditionalConfiguration["IdentityProviderIssuer"] = " " + MPassTestSettings.DefaultIdpIssuer;
            using var host = ServiceFactory.CreateHost(settings, files);

            var exception = await Assert.ThrowsAsync<OptionsValidationException>(() => host.StartAsync(TestContext.Current.CancellationToken));

            var failures = exception.Failures.ToList();
            Assert.Contains(string.Format(OptionsValidationMessages.SettingHasSurroundingWhitespace, Prefix + "SamlLoginDestination"), failures);
            Assert.Contains(string.Format(OptionsValidationMessages.SettingHasSurroundingWhitespace, Prefix + "IdentityProviderIssuer"), failures);
            Assert.Contains(string.Format(DefaultMessages.ArgumentNullMessage, Prefix + "SamlRequestIssuer"), failures);
        }

        public static TheoryData<string, string, string> InvalidSettingMessages => new TheoryData<string, string, string>
        {
            { "SamlLoginDestination", "not-a-url", string.Format(OptionsValidationMessages.DestinationInvalid, Prefix + "SamlLoginDestination") },
            { "SamlLogoutDestination", "ftp://idp.test.local/logout", string.Format(OptionsValidationMessages.DestinationInvalid, Prefix + "SamlLogoutDestination") },
            { "SamlMessageTimeout", "00:31:00", string.Format(OptionsValidationMessages.MessageTimeoutOutOfRange, Prefix + "SamlMessageTimeout", DefaultStaticInfo.MaxSamlMessageTimeout) },
            { "SamlClockSkew", "00:05:01", string.Format(OptionsValidationMessages.ClockSkewOutOfRange, Prefix + "SamlClockSkew", DefaultStaticInfo.MaxSamlClockSkew) },
            { "SamlMessageMaxLength", "0", string.Format(OptionsValidationMessages.MessageMaxLengthInvalid, Prefix + "SamlMessageMaxLength") },
            { "IdentityProviderIssuer", "<MPass IdP metadata EntityID>", string.Format(OptionsValidationMessages.SettingIsPlaceholder, Prefix + "IdentityProviderIssuer") },
            { "SamlRequestIssuer", "__SET_ME__", string.Format(OptionsValidationMessages.SettingIsPlaceholder, Prefix + "SamlRequestIssuer") }
        };

        [Theory]
        [MemberData(nameof(InvalidSettingMessages))]
        public async Task HostStart_InvalidSetting_UsesDefaultMessage_Test(string setting, string value, string expected)
        {
            using var files = new TestCertificateFiles();
            var settings = new MPassTestSettings();
            settings.AdditionalConfiguration[setting] = value;
            using var host = ServiceFactory.CreateHost(settings, files);

            var exception = await Assert.ThrowsAsync<OptionsValidationException>(() => host.StartAsync(TestContext.Current.CancellationToken));

            Assert.Contains(expected, exception.Failures);
        }

        [Fact]
        public async Task HostStart_CertProblems_UseDefaultMessages_Test()
        {
            using var files = new TestCertificateFiles();
            var idpWithKey = TestCertificates.IdpRotation;
            var settings = new MPassTestSettings
            {
                ServiceCertificate = TestCertificates.Rsa1024,
                IdentityProviderCertificatePath = files.WritePfx(idpWithKey, string.Empty)
            };
            using var host = ServiceFactory.CreateHost(settings, files);

            var exception = await Assert.ThrowsAsync<OptionsValidationException>(() => host.StartAsync(TestContext.Current.CancellationToken));

            var failures = exception.Failures.ToList();
            Assert.Contains(string.Format(OptionsValidationMessages.CertificateRsaKeyTooSmall, Prefix + "ServiceCertificate", 2048), failures);
            Assert.Contains(string.Format(OptionsValidationMessages.IdentityProviderCertificateWithPrivateKey,
                $"{Prefix}IdentityProviderCertificates ({idpWithKey.Thumbprint})"), failures);
        }

        [Fact]
        public async Task HostStart_WrongPassword_UsesDefaultMessage_Test()
        {
            using var files = new TestCertificateFiles();
            var settings = new MPassTestSettings
            {
                ServiceCertificatePath = null,
                ServiceCertificatePassword = "wrong-password"
            };
            settings.ServiceCertificatePath = files.WritePfx(TestCertificates.Sp, MPassTestSettings.DefaultPfxPassword);
            using var host = ServiceFactory.CreateHost(settings, files);

            var exception = await Assert.ThrowsAsync<OptionsValidationException>(() => host.StartAsync(TestContext.Current.CancellationToken));

            Assert.Contains(string.Format(OptionsValidationMessages.ServiceCertificateNotLoaded,
                Prefix + "ServiceCertificatePath", Prefix + "ServiceCertificatePassword"), exception.Failures);
        }

        [Fact]
        public async Task GetUserData_CancelEarly_NoConsume_Test()
        {
            var cache = new ConfigurableRecordingReplayCache();
            var time = new ArmedTimeProvider(TestClock.Epoch);
            using var context = ServiceFactory.Create(time: time, configureAfter: s => s.AddSingleton<ISamlReplayCache>(cache));
            var requestId = FunctionalTestKit.NewRequestId();
            var dto = new GetUserDataFromAuthResponseDto { SamlResponse = context.SignedBase64(context.NewLoginResponse(requestId)), AuthRequestId = requestId };
            var auth = context.Auth;
            using var cts = new CancellationTokenSource();
            time.Arm(() => cts.Cancel());

            await Assert.ThrowsAnyAsync<OperationCanceledException>(() => auth.GetUserDataFromAuthResponseAsync(dto, cts.Token));

            Assert.True(time.Fired, "The clock hook did not run inside the call; the test did not exercise the window.");
            Assert.Empty(cache.Keys);
            var retry = await auth.GetUserDataFromAuthResponseAsync(dto, TestContext.Current.CancellationToken);
            FunctionalTestKit.AssertSuccess(retry);
            Assert.Equal(2, cache.Keys.Count);
        }

        [Fact]
        public async Task GetUserData_CancelInCommit_CommitsBothKeys_Test()
        {
            using var cts = new CancellationTokenSource();
            var cache = new ConfigurableRecordingReplayCache { OnAdd = () => cts.Cancel() };
            using var context = ServiceFactory.Create(configureAfter: s => s.AddSingleton<ISamlReplayCache>(cache));
            var requestId = FunctionalTestKit.NewRequestId();
            var fixture = context.NewLoginResponse(requestId);
            var dto = new GetUserDataFromAuthResponseDto { SamlResponse = context.SignedBase64(fixture), AuthRequestId = requestId };

            var result = await Record.ExceptionAsync(() => context.Auth.GetUserDataFromAuthResponseAsync(dto, cts.Token));

            Assert.True(result == null || result is OperationCanceledException);
            Assert.Contains(DefaultStaticInfo.ReplayKeyResponse + fixture.Id, cache.Keys);
            Assert.Contains(DefaultStaticInfo.ReplayKeyAssertion + fixture.Assertions[0].Id, cache.Keys);
            Assert.All(cache.Tokens, token => Assert.False(token.CanBeCanceled));
        }

        [Fact]
        public async Task GetUserData_InvalidXml_WarningLoggedTypeOnly_Test()
        {
            using var context = ServiceFactory.Create();
            const string marker = "MarkerValue7a1f";
            var saml = FixtureEncoding.ToBase64("<saml2p:Response xmlns:saml2p=\"urn:oasis:names:tc:SAML:2.0:protocol\"><" + marker + ">");

            var result = await context.Auth.GetUserDataFromAuthResponseAsync(
                new GetUserDataFromAuthResponseDto
                {
                    SamlResponse = saml, 
                    AuthRequestId = FunctionalTestKit.NewRequestId()
                },
                TestContext.Current.CancellationToken);

            FunctionalTestKit.AssertFailure(result);
            var entries = context.Logs.Entries;
            Assert.NotEmpty(entries);
            Assert.DoesNotContain(entries, e => e.Level >= LogLevel.Error);
            Assert.Contains(entries, e => e.Level == LogLevel.Warning && e.ToFullText().Contains(nameof(XmlException), StringComparison.Ordinal));
            Assert.All(entries, e => Assert.Null(e.Exception));
            Assert.False(context.Logs.Contains(marker));
        }

        [Fact]
        public async Task GetUserData_ServiceError_LoggedWithException_Test()
        {
            var cache = new ConfigurableRecordingReplayCache { Throw = () => new InvalidOperationException("store-down") };
            using var context = ServiceFactory.Create(configureAfter: s => s.AddSingleton<ISamlReplayCache>(cache));
            var requestId = FunctionalTestKit.NewRequestId();

            var result = await context.Auth.GetUserDataFromAuthResponseAsync(
                new GetUserDataFromAuthResponseDto
                {
                    SamlResponse = context.SignedBase64(context.NewLoginResponse(requestId)),
                    AuthRequestId = requestId
                },
                TestContext.Current.CancellationToken);

            FunctionalTestKit.AssertFailureWith(result, AuthDataMessages.ErrorOnGenerateAuthUserData);
            Assert.Null(result.Response);
            var entry = Assert.Single(context.Logs.Entries, e => e.Exception != null);
            Assert.Equal(LogLevel.Warning, entry.Level);
            Assert.IsType<InvalidOperationException>(entry.Exception);
            Assert.Contains(nameof(context.Auth.GetUserDataFromAuthResponseAsync), entry.Message, StringComparison.Ordinal);
            Assert.DoesNotContain(context.Logs.Entries, e => e.Level >= LogLevel.Error);
        }

        [Fact]
        public async Task GetUserData_FormatError_LoggedTypeOperation_Test()
        {
            const string marker = "SecretMarker91c";
            var cache = new ConfigurableRecordingReplayCache
            {
                Throw = () => new FormatException(marker)
            };
            using var context = ServiceFactory.Create(configureAfter: s => s.AddSingleton<ISamlReplayCache>(cache));
            var requestId = FunctionalTestKit.NewRequestId();

            var result = await context.Auth.GetUserDataFromAuthResponseAsync(
                new GetUserDataFromAuthResponseDto
                {
                    SamlResponse = context.SignedBase64(context.NewLoginResponse(requestId)),
                    AuthRequestId = requestId
                },
                TestContext.Current.CancellationToken);

            FunctionalTestKit.AssertFailure(result);
            var entry = Assert.Single(context.Logs.Entries, e => e.ToFullText().Contains(nameof(FormatException), StringComparison.Ordinal));
            Assert.Equal(LogLevel.Warning, entry.Level);
            Assert.Null(entry.Exception);
            Assert.Contains(nameof(context.Auth.GetUserDataFromAuthResponseAsync), entry.Message, StringComparison.Ordinal);
            Assert.False(context.Logs.Contains(marker));
        }

        [Fact]
        public async Task BuildLogoutResponse_Exception_LoggedByBuilder_Test()
        {
            var cache = new ConfigurableRecordingReplayCache { Throw = () => new InvalidOperationException("store-down") };
            using var context = ServiceFactory.Create(configureAfter: s => s.AddSingleton<ISamlReplayCache>(cache));
            var samlRequest = context.SignedBase64(context.NewLogoutRequest(SamlFixtures.DefaultNameId, SessionIndex));

            var result = await context.Builder.BuildLogOutResponseAsync(new BuildLogOutResponseDto
            {
                SamlRequest = samlRequest,
                UserIdentifierId = SamlFixtures.DefaultNameId,
                UserSessionIndexId = SessionIndex
            }, TestContext.Current.CancellationToken);

            FunctionalTestKit.AssertFailureWith(result, RequestBuilderMessages.ErrorBuildLogOutResponse);
            var entry = Assert.Single(context.Logs.ForCategory(typeof(MPassBuilderService).FullName), e => e.Exception != null);
            Assert.Equal(LogLevel.Warning, entry.Level);
            Assert.DoesNotContain(context.Logs.Entries, e => e.Level >= LogLevel.Error);
        }

        [Fact]
        public void VerifySignature_CryptoError_NotVerifiedLogged_Test()
        {
            var logs = new LogCapture();
            var logger = logs.CreateLogger("MPassHelperDotNet.Tests.Verifier");
            var settings = new MPassTestSettings();
            var document = FixtureEncoding.Reparse(FixtureSigner.Sign(SamlFixtureBuilder.Build(
                SamlFixtures.LoginResponse(settings, TestClock.Epoch, FunctionalTestKit.NewRequestId()))));
            var disposed = TestCertificates.PublicOnly(TestCertificates.Idp);
            disposed.Dispose();
            var certificates = new X509Certificate2Collection { disposed };

            var result = SamlMessageLoadAndVerifyHelper.VerifySignature(document, certificates, "Response", false, logger);

            Assert.False(result.IsSuccess && result.Response, "A verifier that cannot use the certificate must not accept the document.");
            Assert.DoesNotContain(logs.Entries, e => e.Level >= LogLevel.Error);
            Assert.All(logs.Entries.Where(e => e.ToFullText().Contains("CryptographicException", StringComparison.Ordinal)),
                e => Assert.Null(e.Exception));
            Assert.Contains(logs.Entries, e => e.Level == LogLevel.Warning
                                               && e.Message.Contains(nameof(SamlMessageLoadAndVerifyHelper.VerifySignature), StringComparison.Ordinal));
        }

        [Theory]
        [InlineData(HttpStatusCode.ServiceUnavailable)]
        [InlineData(HttpStatusCode.NotFound)]
        [InlineData(HttpStatusCode.InternalServerError)]
        public async Task Ping_NonSuccessStatus_MessageHasStatusName_Test(HttpStatusCode status)
        {
            using var server = LoopbackHttpServer.Start(status);
            using var context = ServiceFactory.Create(new MPassTestSettings
            {
                SamlLoginDestination = server.Url()
            });

            var result = await context.Auth.PingAsync(TestContext.Current.CancellationToken);

            FunctionalTestKit.AssertSuccess(result);
            Assert.False(result.Response.IsSuccess);
            Assert.Equal($"Communication problem. Server respond with code: {status}", result.Response.Message);
            Assert.Equal(1, server.RequestCount);
        }

        [Fact]
        public async Task Ping_RepeatedCallsOnSharedClient_EachSucceeds_Test()
        {
            using var server = LoopbackHttpServer.Start(HttpStatusCode.OK);
            using var context = ServiceFactory.Create(new MPassTestSettings
            {
                SamlLoginDestination = server.Url()
            });

            var results = new List<PingResponse>();
            for (var i = 0; i < 5; i++)
                results.Add((await context.Auth.PingAsync(TestContext.Current.CancellationToken)).Response);

            Assert.All(results, r => Assert.True(r.IsSuccess));
            Assert.Equal(5, server.RequestCount);
        }

        [Fact]
        public void IdpCerts_SeparatePrimary_NoDuplicate_Test()
        {
            var options = new MPassSamlOptions
            {
                IdentityProviderCertificates = TestCertificates.Collection(TestCertificates.Idp, TestCertificates.IdpRotation),
                IdentityProviderCertificate = TestCertificates.PublicOnly(TestCertificates.Idp)
            };

            var certificates = CertificateLoader.IdentityProviderCertificates(options);

            Assert.Equal(2, certificates.Count);
            Assert.Equal(TestCertificates.Idp.Thumbprint, certificates[0].Thumbprint);
            Assert.Equal(TestCertificates.IdpRotation.Thumbprint, certificates[1].Thumbprint);
        }

        [Fact]
        public void IdpCerts_PrimaryOnlyOrNull_SingleOrEmpty_Test()
        {
            var primaryOnly = new MPassSamlOptions
            {
                IdentityProviderCertificates = null,
                IdentityProviderCertificate = TestCertificates.PublicOnly(TestCertificates.Idp)
            };

            Assert.Single(CertificateLoader.IdentityProviderCertificates(primaryOnly));
            Assert.Empty(CertificateLoader.IdentityProviderCertificates(new MPassSamlOptions()));
            Assert.Empty(CertificateLoader.IdentityProviderCertificates(null));
        }

        [Fact]
        public async Task Services_EmptyCertCollection_UsesPrimaryCert_Test()
        {
            using var context = ServiceFactory.Create(configureAfter: s => s.AddHealthChecks().AddMPassCertificateHealthCheck());
            var options = context.Options;
            var primary = options.IdentityProviderCertificate;
            options.IdentityProviderCertificates = new X509Certificate2Collection();
            Assert.NotNull(primary);
            var requestId = FunctionalTestKit.NewRequestId();

            var login = await context.Auth.GetUserDataFromAuthResponseAsync(
                new GetUserDataFromAuthResponseDto
                {
                    SamlResponse = context.SignedBase64(context.NewLoginResponse(requestId)),
                    AuthRequestId = requestId
                },
                TestContext.Current.CancellationToken);
            var slo = await context.Auth.ProcessExternalLogoutRequestAsync(new ProcessExternalLogoutRequestDto
            {
                SamlRequest = context.SignedBase64(context.NewLogoutRequest(SamlFixtures.DefaultNameId, SessionIndex)),
                SessionIndexId = SessionIndex,
                UserIdentifierId = SamlFixtures.DefaultNameId
            }, TestContext.Current.CancellationToken);
            var health = await context.Provider.GetRequiredService<HealthCheckService>().CheckHealthAsync(TestContext.Current.CancellationToken);

            FunctionalTestKit.AssertSuccess(login);
            FunctionalTestKit.AssertSuccess(slo);
            Assert.Equal(HealthStatus.Healthy, health.Status);
        }

        [Fact]
        public async Task Health_RotationDuplicatesPrimary_ReportedOnce_Test()
        {
            var expiring = TestCertificates.CreateRsa("CN=Expiring primary", 2048, TestClock.Epoch.AddDays(-10), TestClock.Epoch.AddDays(10));
            using var context = ServiceFactory.Create(new MPassTestSettings
                {
                    IdentityProviderCertificate = expiring
                }, configureAfter: s => s.AddHealthChecks().AddMPassCertificateHealthCheck());
            var options = context.Options;
            options.IdentityProviderCertificate = TestCertificates.PublicOnly(expiring);

            var report = await context.Provider.GetRequiredService<HealthCheckService>().CheckHealthAsync(TestContext.Current.CancellationToken);

            var description = report.Entries["MPass"].Description;
            Assert.Equal(HealthStatus.Degraded, report.Status);
            Assert.Equal(1, CountOccurrences(description, expiring.Thumbprint));
        }

        [Fact]
        public async Task ValidateLogout_RotationCert_Succeeds_Test()
        {
            var settings = new MPassTestSettings();
            settings.IdentityProviderAdditionalCertificates.Add(TestCertificates.IdpRotation);
            using var context = ServiceFactory.Create(settings);
            var requestId = FunctionalTestKit.NewRequestId();
            var saml = context.SignedBase64(context.NewLogoutResponse(requestId), new FixtureSigningOptions
            {
                Certificate = TestCertificates.IdpRotation
            });

            var result = await context.Auth.ValidateLogoutResponseAsync(
                new MPassHelperDotNet.Models.Dto.AuthService.LogoutResponse.ValidateLogoutResponseDto
                {
                    SamlResponse = saml, 
                    LogOutRequestId = requestId
                },
                TestContext.Current.CancellationToken);

            FunctionalTestKit.AssertSuccess(result);
        }

        private static int CountOccurrences(string text, string fragment)
        {
            var count = 0;
            for (var index = text.IndexOf(fragment, StringComparison.Ordinal); index >= 0;
                 index = text.IndexOf(fragment, index + fragment.Length, StringComparison.Ordinal))
                count++;

            return count;
        }
    }
}
