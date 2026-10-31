using System;
using System.IO;
using System.Linq;
using System.Threading.Tasks;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;
using MPassHelperDotNet.Abstractions.Services;
using MPassHelperDotNet.Abstractions.Services.Replay;
using MPassHelperDotNet.Configurations.ClientCertificateOption;
using MPassHelperDotNet.Helpers;
using MPassHelperDotNet.Helpers.Messages;
using MPassHelperDotNet.Models.Client;
using MPassHelperDotNet.Models.Dto.AuthService.LoginResponse;
using MPassHelperDotNet.Services.Replay;
using MPassHelperDotNet.Tests.Helpers.Certificates;
using MPassHelperDotNet.Tests.Helpers.Fakes;
using MPassHelperDotNet.Tests.Helpers.Hosting;
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
    public class OptionsAndDependencyInjectionTests
    {
        private const string Prefix = "MPassSamlOptions.";

        private static readonly string[] RequiredSettings =
        {
            "SamlRequestIssuer", "ServiceCertificatePath", "IdentityProviderCertificatePath", "IdentityProviderIssuer",
            "SamlLoginDestination", "SamlLogoutDestination", "SamlServiceLoginDestination", "SamlServiceLogoutDestination",
            "SamlServiceSingleLogoutDestination"
        };

        [Fact]
        public async Task HostStart_MissingSection_FailsNamingAll_Test()
        {
            using var files = new TestCertificateFiles();
            using var host = ServiceFactory.CreateHost(new MPassTestSettings { OmitSection = true }, files);

            var exception = await Assert.ThrowsAsync<OptionsValidationException>(() => host.StartAsync(TestContext.Current.CancellationToken));

            var failures = string.Join("\n", exception.Failures);
            foreach (var setting in RequiredSettings)
                Assert.Contains(Prefix + setting, failures, StringComparison.Ordinal);
        }

        [Fact]
        public async Task HostStart_MissingIssuers_FailsNamingBoth_Test()
        {
            using var files = new TestCertificateFiles();
            var settings = new MPassTestSettings { SamlRequestIssuer = null, IdentityProviderIssuer = null };
            using var host = ServiceFactory.CreateHost(settings, files);

            var exception = await Assert.ThrowsAsync<OptionsValidationException>(() => host.StartAsync(TestContext.Current.CancellationToken));

            var failures = exception.Failures.ToList();
            Assert.Contains(failures, f => f.Contains(Prefix + "SamlRequestIssuer", StringComparison.Ordinal));
            Assert.Contains(failures, f => f.Contains(Prefix + "IdentityProviderIssuer", StringComparison.Ordinal));
            Assert.DoesNotContain(failures, f => f.Contains(Prefix + "SamlLoginDestination", StringComparison.Ordinal));
        }

        [Theory]
        [InlineData("IdentityProviderIssuer", "<MPass IdP metadata EntityID>")]
        [InlineData("SamlLoginDestination", "not-a-url")]
        [InlineData("SamlServiceLoginDestination", "/relative/acs")]
        [InlineData("SamlLogoutDestination", "ftp://idp.test.local/logout")]
        [InlineData("SamlMessageTimeout", "00:31:00")]
        [InlineData("SamlMessageTimeout", "00:00:00")]
        [InlineData("SamlClockSkew", "00:05:01")]
        [InlineData("SamlClockSkew", "-00:00:01")]
        [InlineData("SamlMessageMaxLength", "0")]
        public async Task HostStart_InvalidSetting_FailsNamingSetting_Test(string setting, string value)
        {
            using var files = new TestCertificateFiles();
            var settings = new MPassTestSettings();
            settings.AdditionalConfiguration[setting] = value;
            using var host = ServiceFactory.CreateHost(settings, files);

            var exception = await Assert.ThrowsAsync<OptionsValidationException>(() => host.StartAsync(TestContext.Current.CancellationToken));

            Assert.Contains(exception.Failures, f => f.Contains(Prefix + setting, StringComparison.Ordinal));
        }

        [Fact]
        public async Task HostStart_MissingIdpCertFile_Fails_Test()
        {
            using var files = new TestCertificateFiles();
            var settings = new MPassTestSettings { IdentityProviderCertificatePath = files.MissingPath() };
            using var host = ServiceFactory.CreateHost(settings, files);

            var exception = await Assert.ThrowsAsync<OptionsValidationException>(() => host.StartAsync(TestContext.Current.CancellationToken));
            Assert.Contains(exception.Failures, f => f.Contains(Prefix + "IdentityProviderCertificatePath", StringComparison.Ordinal));
        }

        [Fact]
        public async Task HostStart_WrongServiceCertPassword_Fails_Test()
        {
            using var files = new TestCertificateFiles();
            var settings = new MPassTestSettings();
            settings.ServiceCertificatePath = files.WritePfx(TestCertificates.Sp, MPassTestSettings.DefaultPfxPassword);
            settings.ServiceCertificatePassword = "wrong-password";
            using var host = ServiceFactory.CreateHost(settings, files);

            var exception = await Assert.ThrowsAsync<OptionsValidationException>(() => host.StartAsync(TestContext.Current.CancellationToken));
            Assert.Contains(exception.Failures, f => f.Contains(Prefix + "ServiceCertificatePath", StringComparison.Ordinal));
        }

        [Fact]
        public async Task HostStart_ValidConfig_SucceedsClearsPassword_Test()
        {
            using var files = new TestCertificateFiles();
            using var host = ServiceFactory.CreateHost(new MPassTestSettings(), files);

            await host.StartAsync(TestContext.Current.CancellationToken);

            var options = host.Services.GetRequiredService<IOptions<MPassSamlOptions>>().Value;
            Assert.Null(options.ServiceCertificatePassword);
            Assert.Null(host.Services.GetRequiredService<IOptionsMonitor<MPassSamlOptions>>().CurrentValue.ServiceCertificatePassword);
            Assert.Null(host.Services.GetRequiredService<MPassSamlOptions>().ServiceCertificatePassword);
            Assert.NotNull(options.ServiceCertificate);
            Assert.True(options.ServiceCertificate.HasPrivateKey);
            await host.StopAsync(TestContext.Current.CancellationToken);
        }

        [Fact]
        public async Task HostStart_CertsLoadedOnce_ViewsShareInstances_Test()
        {
            using var files = new TestCertificateFiles();
            var settings = new MPassTestSettings();
            using var host = ServiceFactory.CreateHost(settings, files);
            await host.StartAsync(TestContext.Current.CancellationToken);

            var first = host.Services.GetRequiredService<IOptions<MPassSamlOptions>>().Value;

            foreach (var file in Directory.GetFiles(files.DirectoryPath))
                File.Delete(file);
            var monitor = host.Services.GetRequiredService<IOptionsMonitor<MPassSamlOptions>>().CurrentValue;
            var raw = host.Services.GetRequiredService<MPassSamlOptions>();
            var second = host.Services.GetRequiredService<IOptions<MPassSamlOptions>>().Value;

            Assert.Same(first, second);
            Assert.Same(first, monitor);
            Assert.Same(first, raw);
            Assert.Same(first.ServiceCertificate, monitor.ServiceCertificate);
            Assert.Same(first.IdentityProviderCertificate, raw.IdentityProviderCertificate);

            using var scope = host.Services.CreateScope();
            var auth = scope.ServiceProvider.GetRequiredService<IAuthMPassService>();
            var requestId = FunctionalTestKit.NewRequestId();
            var fixture = SamlFixtures.LoginResponse(settings, TestClock.Epoch, requestId);
            var login = await auth.GetUserDataFromAuthResponseAsync(new GetUserDataFromAuthResponseDto
            {
                SamlResponse = FixtureSigner.SignToBase64(SamlFixtureBuilder.Build(fixture)),
                AuthRequestId = requestId
            }, TestContext.Current.CancellationToken);
            FunctionalTestKit.AssertSuccess(login);
            await host.StopAsync(TestContext.Current.CancellationToken);
        }

        [Fact]
        public void Options_RotationCerts_PrimaryFirstThenRest_Test()
        {
            var settings = new MPassTestSettings();
            settings.IdentityProviderAdditionalCertificates.Add(TestCertificates.IdpRotation);
            settings.IdentityProviderAdditionalCertificates.Add(TestCertificates.WrongKey);

            using var context = ServiceFactory.Create(settings);
            var options = context.Options;

            Assert.Equal(3, options.IdentityProviderCertificates.Count);
            Assert.Equal(TestCertificates.Idp.Thumbprint, options.IdentityProviderCertificates[0].Thumbprint);
            Assert.Equal(TestCertificates.IdpRotation.Thumbprint, options.IdentityProviderCertificates[1].Thumbprint);
            Assert.Equal(TestCertificates.WrongKey.Thumbprint, options.IdentityProviderCertificates[2].Thumbprint);
            Assert.Equal(TestCertificates.Idp.Thumbprint, options.IdentityProviderCertificate.Thumbprint);
            Assert.All(options.IdentityProviderCertificates.Cast<System.Security.Cryptography.X509Certificates.X509Certificate2>(),
                c => Assert.False(c.HasPrivateKey));
        }

        [Fact]
        public async Task GetUserData_RotationCert_Succeeds_Test()
        {
            var settings = new MPassTestSettings();
            settings.IdentityProviderAdditionalCertificates.Add(TestCertificates.IdpRotation);
            using var context = ServiceFactory.Create(settings);
            var requestId = FunctionalTestKit.NewRequestId();
            var saml = context.SignedBase64(context.NewLoginResponse(requestId),
                new FixtureSigningOptions { Certificate = TestCertificates.IdpRotation });

            var result = await context.Auth.GetUserDataFromAuthResponseAsync(
                new GetUserDataFromAuthResponseDto { SamlResponse = saml, AuthRequestId = requestId }, TestContext.Current.CancellationToken);

            FunctionalTestKit.AssertSuccess(result);
        }

        [Fact]
        public async Task HostStart_DuplicateIdpCert_Fails_Test()
        {
            using var files = new TestCertificateFiles();
            var settings = new MPassTestSettings();
            settings.IdentityProviderAdditionalCertificates.Add(TestCertificates.Idp);
            using var host = ServiceFactory.CreateHost(settings, files);

            var exception = await Assert.ThrowsAsync<OptionsValidationException>(() => host.StartAsync(TestContext.Current.CancellationToken));
            Assert.Contains(exception.Failures, f => f.Contains(Prefix + "IdentityProviderAdditionalCertificatePaths", StringComparison.Ordinal));
        }

        [Fact]
        public async Task HostStart_IdpCertWithPrivateKey_Fails_Test()
        {
            using var files = new TestCertificateFiles();
            var settings = new MPassTestSettings();
            settings.IdentityProviderCertificatePath = files.WritePfx(TestCertificates.IdpRotation, string.Empty);
            using var host = ServiceFactory.CreateHost(settings, files);

            var exception = await Record.ExceptionAsync(() => host.StartAsync(TestContext.Current.CancellationToken));

            var validation = Assert.IsType<OptionsValidationException>(exception);
            Assert.Contains(validation.Failures, f => f.Contains("private key", StringComparison.Ordinal));
        }

        [Fact]
        public async Task HostStart_NonRsaIdpCert_FailsWithRsaMessage_Test()
        {
            using var files = new TestCertificateFiles();
            using var ecdsa = System.Security.Cryptography.ECDsa.Create(System.Security.Cryptography.ECCurve.NamedCurves.nistP256);
            var request = new System.Security.Cryptography.X509Certificates.CertificateRequest("CN=EC IdP", ecdsa,
                System.Security.Cryptography.HashAlgorithmName.SHA256);
            using var ecCertificate = request.CreateSelfSigned(TestCertificates.DefaultNotBefore, TestCertificates.DefaultNotAfter);
            var settings = new MPassTestSettings { IdentityProviderCertificatePath = files.WriteCer(ecCertificate) };
            using var host = ServiceFactory.CreateHost(settings, files);

            var exception = await Assert.ThrowsAsync<OptionsValidationException>(() => host.StartAsync(TestContext.Current.CancellationToken));

            Assert.Contains(exception.Failures, f => f.Contains("must use an RSA key", StringComparison.Ordinal)
                                                     && f.Contains(Prefix + "IdentityProviderCertificates", StringComparison.Ordinal));
        }

        [Fact]
        public async Task HostStart_NonLoopbackHttp_WarningLogged_Test()
        {
            using var files = new TestCertificateFiles();
            var logs = new LogCapture();
            var settings = new MPassTestSettings
            {
                SamlLoginDestination = "http://idp.test.local/saml/login",
                SamlServiceLoginDestination = "http://sp.test.local/saml/acs"
            };
            using var host = ServiceFactory.CreateHost(settings, files, logs);

            await host.StartAsync(TestContext.Current.CancellationToken);

            var warnings = logs.ForCategory(typeof(MPassSamlOptionsValidation).FullName)
                .Where(e => e.Level == LogLevel.Warning).ToList();
            Assert.Equal(2, warnings.Count);
            Assert.Contains(warnings, w => w.ToFullText().Contains(Prefix + "SamlLoginDestination", StringComparison.Ordinal));
            Assert.Contains(warnings, w => w.ToFullText().Contains(Prefix + "SamlServiceLoginDestination", StringComparison.Ordinal));
            Assert.All(warnings, w => Assert.EndsWith("MPassSamlOptionsValidation", w.Category, StringComparison.Ordinal));
            await host.StopAsync(TestContext.Current.CancellationToken);
        }

        [Fact]
        public async Task HostStart_HttpsAndLoopbackHttp_NoWarning_Test()
        {
            using var files = new TestCertificateFiles();
            var logs = new LogCapture();
            var settings = new MPassTestSettings
            {
                SamlLoginDestination = "http://localhost:5001/saml/login",
                SamlLogoutDestination = "http://127.0.0.1:5001/saml/logout"
            };
            using var host = ServiceFactory.CreateHost(settings, files, logs);

            await host.StartAsync(TestContext.Current.CancellationToken);

            Assert.DoesNotContain(logs.ForCategory(typeof(MPassSamlOptionsValidation).FullName), e => e.Level >= LogLevel.Warning);
            await host.StopAsync(TestContext.Current.CancellationToken);
        }

        [Fact]
        public void ConsumerPostConfig_BeforeAndAfterAdd_BothRun_Test()
        {
            var before = 0;
            var after = 0;

            using var context = ServiceFactory.Create(
                configureBefore: s => s.PostConfigure<MPassSamlOptions>(o =>
                {
                    before++;
                    o.SamlRequestIssuer += "#before";
                }),
                configureAfter: s => s.PostConfigure<MPassSamlOptions>(o =>
                {
                    after++;
                    o.SamlRequestIssuer += "#after";
                }));
            var options = context.Options;

            Assert.Equal(1, before);
            Assert.Equal(1, after);
            Assert.Equal(MPassTestSettings.DefaultSpIssuer + "#before#after", options.SamlRequestIssuer);
            Assert.NotNull(options.ServiceCertificate);
        }

        [Fact]
        public void AddMPassService_Twice_NoDuplicateServicesCert_Test()
        {
            using var files = new TestCertificateFiles();
            var settings = new MPassTestSettings();
            settings.IdentityProviderAdditionalCertificates.Add(TestCertificates.IdpRotation);
            var configuration = new ConfigurationBuilder().AddInMemoryCollection(settings.ToConfiguration(files)).Build();
            var services = new ServiceCollection();
            services.AddSingleton<TimeProvider>(TestClock.CreateFake());

            services.AddMPassService(configuration);
            services.AddMPassService(configuration);
            using var provider = services.BuildServiceProvider(new ServiceProviderOptions { ValidateScopes = true });

            Assert.Single(provider.GetServices<IPostConfigureOptions<MPassSamlOptions>>().OfType<ClientCertificateOptionsPostConfigure>());
            Assert.Single(provider.GetServices<IValidateOptions<MPassSamlOptions>>().OfType<MPassSamlOptionsValidation>());
            using var scope = provider.CreateScope();
            Assert.Single(scope.ServiceProvider.GetServices<IAuthMPassService>());
            Assert.Single(scope.ServiceProvider.GetServices<IMPassBuilderService>());
            Assert.Single(provider.GetServices<ISamlReplayCache>());
            
            var options = provider.GetRequiredService<IOptions<MPassSamlOptions>>().Value;
            Assert.Single(options.IdentityProviderAdditionalCertificatePaths);
            Assert.Equal(2, options.IdentityProviderCertificates.Count);
        }

        [Fact]
        public void AddMPassService_Twice_SingleDescriptors_Test()
        {
            using var files = new TestCertificateFiles();
            var configuration = new ConfigurationBuilder().AddInMemoryCollection(new MPassTestSettings().ToConfiguration(files)).Build();
            var services = new ServiceCollection();

            services.AddMPassService(configuration);
            services.AddMPassService(configuration);

            Assert.Single(services, d => d.ServiceType == typeof(IAuthMPassService));
            Assert.Single(services, d => d.ServiceType == typeof(IMPassBuilderService));
            Assert.Single(services, d => d.ServiceType == typeof(ISamlReplayCache));
            Assert.Single(services, d => d.ServiceType == typeof(IPostConfigureOptions<MPassSamlOptions>)
                                         && d.ImplementationType == typeof(ClientCertificateOptionsPostConfigure));
            Assert.Single(services, d => d.ServiceType == typeof(IValidateOptions<MPassSamlOptions>)
                                         && d.ImplementationType == typeof(MPassSamlOptionsValidation));
            Assert.Single(services, d => d.ServiceType == typeof(IOptions<MPassSamlOptions>));
            Assert.Single(services, d => d.ServiceType == typeof(MPassSamlOptions));
        }

        [Theory]
        [InlineData(true)]
        [InlineData(false)]
        public async Task GetUserData_ConsumerCacheBeforeOrAfter_Used_Test(bool registerBefore)
        {
            var consumerCache = new KeyRecordingReplayCache();
            Action<IServiceCollection> register = s => s.AddSingleton<ISamlReplayCache>(consumerCache);
            using var context = registerBefore
                ? ServiceFactory.Create(configureBefore: register)
                : ServiceFactory.Create(configureAfter: register);
            var requestId = FunctionalTestKit.NewRequestId();
            var fixture = context.NewLoginResponse(requestId);

            var result = await context.Auth.GetUserDataFromAuthResponseAsync(
                new GetUserDataFromAuthResponseDto { SamlResponse = context.SignedBase64(fixture), AuthRequestId = requestId },
                TestContext.Current.CancellationToken);

            FunctionalTestKit.AssertSuccess(result);
            Assert.Same(consumerCache, context.ReplayCache);
            Assert.Contains(DefaultStaticInfo.ReplayKeyResponse + fixture.Id, consumerCache.Keys);
            Assert.Contains(DefaultStaticInfo.ReplayKeyAssertion + fixture.Assertions[0].Id, consumerCache.Keys);
        }

        [Fact]
        public async Task DefaultReplayCache_InMemory_ReuseFails_Test()
        {
            using var context = ServiceFactory.Create();
            var requestId = FunctionalTestKit.NewRequestId();
            var saml = context.SignedBase64(context.NewLoginResponse(requestId));
            var dto = new GetUserDataFromAuthResponseDto { SamlResponse = saml, AuthRequestId = requestId };

            var first = await context.Auth.GetUserDataFromAuthResponseAsync(dto, TestContext.Current.CancellationToken);
            var second = await context.Auth.GetUserDataFromAuthResponseAsync(dto, TestContext.Current.CancellationToken);

            Assert.IsType<InMemorySamlReplayCache>(context.ReplayCache);
            FunctionalTestKit.AssertSuccess(first);
            FunctionalTestKit.AssertFailureWith(second, SamlLoadValidationMessages.SamlReplayDetected);
            Assert.Null(second.Response);
        }
    }
}
