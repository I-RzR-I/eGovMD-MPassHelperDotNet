using System;
using System.Xml;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Options;
using Microsoft.Extensions.Time.Testing;
using MPassHelperDotNet.Abstractions.Services;
using MPassHelperDotNet.Abstractions.Services.Replay;
using MPassHelperDotNet.Models.Client;
using MPassHelperDotNet.Tests.Helpers.Certificates;
using MPassHelperDotNet.Tests.Helpers.Logging;
using MPassHelperDotNet.Tests.Helpers.Saml;
using MPassHelperDotNet.Tests.Helpers.Signing;
using MPassHelperDotNet.Tests.Models.Hosting;
using MPassHelperDotNet.Tests.Models.Saml;
using MPassHelperDotNet.Tests.Models.Signing;

namespace MPassHelperDotNet.Tests.Helpers.Hosting
{
    internal sealed class MPassTestContext : IDisposable
    {
        private readonly object _scopeLock = new object();
        private IServiceScope _scope;
        private bool _disposed;

        internal MPassTestContext(MPassTestSettings settings, TestCertificateFiles files, FakeTimeProvider time, LogCapture logs,
            IConfiguration configuration, ServiceProvider provider)
        {
            Settings = settings;
            Files = files;
            Time = time;
            Logs = logs;
            Configuration = configuration;
            Provider = provider;
        }

        internal MPassTestSettings Settings { get; }

        internal TestCertificateFiles Files { get; }

        internal FakeTimeProvider Time { get; }

        internal LogCapture Logs { get; }

        internal IConfiguration Configuration { get; }

        internal ServiceProvider Provider { get; }

        internal DateTimeOffset Now => Time.GetUtcNow();

        internal IServiceScope Scope
        {
            get
            {
                lock (_scopeLock)
                {
                    if (_disposed)
                        throw new ObjectDisposedException(nameof(MPassTestContext));

                    return _scope ?? (_scope = Provider.CreateScope());
                }
            }
        }

        internal IAuthMPassService Auth => Scope.ServiceProvider.GetRequiredService<IAuthMPassService>();

        internal IMPassBuilderService Builder => Scope.ServiceProvider.GetRequiredService<IMPassBuilderService>();

        internal MPassSamlOptions Options => Provider.GetRequiredService<IOptions<MPassSamlOptions>>().Value;

        internal ISamlReplayCache ReplayCache => Provider.GetRequiredService<ISamlReplayCache>();

        internal IServiceScope CreateScope() => Provider.CreateScope();

        internal ResponseFixture NewLoginResponse(string inResponseTo) => SamlFixtures.LoginResponse(Settings, Now, inResponseTo);

        internal LogoutRequestFixture NewLogoutRequest(string nameId = SamlFixtures.DefaultNameId, string sessionIndex = "_session-default")
            => SamlFixtures.LogoutRequest(Settings, Now, nameId, sessionIndex);

        internal LogoutResponseFixture NewLogoutResponse(string inResponseTo) => SamlFixtures.LogoutResponse(Settings, Now, inResponseTo);

        internal string SignedBase64(ResponseFixture fixture, FixtureSigningOptions options = null, bool indent = false)
            => FixtureSigner.SignToBase64(SamlFixtureBuilder.Build(fixture, indent), options);

        internal string SignedBase64(LogoutRequestFixture fixture, FixtureSigningOptions options = null, bool indent = false)
            => FixtureSigner.SignToBase64(SamlFixtureBuilder.Build(fixture, indent), options);

        internal string SignedBase64(LogoutResponseFixture fixture, FixtureSigningOptions options = null, bool indent = false)
            => FixtureSigner.SignToBase64(SamlFixtureBuilder.Build(fixture, indent), options);

        internal static string UnsignedBase64(XmlDocument document) => FixtureEncoding.ToBase64(document);

        public void Dispose()
        {
            lock (_scopeLock)
            {
                if (_disposed)
                    return;

                _disposed = true;
                _scope?.Dispose();
            }

            Provider.Dispose();
            Files.Dispose();
        }
    }
}
