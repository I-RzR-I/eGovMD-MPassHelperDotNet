using System;
using System.Runtime.InteropServices;
using System.Security.Cryptography.X509Certificates;
using System.Threading.Tasks;
using Microsoft.Extensions.Options;
using MPassHelperDotNet.Configurations.Certificate;
using MPassHelperDotNet.Tests.Helpers.Certificates;
using MPassHelperDotNet.Tests.Helpers.Hosting;
using MPassHelperDotNet.Tests.Helpers.Runtime;
using MPassHelperDotNet.Tests.Models.Hosting;
using Xunit;
using static MPassHelperDotNet.Tests.Helpers.Kits.SecurityTestKit;

namespace MPassHelperDotNet.Tests.Tests.Security
{
    [Trait(TestAreas.Trait, TestAreas.Security)]
    public class CertificateSecurityTests
    {
        [Fact]
        public async Task HostStart_Rsa1024IdpCert_Fails_Test()
        {
            using var files = new TestCertificateFiles();
            var settings = new MPassTestSettings
            {
                IdentityProviderCertificate = TestCertificates.Rsa1024
            };

            await AssertStartupFails(settings, files);
        }

        [Fact]
        public async Task HostStart_Rsa1024RotationCert_Fails_Test()
        {
            using var files = new TestCertificateFiles();
            var settings = new MPassTestSettings();
            settings.IdentityProviderAdditionalCertificates.Add(TestCertificates.Rsa1024);

            await AssertStartupFails(settings, files);
        }

        [Fact]
        public async Task HostStart_Rsa1024ServiceCert_Fails_Test()
        {
            using var files = new TestCertificateFiles();
            var settings = new MPassTestSettings
            {
                ServiceCertificate = TestCertificates.Rsa1024
            };

            await AssertStartupFails(settings, files);
        }

        [Fact]
        public async Task HostStart_ServiceCertNoPrivateKey_Fails_Test()
        {
            using var files = new TestCertificateFiles();
            var settings = new MPassTestSettings
            {
                ServiceCertificate = null,
                ServiceCertificatePath = files.WritePfx(TestCertificates.PublicOnly(TestCertificates.Sp), MPassTestSettings.DefaultPfxPassword)
            };

            await AssertStartupFails(settings, files);
        }

        [Fact]
        public async Task HostStart_ServiceCertPublicDerFile_Fails_Test()
        {
            using var files = new TestCertificateFiles();
            var settings = new MPassTestSettings
            {
                ServiceCertificate = null, 
                ServiceCertificatePath = files.WriteCer(TestCertificates.Sp)
            };

            await AssertStartupFails(settings, files);
        }

        [Fact]
        public async Task HostStart_ValidCerts_SucceedsClearsPassword_Test()
        {
            using var files = new TestCertificateFiles();
            using var host = ServiceFactory.CreateHost(new MPassTestSettings(), files);

            await host.StartAsync(Ct);
            try
            {
                var options = ((IOptions<MPassHelperDotNet.Models.Client.MPassSamlOptions>)host.Services.GetService(typeof(IOptions<MPassHelperDotNet.Models.Client.MPassSamlOptions>))).Value;
                Assert.True(options.ServiceCertificate.HasPrivateKey);
                Assert.Null(options.ServiceCertificatePassword);
                Assert.All(options.IdentityProviderCertificates, c => Assert.False(c.HasPrivateKey));
            }
            finally
            {
                await host.StopAsync(Ct);
            }
        }

        [Fact]
        public void Services_Rsa1024IdpCert_ResolveThrows_Test()
        {
            using var context = ServiceFactory.Create(new MPassTestSettings
            {
                IdentityProviderCertificate = TestCertificates.Rsa1024
            });

            Assert.Throws<OptionsValidationException>(() => context.Auth);
        }

        [Fact]
        public void LoadPublic_PemChain_UserStoreUnchanged_Test()
        {
            if (!RuntimeInformation.IsOSPlatform(OSPlatform.Windows))
                Assert.Skip("Certificate store counts are checked on Windows only.");

            var chain = TestCertificates.CreateChain();
            using var files = new TestCertificateFiles();
            var pemPath = files.WritePem(chain.EndEntity, chain.Intermediate, chain.Root);
            var before = StoreCounts();

            var direct = CertificateLoader.Public(pemPath);
            var all = CertificateLoader.LoadAll(new[] { pemPath });
            var settings = new MPassTestSettings
            {
                IdentityProviderCertificate = null,
                IdentityProviderCertificatePath = pemPath
            };
            using (var context = ServiceFactory.Create(settings))
            {
                Assert.Single(context.Options.IdentityProviderCertificates);
            }

            var after = StoreCounts();
            Assert.Equal(before, after);
            Assert.Equal(chain.EndEntity.Thumbprint, direct.Thumbprint);
            Assert.Equal(chain.EndEntity.Thumbprint, Assert.Single(all).Thumbprint);
            Assert.False(StoreContains(StoreName.CertificateAuthority, chain.Intermediate.Thumbprint));
            Assert.False(StoreContains(StoreName.Root, chain.Root.Thumbprint));
        }

        private static async Task AssertStartupFails(MPassTestSettings settings, TestCertificateFiles files)
        {
            using var host = ServiceFactory.CreateHost(settings, files);

            await Assert.ThrowsAsync<OptionsValidationException>(() => host.StartAsync(Ct));
        }

        private static (int Ca, int Root, int My) StoreCounts()
            => (Count(StoreName.CertificateAuthority), Count(StoreName.Root), Count(StoreName.My));

        private static int Count(StoreName name)
        {
            using var store = new X509Store(name, StoreLocation.CurrentUser);
            store.Open(OpenFlags.ReadOnly);

            return store.Certificates.Count;
        }

        private static bool StoreContains(StoreName name, string thumbprint)
        {
            using var store = new X509Store(name, StoreLocation.CurrentUser);
            store.Open(OpenFlags.ReadOnly);

            return store.Certificates.Find(X509FindType.FindByThumbprint, thumbprint, false).Count > 0;
        }
    }
}
