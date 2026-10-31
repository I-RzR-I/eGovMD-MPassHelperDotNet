using System.IO;
using MPassHelperDotNet.Configurations.Certificate;
using MPassHelperDotNet.Tests.Helpers.Certificates;
using MPassHelperDotNet.Tests.Helpers.Runtime;
using MPassHelperDotNet.Tests.Models.Hosting;
using Xunit;

namespace MPassHelperDotNet.Tests.Tests.Functional
{
    [Trait(TestAreas.Trait, TestAreas.Functional)]
    public class CertificateLoaderTests
    {
        [Fact]
        public void LoadPublic_PemChainOfThree_ReturnsEndEntity_Test()
        {
            var chain = TestCertificates.CreateChain();
            using var files = new TestCertificateFiles();
            var path = files.WritePem(chain.EndEntity, chain.Intermediate, chain.Root);

            using var certificate = CertificateLoader.Public(path);

            Assert.NotNull(certificate);
            Assert.Equal(chain.EndEntity.Thumbprint, certificate.Thumbprint);
            Assert.False(certificate.HasPrivateKey);
        }

        [Fact]
        public void LoadPublic_PemWithTwoCerts_ReturnsFirst_Test()
        {
            using var files = new TestCertificateFiles();
            var path = files.WritePem(TestCertificates.Idp, TestCertificates.IdpRotation);

            using var certificate = CertificateLoader.Public(path);

            Assert.Equal(TestCertificates.Idp.Thumbprint, certificate.Thumbprint);
        }

        [Fact]
        public void LoadPublic_PemWithCrLf_ReturnsEndEntity_Test()
        {
            var chain = TestCertificates.CreateChain();
            using var files = new TestCertificateFiles();
            var pem = (TestCertificateFiles.ToPem(chain.EndEntity) + TestCertificateFiles.ToPem(chain.Intermediate)).Replace("\n", "\r\n");
            var path = files.WriteText("chain-crlf.pem", pem);

            using var certificate = CertificateLoader.Public(path);

            Assert.Equal(chain.EndEntity.Thumbprint, certificate.Thumbprint);
        }

        [Fact]
        public void LoadPublic_DerFile_ReturnsCert_Test()
        {
            using var files = new TestCertificateFiles();
            var path = files.WriteCer(TestCertificates.Idp);

            using var certificate = CertificateLoader.Public(path);

            Assert.Equal(TestCertificates.Idp.Thumbprint, certificate.Thumbprint);
        }

        [Fact]
        public void LoadPublic_TlsCrtDirectory_ReturnsEndEntity_Test()
        {
            var chain = TestCertificates.CreateChain();
            using var files = new TestCertificateFiles();
            var directory = Path.Combine(files.DirectoryPath, "k8s-secret");
            Directory.CreateDirectory(directory);
            File.WriteAllText(Path.Combine(directory, "tls.crt"),
                TestCertificateFiles.ToPem(chain.EndEntity) + TestCertificateFiles.ToPem(chain.Intermediate));

            using var certificate = CertificateLoader.Public(directory);

            Assert.Equal(chain.EndEntity.Thumbprint, certificate.Thumbprint);
        }

        [Theory]
        [InlineData(null)]
        [InlineData("")]
        [InlineData("   ")]
        public void LoadPublic_BlankPath_ReturnsNull_Test(string path)
        {
            Assert.Null(CertificateLoader.Public(path));
        }

        [Fact]
        public void LoadPublic_MissingFile_ReturnsNull_Test()
        {
            using var files = new TestCertificateFiles();
            Assert.Null(CertificateLoader.Public(files.MissingPath()));
        }

        [Fact]
        public void LoadAll_MissingAndDuplicate_SkippedInOrder_Test()
        {
            using var files = new TestCertificateFiles();
            var paths = new[]
            {
                files.WriteCer(TestCertificates.Idp),
                files.MissingPath(),
                files.WritePem(TestCertificates.IdpRotation),
                files.WritePem(TestCertificates.Idp),
                files.WriteCer(TestCertificates.WrongKey)
            };

            var certificates = CertificateLoader.LoadAll(paths);

            Assert.Equal(3, certificates.Count);
            Assert.Equal(TestCertificates.Idp.Thumbprint, certificates[0].Thumbprint);
            Assert.Equal(TestCertificates.IdpRotation.Thumbprint, certificates[1].Thumbprint);
            Assert.Equal(TestCertificates.WrongKey.Thumbprint, certificates[2].Thumbprint);
        }

        [Fact]
        public void LoadAll_NullPaths_ReturnsEmpty_Test()
        {
            var certificates = CertificateLoader.LoadAll(null);
            Assert.NotNull(certificates);
            Assert.Empty(certificates);
        }

        [Fact]
        public void LoadPublic_PemChain_UserCaStoreUnchanged_Test()
        {
            if (!System.OperatingSystem.IsWindows())
                Assert.Skip("CurrentUser\\CA store check runs on Windows only.");

            var chain = TestCertificates.CreateChain();
            using var files = new TestCertificateFiles();
            var path = files.WritePem(chain.EndEntity, chain.Intermediate, chain.Root);
            var before = CountCurrentUserCa();

            using var certificate = CertificateLoader.Public(path);

            Assert.Equal(chain.EndEntity.Thumbprint, certificate.Thumbprint);
            Assert.Equal(before, CountCurrentUserCa());
        }

        private static int CountCurrentUserCa()
        {
            using var store = new System.Security.Cryptography.X509Certificates.X509Store(
                System.Security.Cryptography.X509Certificates.StoreName.CertificateAuthority,
                System.Security.Cryptography.X509Certificates.StoreLocation.CurrentUser);
            store.Open(System.Security.Cryptography.X509Certificates.OpenFlags.ReadOnly);

            return store.Certificates.Count;
        }

        [Fact]
        public void LoadPrivate_PfxWithPassword_KeyCanSign_Test()
        {
            using var files = new TestCertificateFiles();
            var path = files.WritePfx(TestCertificates.Sp, MPassTestSettings.DefaultPfxPassword);

            using var certificate = CertificateLoader.Private(path, MPassTestSettings.DefaultPfxPassword);

            Assert.NotNull(certificate);
            Assert.True(certificate.HasPrivateKey);
            using var rsa = System.Security.Cryptography.X509Certificates.RSACertificateExtensions.GetRSAPrivateKey(certificate);
            var signature = rsa.SignData(new byte[] { 1, 2, 3 }, System.Security.Cryptography.HashAlgorithmName.SHA256,
                System.Security.Cryptography.RSASignaturePadding.Pkcs1);
            Assert.NotEmpty(signature);
        }
    }
}
