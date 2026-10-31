using System;
using System.Globalization;
using System.IO;
using System.Linq;
using System.Net;
using System.Net.Http;
using System.Security.Cryptography.X509Certificates;
using System.Security.Cryptography.Xml;
using System.Threading.Tasks;
using System.Xml;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Logging;
using MPassHelperDotNet.Tests.Helpers.Certificates;
using MPassHelperDotNet.Tests.Helpers.Hosting;
using MPassHelperDotNet.Tests.Helpers.Http;
using MPassHelperDotNet.Tests.Helpers.Logging;
using MPassHelperDotNet.Tests.Helpers.Runtime;
using MPassHelperDotNet.Tests.Helpers.Saml;
using MPassHelperDotNet.Tests.Helpers.Signing;
using MPassHelperDotNet.Tests.Models.Hosting;
using MPassHelperDotNet.Tests.Models.Signing;
using Xunit;

namespace MPassHelperDotNet.Tests.Tests.Functional
{
    [Trait(TestAreas.Trait, TestAreas.Functional)]
    public class InfrastructureSmokeTests
    {
        private const string RequestId = "_req-smoke-0001";

        [Fact]
        public void TestCerts_SharedSet_KeySizesAndPrivateKeys_Test()
        {
            var idp = TestCertificates.Idp;
            var rotation = TestCertificates.IdpRotation;
            var wrong = TestCertificates.WrongKey;
            var rsa1024Cert = TestCertificates.Rsa1024;
            var sp = TestCertificates.Sp;

            Assert.Equal(2048, KeySize(idp));
            Assert.Equal(2048, KeySize(rotation));
            Assert.Equal(2048, KeySize(wrong));
            Assert.Equal(1024, KeySize(rsa1024Cert));
            Assert.Equal(2048, KeySize(sp));
            Assert.True(idp.HasPrivateKey);
            Assert.True(sp.HasPrivateKey);
            Assert.False(TestCertificates.PublicOnly(idp).HasPrivateKey);
            Assert.Equal(5, new[] { idp, rotation, wrong, rsa1024Cert, sp }.Select(c => c.GetPublicKeyString()).Distinct().Count());
        }

        [Fact]
        public void TestCerts_Chain_IssuerLinksAndThreePemCerts_Test()
        {
            var chain = TestCertificates.CreateChain();
            using var files = new TestCertificateFiles();

            var pemPath = files.WritePem(chain.EndEntity, chain.Intermediate, chain.Root);
            var pem = File.ReadAllText(pemPath);

            Assert.Equal(chain.Root.Subject, chain.Intermediate.Issuer);
            Assert.NotEqual(chain.Intermediate.Subject, chain.Intermediate.Issuer);
            Assert.Equal(chain.Intermediate.Subject, chain.EndEntity.Issuer);
            Assert.Equal(3, CountOccurrences(pem, "-----BEGIN CERTIFICATE-----"));
            Assert.Equal(3, CountOccurrences(pem, "-----END CERTIFICATE-----"));
        }

        [Fact]
        public void TestCertFiles_Dispose_DeletesTempDirectory_Test()
        {
            var files = new TestCertificateFiles();
            var path = files.WriteCer(TestCertificates.Idp);
            Assert.True(File.Exists(path));

            files.Dispose();

            Assert.False(Directory.Exists(files.DirectoryPath));
        }

        [Fact]
        public void FixtureSigner_DefaultRoot_VerifiesRsaSha256_Test()
        {
            var fixture = SamlFixtures.LoginResponse(new MPassTestSettings(), TestClock.Epoch, RequestId);

            var signed = FixtureSigner.Sign(SamlFixtureBuilder.Build(fixture));

            var signature = Assert.Single(FixtureSigner.DirectSignatures(signed.DocumentElement));
            Assert.Contains(SignedXml.XmlDsigRSASHA256Url, signature.OuterXml, StringComparison.Ordinal);
            Assert.True(VerifyRootSignature(signed, TestCertificates.Idp));
            Assert.False(VerifyRootSignature(signed, TestCertificates.WrongKey));
        }

        [Fact]
        public void FixtureSigner_RootAndAssertion_RootVerifies_Test()
        {
            var fixture = SamlFixtures.LoginResponse(new MPassTestSettings(), TestClock.Epoch, RequestId);

            var signed = FixtureSigner.Sign(SamlFixtureBuilder.Build(fixture),
                new FixtureSigningOptions { Placement = SignaturePlacement.RootAndAssertion });

            Assert.Single(FixtureSigner.DirectSignatures(signed.DocumentElement));
            Assert.Single(FixtureSigner.DirectSignatures(FixtureSigner.FindAssertion(signed)));
            Assert.True(VerifyRootSignature(signed, TestCertificates.Idp));
        }

        [Fact]
        public void FixtureSigner_EnvelopedOnlyTransform_Verifies_Test()
        {
            var fixture = SamlFixtures.LoginResponse(new MPassTestSettings(), TestClock.Epoch, RequestId);

            var signed = FixtureSigner.Sign(SamlFixtureBuilder.Build(fixture), FixtureSigningOptions.EnvelopedOnly());

            Assert.True(VerifyRootSignature(signed, TestCertificates.Idp));
        }

        [Fact]
        public void FixtureSigner_DuplicateId_RootReferenceKept_Test()
        {
            var fixture = SamlFixtures.LoginResponse(new MPassTestSettings(), TestClock.Epoch, RequestId);
            fixture.DuplicateIdAttributeName = "ID";

            var signed = FixtureSigner.Sign(SamlFixtureBuilder.Build(fixture));

            var ns = SamlNs.CreateNamespaceManager(signed);
            var referenceUri = signed.SelectSingleNode("/saml2p:Response/ds:Signature/ds:SignedInfo/ds:Reference/@URI", ns);
            Assert.NotNull(referenceUri);
            Assert.Equal("#" + fixture.Id, referenceUri.Value);
            Assert.Equal(2, signed.SelectNodes("//*[@ID='" + fixture.Id + "']").Count);
        }

        [Fact]
        public void SamlBuilder_Indent_KeepsNewlinesAndVerifies_Test()
        {
            var fixture = SamlFixtures.LoginResponse(new MPassTestSettings(), TestClock.Epoch, RequestId);

            var signed = FixtureSigner.Sign(SamlFixtureBuilder.Build(fixture, indent: true));

            Assert.Contains("\n", signed.OuterXml, StringComparison.Ordinal);
            Assert.True(VerifyRootSignature(signed, TestCertificates.Idp));
        }

        [Fact]
        public void SamlBuilder_LogoutPair_RootSignaturesVerify_Test()
        {
            var settings = new MPassTestSettings();
            var logoutRequest = SamlFixtures.LogoutRequest(settings, TestClock.Epoch);
            var logoutResponse = SamlFixtures.LogoutResponse(settings, TestClock.Epoch, RequestId);

            var signedRequest = FixtureSigner.Sign(SamlFixtureBuilder.Build(logoutRequest));
            var signedResponse = FixtureSigner.Sign(SamlFixtureBuilder.Build(logoutResponse));

            Assert.Equal("LogoutRequest", signedRequest.DocumentElement.LocalName);
            Assert.Equal(SamlNs.Protocol, signedRequest.DocumentElement.NamespaceURI);
            Assert.Equal("LogoutResponse", signedResponse.DocumentElement.LocalName);
            Assert.True(VerifyRootSignature(signedRequest, TestCertificates.Idp));
            Assert.True(VerifyRootSignature(signedResponse, TestCertificates.Idp));
        }

        [Fact]
        public void SamlFixtures_LoginResponse_HasExpectedFields_Test()
        {
            var settings = new MPassTestSettings();

            var document = SamlFixtureBuilder.Build(SamlFixtures.LoginResponse(settings, TestClock.Epoch, RequestId));

            var ns = SamlNs.CreateNamespaceManager(document);
            var root = document.DocumentElement;
            Assert.Equal(settings.SamlServiceLoginDestination, root.GetAttribute("Destination"));
            Assert.Equal(RequestId, root.GetAttribute("InResponseTo"));
            Assert.Equal("2026-06-01T10:00:00Z", root.GetAttribute("IssueInstant"));
            Assert.Equal(settings.IdentityProviderIssuer, root.SelectSingleNode("saml2:Issuer", ns)?.InnerText);
            Assert.Equal(settings.IdentityProviderIssuer, root.SelectSingleNode("saml2:Assertion/saml2:Issuer", ns)?.InnerText);
            Assert.Equal(settings.SamlRequestIssuer,
                root.SelectSingleNode("saml2:Assertion/saml2:Conditions/saml2:AudienceRestriction/saml2:Audience", ns)?.InnerText);
            Assert.Equal(SamlNs.MethodBearer, root.SelectSingleNode("saml2:Assertion/saml2:Subject/saml2:SubjectConfirmation/@Method", ns)?.Value);
            Assert.Equal(SamlFixtures.DefaultNameId, root.SelectSingleNode("saml2:Assertion/saml2:Subject/saml2:NameID", ns)?.InnerText);
        }

        [Fact]
        public void LogCapture_RecordsMessageValuesAndException_Test()
        {
            var capture = new LogCapture();
            var logger = capture.CreateLogger("MPassHelperDotNet.Smoke");

            logger.LogWarning(new InvalidOperationException("smoke-exception"), "{Operation} failed", "SmokeOperation");

            var entry = Assert.Single(capture.Entries);
            Assert.Equal(LogLevel.Warning, entry.Level);
            Assert.Equal("SmokeOperation failed", entry.Message);
            Assert.IsType<InvalidOperationException>(entry.Exception);
            Assert.True(capture.Contains("Operation=SmokeOperation"));
            Assert.True(capture.Contains("smoke-exception"));
            Assert.Single(capture.ForCategory("MPassHelperDotNet"));

            capture.Clear();
            Assert.Empty(capture.Entries);
        }

        [Fact]
        public void CultureScope_Dispose_RestoresPreviousCultures_Test()
        {
            var before = CultureInfo.CurrentCulture;
            var beforeUi = CultureInfo.CurrentUICulture;

            using (new CultureScope(TestCultures.Turkish))
            {
                Assert.Equal(TestCultures.Turkish, CultureInfo.CurrentCulture.Name);
                Assert.Equal(TestCultures.Turkish, CultureInfo.CurrentUICulture.Name);
            }

            Assert.Equal(before, CultureInfo.CurrentCulture);
            Assert.Equal(beforeUi, CultureInfo.CurrentUICulture);
        }

        [Fact]
        public void TestSettings_Configuration_WritesKeysAndFiles_Test()
        {
            using var files = new TestCertificateFiles();
            var settings = new MPassTestSettings();
            settings.IdentityProviderAdditionalCertificates.Add(TestCertificates.IdpRotation);
            settings.AdditionalConfiguration["SamlMessageTimeout"] = null;

            var values = settings.ToConfiguration(files);

            Assert.Equal(MPassTestSettings.DefaultIdpIssuer, values["MPassSamlOptions:IdentityProviderIssuer"]);
            Assert.Equal("00:02:00", values["MPassSamlOptions:SamlClockSkew"]);
            Assert.DoesNotContain("MPassSamlOptions:SamlMessageTimeout", values.Keys);
            Assert.True(File.Exists(values["MPassSamlOptions:ServiceCertificatePath"]));
            Assert.True(File.Exists(values["MPassSamlOptions:IdentityProviderCertificatePath"]));
            Assert.True(File.Exists(values["MPassSamlOptions:IdentityProviderAdditionalCertificatePaths:0"]));
            Assert.Empty(new MPassTestSettings { OmitSection = true }.ToConfiguration(files));
        }

        [Fact]
        public void ServiceFactory_Default_ResolvesBothServices_Test()
        {
            using var context = ServiceFactory.Create();

            Assert.NotNull(context.Auth);
            Assert.NotNull(context.Builder);
            Assert.Same(context.Time, context.Provider.GetRequiredService<TimeProvider>());
            Assert.Equal(TestClock.Epoch, context.Now);
        }

        [Theory]
        [InlineData(HttpStatusCode.OK)]
        [InlineData(HttpStatusCode.ServiceUnavailable)]
        public async Task LoopbackHttpServer_Get_ReturnsStatusAndCounts_Test(HttpStatusCode statusCode)
        {
            using var server = LoopbackHttpServer.Start(statusCode);
            using var client = new HttpClient { Timeout = TimeSpan.FromSeconds(30) };

            using var response = await client.GetAsync(server.Url(), TestContext.Current.CancellationToken);

            Assert.Equal(statusCode, response.StatusCode);
            Assert.Equal(1, server.RequestCount);
        }

        [Fact]
        public async Task ClosedPort_Get_ThrowsHttpRequestException_Test()
        {
            using var port = new ClosedLoopbackPort();
            using var client = new HttpClient { Timeout = TimeSpan.FromSeconds(30) };

            await Assert.ThrowsAsync<HttpRequestException>(() => client.GetAsync(port.Url(), TestContext.Current.CancellationToken));
        }

        private static int KeySize(X509Certificate2 certificate)
        {
            using var rsa = certificate.GetRSAPublicKey();

            return rsa.KeySize;
        }

        private static int CountOccurrences(string text, string fragment)
        {
            var count = 0;
            var index = text.IndexOf(fragment, StringComparison.Ordinal);
            while (index >= 0)
            {
                count++;
                index = text.IndexOf(fragment, index + fragment.Length, StringComparison.Ordinal);
            }

            return count;
        }

        private static bool VerifyRootSignature(XmlDocument signed, X509Certificate2 certificate)
        {
            var document = FixtureEncoding.Reparse(signed);
            var signature = Assert.Single(FixtureSigner.DirectSignatures(document.DocumentElement));
            var signedXml = new SignedXml(document);
            signedXml.LoadXml(signature);

            return signedXml.CheckSignature(TestCertificates.PublicOnly(certificate), true);
        }
    }
}
