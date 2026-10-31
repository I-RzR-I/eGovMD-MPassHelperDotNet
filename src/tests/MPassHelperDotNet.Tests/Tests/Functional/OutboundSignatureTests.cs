using System;
using System.Security.Cryptography.Xml;
using System.Threading.Tasks;
using System.Xml;
using MPassHelperDotNet.Models.Dto.AuthService.ExternalLogoutRequest;
using MPassHelperDotNet.Models.Dto.AuthService.LoginRequest;
using MPassHelperDotNet.Models.Dto.AuthService.LoginResponse;
using MPassHelperDotNet.Models.Dto.AuthService.LogoutRequest;
using MPassHelperDotNet.Tests.Helpers.Certificates;
using MPassHelperDotNet.Tests.Helpers.Hosting;
using MPassHelperDotNet.Tests.Helpers.Kits;
using MPassHelperDotNet.Tests.Helpers.Runtime;
using MPassHelperDotNet.Tests.Helpers.Saml;
using MPassHelperDotNet.Tests.Helpers.Signing;
using Xunit;

namespace MPassHelperDotNet.Tests.Tests.Functional
{
    [Trait(TestAreas.Trait, TestAreas.Functional)]
    public class OutboundSignatureTests
    {
        [Theory]
        [InlineData("AuthnRequest")]
        [InlineData("LogoutRequest")]
        [InlineData("LogoutResponse")]
        public async Task Outbound_RsaSha256Root_VerifiesWithSpCert_Test(string kind)
        {
            using var context = ServiceFactory.Create();
            var ct = TestContext.Current.CancellationToken;
            string html;
            string samlVariable = "SAMLRequest";
            switch (kind)
            {
                case "AuthnRequest":
                    html = (await context.Auth.GenerateAuthRequestAsync(new GenerateAuthRequestDto
                    {
                        RelayState = "rs"
                    }, ct)).Response.HtmlDocument;
                    break;
                case "LogoutRequest":
                    html = (await context.Auth.GenerateLogoutRequestAsync(new GenerateLogOutRequestDto
                    {
                        RelayState = "rs", 
                        SessionIndexId = "_s1", 
                        UserIdentifierId = SamlFixtures.DefaultNameId
                    }, ct)).Response.HtmlDocument;
                    break;
                default:
                    samlVariable = "SAMLResponse";
                    var request = context.SignedBase64(context.NewLogoutRequest(SamlFixtures.DefaultNameId, "_s1"));
                    html = (await context.Auth.ProcessExternalLogoutRequestAsync(new ProcessExternalLogoutRequestDto
                    {
                        SamlRequest = request,
                        SessionIndexId = "_s1",
                        UserIdentifierId = SamlFixtures.DefaultNameId
                    }, ct)).Response.HtmlDocument;
                    break;
            }

            var document = FunctionalTestKit.DecodeOnceToXml(HtmlFormReader.GetInputValue(html, samlVariable));

            var root = document.DocumentElement;
            Assert.Equal(kind, root.LocalName);

            var signature = Assert.Single(FixtureSigner.DirectSignatures(root));
            var signedXml = new SignedXml(document);
            signedXml.LoadXml(signature);
            Assert.Equal(SignedXml.XmlDsigRSASHA256Url, signedXml.SignedInfo.SignatureMethod);
            Assert.Equal(SignedXml.XmlDsigExcC14NTransformUrl, signedXml.SignedInfo.CanonicalizationMethod);

            var reference = Assert.IsType<Reference>(Assert.Single(signedXml.SignedInfo.References));
            Assert.Equal("#" + root.GetAttribute("ID"), reference.Uri);
            Assert.Equal(SignedXml.XmlDsigSHA256Url, reference.DigestMethod);
            Assert.True(signedXml.CheckSignature(TestCertificates.PublicOnly(TestCertificates.Sp), true));
            Assert.False(signedXml.CheckSignature(TestCertificates.PublicOnly(TestCertificates.WrongKey), true));
            Assert.DoesNotContain("PRIVATE", signature.OuterXml, StringComparison.OrdinalIgnoreCase);

            var ns = SamlNs.CreateNamespaceManager(document);
            var issuer = root.SelectSingleNode("saml2:Issuer", ns);
            Assert.Same(signature, NextElement(issuer));
        }

        [Fact]
        public async Task GetUserData_UpperCaseDestination_Succeeds_Test()
        {
            using var scope = new CultureScope(TestCultures.Turkish);
            using var context = ServiceFactory.Create();
            var requestId = FunctionalTestKit.NewRequestId();
            var fixture = context.NewLoginResponse(requestId);
            fixture.Destination = context.Settings.SamlServiceLoginDestination.ToUpperInvariant();
            fixture.Assertions[0].SubjectConfirmations[0].Data[0].Recipient = context.Settings.SamlServiceLoginDestination.ToUpperInvariant();

            var result = await context.Auth.GetUserDataFromAuthResponseAsync(
                new GetUserDataFromAuthResponseDto
                {
                    SamlResponse = context.SignedBase64(fixture),
                    AuthRequestId = requestId
                }, TestContext.Current.CancellationToken);

            FunctionalTestKit.AssertSuccess(result);
        }

        [Fact]
        public async Task GetUserData_UpperCaseInResponseTo_Fails_Test()
        {
            using var context = ServiceFactory.Create();
            var requestId = "_abcdef" + Guid.NewGuid().ToString("N");
            var fixture = context.NewLoginResponse(requestId.ToUpperInvariant());

            var result = await context.Auth.GetUserDataFromAuthResponseAsync(
                new GetUserDataFromAuthResponseDto
                {
                    SamlResponse = context.SignedBase64(fixture),
                    AuthRequestId = requestId
                }, TestContext.Current.CancellationToken);

            FunctionalTestKit.AssertFailure(result);
        }

        private static XmlNode NextElement(XmlNode node)
        {
            var next = node?.NextSibling;
            while (next != null && next.NodeType != XmlNodeType.Element)
                next = next.NextSibling;

            return next;
        }
    }
}
