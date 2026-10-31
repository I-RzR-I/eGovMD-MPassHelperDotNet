using System;
using System.Collections.Generic;
using System.Linq;
using System.Security.Cryptography.Xml;
using System.Threading.Tasks;
using System.Xml;
using MPassHelperDotNet.Extensions;
using MPassHelperDotNet.Helpers.Messages;
using MPassHelperDotNet.Helpers.SAML;
using MPassHelperDotNet.Models.Dto.AuthService.LoginRequest;
using MPassHelperDotNet.Models.Dto.AuthService.LogoutRequest;
using MPassHelperDotNet.Models.Dto.RequestBuilder.LoginRequest;
using MPassHelperDotNet.Models.Dto.RequestBuilder.LogoutRequest;
using MPassHelperDotNet.Models.Dto.RequestBuilder.LogOutResponse;
using MPassHelperDotNet.Tests.Helpers.Certificates;
using MPassHelperDotNet.Tests.Helpers.Hosting;
using MPassHelperDotNet.Tests.Helpers.Runtime;
using MPassHelperDotNet.Tests.Helpers.Saml;
using MPassHelperDotNet.Tests.Helpers.Signing;
using MPassHelperDotNet.Tests.Models.Hosting;
using Xunit;
using static MPassHelperDotNet.Tests.Helpers.Kits.SecurityTestKit;

namespace MPassHelperDotNet.Tests.Tests.Security
{
    [Trait(TestAreas.Trait, TestAreas.Security)]
    public class OutboundSecurityTests
    {
        private const string HtmlMetacharacters = "\"'<>&";

        public static TheoryData<string, bool> RelayStates => new TheoryData<string, bool>
        {
            { new string('r', 80), true },
            { new string('r', 81), false },
            { new string('ă', 40), true },
            { new string('ă', 41), false },
            { new string('€', 27), false }
        };

        [Theory]
        [MemberData(nameof(RelayStates))]
        public async Task GenerateAuth_RelayStateMax80Utf8Bytes_Test(string relayState, bool accepted)
        {
            using var context = ServiceFactory.Create();

            var result = await context.Auth.GenerateAuthRequestAsync(new GenerateAuthRequestDto
            {
                RelayState = relayState
            }, Ct);

            AssertRelayStateOutcome(result, accepted);
        }

        [Theory]
        [MemberData(nameof(RelayStates))]
        public async Task GenerateLogout_RelayStateMax80Utf8Bytes_Test(string relayState, bool accepted)
        {
            using var context = ServiceFactory.Create();

            var result = await context.Auth.GenerateLogoutRequestAsync(new GenerateLogOutRequestDto
            {
                RelayState = relayState,
                SessionIndexId = "_session-1",
                UserIdentifierId = SamlFixtures.DefaultNameId
            }, Ct);

            AssertRelayStateOutcome(result, accepted);
        }

        [Theory]
        [MemberData(nameof(RelayStates))]
        public async Task ExternalLogout_RelayStateMax80Utf8Bytes_Test(string relayState, bool accepted)
        {
            using var context = ServiceFactory.Create();

            var result = await SubmitLogoutRequestAsync(context, context.SignedBase64(context.NewLogoutRequest()), relayState: relayState);

            AssertRelayStateOutcome(result, accepted);
        }

        [Theory]
        [MemberData(nameof(RelayStates))]
        public async Task Builders_RelayState_Max80Utf8Bytes_Test(string relayState, bool accepted)
        {
            using var context = ServiceFactory.Create();

            var login = await context.Builder.BuildLogInRequestAsync(new BuildLogInRequestDto
            {
                RelayState = relayState
            }, Ct);
            var logout = await context.Builder.BuildLogOutRequestAsync(new BuildLogOutRequestDto
            {
                RelayState = relayState,
                UserIdentifierId = SamlFixtures.DefaultNameId,
                UserSessionId = "_session-1"
            }, Ct);
            var logoutResponse = await context.Builder.BuildLogOutResponseAsync(new BuildLogOutResponseDto
            {
                RelayState = relayState,
                SamlRequest = context.SignedBase64(context.NewLogoutRequest()),
                UserIdentifierId = SamlFixtures.DefaultNameId,
                UserSessionIndexId = DefaultLogoutSessionIndex
            }, Ct);

            AssertRelayStateOutcome(login, accepted);
            AssertRelayStateOutcome(logout, accepted);
            AssertRelayStateOutcome(logoutResponse, accepted);
        }

        [Fact]
        public async Task ExternalLogout_LongRelayState_NoConsume_Test()
        {
            using var context = ServiceFactory.Create();
            var saml = context.SignedBase64(context.NewLogoutRequest());

            var rejected = await SubmitLogoutRequestAsync(context, saml, relayState: new string('r', 81));
            var accepted = await SubmitLogoutRequestAsync(context, saml, relayState: "ok");

            AssertRejectedWith(rejected, RequestBuilderMessages.RelayStateTooLong);
            AssertAccepted(accepted);
        }

        private static void AssertRelayStateOutcome(RzR.ResultMessage.Abstractions.IResult result, bool accepted)
        {
            if (accepted)
                AssertAccepted(result);
            else
                AssertRejectedWith(result, RequestBuilderMessages.RelayStateTooLong);
        }

        [Fact]
        public async Task GenerateAuth_RelayStateMarkup_OneForm_Test()
        {
            using var context = ServiceFactory.Create();
            var relayState = "x" + HtmlMetacharacters + "<script>alert(1)</script>";

            var result = await context.Auth.GenerateAuthRequestAsync(new GenerateAuthRequestDto
            {
                RelayState = relayState
            }, Ct);

            AssertAccepted(result);
            AssertSafeForm(result.Response.HtmlDocument, "SAMLRequest", relayState, MPassTestSettings.DefaultIdpLoginUrl);
        }

        [Fact]
        public async Task Outbound_LogoutRelayStateMarkup_Encoded_Test()
        {
            using var context = ServiceFactory.Create();
            var relayState = HtmlMetacharacters + "\"><img src=x onerror=alert(1)>";

            var logoutRequest = await context.Auth.GenerateLogoutRequestAsync(new GenerateLogOutRequestDto
            {
                RelayState = relayState,
                SessionIndexId = "_session-1",
                UserIdentifierId = SamlFixtures.DefaultNameId
            }, Ct);
            var logoutResponse = await SubmitLogoutRequestAsync(context, context.SignedBase64(context.NewLogoutRequest()), relayState: relayState);

            AssertAccepted(logoutRequest);
            AssertAccepted(logoutResponse);
            AssertSafeForm(logoutRequest.Response.HtmlDocument, "SAMLRequest", relayState, MPassTestSettings.DefaultIdpLogoutUrl);
            AssertSafeForm(logoutResponse.Response.HtmlDocument, "SAMLResponse", relayState, MPassTestSettings.DefaultIdpLogoutUrl);
        }

        [Fact]
        public async Task GenerateAuth_DestinationMarkup_ActionEncoded_Test()
        {
            var settings = new MPassTestSettings
            {
                SamlLoginDestination = "https://idp.test.local/saml/login?a=1&b=\"x\"&c='y'"
            };
            using var context = ServiceFactory.Create(settings);

            var result = await context.Auth.GenerateAuthRequestAsync(new GenerateAuthRequestDto
            {
                RelayState = "rs"
            }, Ct);

            AssertAccepted(result);
            AssertSafeForm(result.Response.HtmlDocument, "SAMLRequest", "rs", settings.SamlLoginDestination);
        }

        private static void AssertSafeForm(string html, string samlVariable, string expectedRelayState, string expectedAction)
        {
            Assert.Equal(1, HtmlFormReader.CountForms(html));
            Assert.Equal(2, CountOccurrences(html, "type=\"hidden\""));
            Assert.Equal(3, CountOccurrences(html, "<input"));
            Assert.Equal(expectedRelayState, HtmlFormReader.GetInputValue(html, "RelayState"));
            Assert.Equal(expectedAction, HtmlFormReader.GetFormAction(html));
            Assert.NotNull(HtmlFormReader.GetInputValue(html, samlVariable));
            Assert.DoesNotContain("<script", html, StringComparison.OrdinalIgnoreCase);
            Assert.DoesNotContain("<img", html, StringComparison.OrdinalIgnoreCase);
            Assert.Contains("name=\"RelayState\"", html, StringComparison.Ordinal);
            Assert.DoesNotContain("value='", html, StringComparison.Ordinal);
        }

        [Fact]
        public async Task GenerateAuth_IssuerMarkup_RoundTrips_Test()
        {
            const string issuer = "https://sp.test.local/metadata?a=1&b=<2>\"q\"'s'";
            using var context = ServiceFactory.Create(new MPassTestSettings
            {
                SamlRequestIssuer = issuer
            });

            var result = await context.Auth.GenerateAuthRequestAsync(new GenerateAuthRequestDto
            {
                RelayState = "rs"
            }, Ct);

            AssertAccepted(result);
            var document = FixtureEncoding.LoadXml(HtmlFormReader.GetSamlXml(result.Response.HtmlDocument, "SAMLRequest"));
            var ns = SamlNs.CreateNamespaceManager(document);
            Assert.Equal("AuthnRequest", document.DocumentElement.LocalName);
            Assert.Equal(issuer, document.SelectSingleNode("/saml2p:AuthnRequest/saml2:Issuer", ns)?.InnerText);
            Assert.Single(document.DocumentElement.SelectNodes("saml2:Issuer", ns).Cast<XmlNode>());
        }

        [Fact]
        public async Task GenerateLogout_IdentifierMarkup_RoundTrips_Test()
        {
            const string nameId = "200<0>&\"1\"'";
            const string sessionIndex = "_s</saml2p:SessionIndex><saml2:Inserted/>";
            using var context = ServiceFactory.Create();

            var result = await context.Auth.GenerateLogoutRequestAsync(new GenerateLogOutRequestDto
            {
                RelayState = "rs",
                SessionIndexId = sessionIndex,
                UserIdentifierId = nameId
            }, Ct);

            AssertAccepted(result);
            var document = FixtureEncoding.LoadXml(HtmlFormReader.GetSamlXml(result.Response.HtmlDocument, "SAMLRequest"));
            var ns = SamlNs.CreateNamespaceManager(document);
            Assert.Equal(nameId, document.SelectSingleNode("/saml2p:LogoutRequest/saml2:NameID", ns)?.InnerText);
            Assert.Equal(sessionIndex, document.SelectSingleNode("/saml2p:LogoutRequest/saml2p:SessionIndex", ns)?.InnerText);
            Assert.Null(document.SelectSingleNode("//saml2:Inserted", ns));
        }

        [Fact]
        public async Task GenerateLogout_InvalidCharacter_Rejected_Test()
        {
            using var context = ServiceFactory.Create();

            var result = await context.Auth.GenerateLogoutRequestAsync(new GenerateLogOutRequestDto
            {
                RelayState = "rs",
                SessionIndexId = "_session-1",
                UserIdentifierId = "2000\u0001000"
            }, Ct);

            AssertRejected(result);
            AssertOnlyFixedMessages(result);
        }

        [Fact]
        public async Task GenerateAuth_Signature_VerifiesRsaSha256_Test()
        {
            using var context = ServiceFactory.Create();

            var result = await context.Auth.GenerateAuthRequestAsync(new GenerateAuthRequestDto
            {
                RelayState = "rs"
            }, Ct);

            AssertAccepted(result);
            AssertOutboundSignature(HtmlFormReader.GetSamlXml(result.Response.HtmlDocument, "SAMLRequest"), "AuthnRequest");
        }

        [Fact]
        public async Task GenerateLogout_Signature_VerifiesRsaSha256_Test()
        {
            using var context = ServiceFactory.Create();

            var result = await context.Auth.GenerateLogoutRequestAsync(new GenerateLogOutRequestDto
            {
                RelayState = "rs",
                SessionIndexId = "_session-1",
                UserIdentifierId = SamlFixtures.DefaultNameId
            }, Ct);

            AssertAccepted(result);
            AssertOutboundSignature(HtmlFormReader.GetSamlXml(result.Response.HtmlDocument, "SAMLRequest"), "LogoutRequest");
        }

        [Fact]
        public async Task ExternalLogout_Signature_VerifiesRsaSha256_Test()
        {
            using var context = ServiceFactory.Create();
            var inbound = context.NewLogoutRequest();

            var result = await SubmitLogoutRequestAsync(context, context.SignedBase64(inbound));

            AssertAccepted(result);
            var xml = HtmlFormReader.GetSamlXml(result.Response.HtmlDocument, "SAMLResponse");
            AssertOutboundSignature(xml, "LogoutResponse");
            var document = FixtureEncoding.LoadXml(xml);
            Assert.Equal(inbound.Id, document.DocumentElement.GetAttribute("InResponseTo"));
            Assert.Equal(result.Response.LogoutResponseId, document.DocumentElement.GetAttribute("ID"));
        }

        private static void AssertOutboundSignature(string xml, string expectedRoot)
        {
            Assert.False(string.IsNullOrEmpty(xml));
            var document = FixtureEncoding.LoadXml(xml);
            var root = document.DocumentElement;
            var ns = SamlNs.CreateNamespaceManager(document);
            var rootId = root.GetAttribute("ID");

            var load = SamlXmlLoadHelper.LoadFromBase64(FixtureEncoding.ToBase64(xml), 0);
            AssertAccepted(load);
            
            var verified = SamlMessageLoadAndVerifyHelper.VerifySignature(load.Response, TestCertificates.Collection(TestCertificates.Sp), expectedRoot, false);
            Assert.True(verified.IsSuccess && verified.Response, "outbound signature not verified: " + Describe(verified));
           
            var wrongKey = SamlMessageLoadAndVerifyHelper.VerifySignature(load.Response, TestCertificates.Collection(TestCertificates.Idp), expectedRoot, false);
            Assert.False(wrongKey.IsSuccess && wrongKey.Response);

            var signature = Assert.Single(FixtureSigner.DirectSignatures(root));
            var previous = signature.PreviousSibling as XmlElement;
            Assert.NotNull(previous);
            Assert.Equal("Issuer", previous.LocalName);
            Assert.Equal(SignedXml.XmlDsigRSASHA256Url, signature.SelectSingleNode("ds:SignedInfo/ds:SignatureMethod/@Algorithm", ns)?.Value);
            Assert.Equal(SignedXml.XmlDsigExcC14NTransformUrl, signature.SelectSingleNode("ds:SignedInfo/ds:CanonicalizationMethod/@Algorithm", ns)?.Value);
            
            var reference = Assert.Single(signature.SelectNodes("ds:SignedInfo/ds:Reference", ns).Cast<XmlElement>());
            Assert.Equal("#" + rootId, reference.GetAttribute("URI"));
            Assert.Equal(SignedXml.XmlDsigSHA256Url, reference.SelectSingleNode("ds:DigestMethod/@Algorithm", ns)?.Value);
           
            var transforms = reference.SelectNodes("ds:Transforms/ds:Transform/@Algorithm", ns).Cast<XmlNode>().Select(n => n.Value).ToList();
            Assert.Equal(new[] { SignedXml.XmlDsigEnvelopedSignatureTransformUrl, SignedXml.XmlDsigExcC14NTransformUrl }, transforms);

            var certificates = signature.SelectNodes("ds:KeyInfo/ds:X509Data/ds:X509Certificate", ns);
            Assert.Equal(1, certificates.Count);
            Assert.Equal(Convert.ToBase64String(TestCertificates.Sp.RawData), certificates[0].InnerText.Trim());
            Assert.DoesNotContain("PrivateKey", signature.OuterXml, StringComparison.OrdinalIgnoreCase);
            Assert.Null(signature.SelectSingleNode("ds:KeyInfo/ds:KeyValue", ns));

            Assert.EndsWith("Z", root.GetAttribute("IssueInstant"), StringComparison.Ordinal);
            Assert.Equal(TestClock.Epoch.UtcDateTime, XmlConvert.ToDateTime(root.GetAttribute("IssueInstant"), XmlDateTimeSerializationMode.Utc));
        }

        [Fact]
        public void GenerateRequestId_10000Ids_UniqueNCNames_Test()
        {
            var ids = new HashSet<string>(StringComparer.Ordinal);
            for (var i = 0; i < 10000; i++)
            {
                var id = StringExtensions.GenerateRequestId();

                Assert.Equal(id, XmlConvert.VerifyNCName(id));
                Assert.StartsWith("_", id, StringComparison.Ordinal);
                Assert.Equal(33, id.Length);
                Assert.Matches("^_[0-9a-f]{32}$", id);
                Assert.True(ids.Add(id), "duplicate id " + id);
            }
        }

        [Fact]
        public async Task GenerateAuth_RequestIds_UniqueMatchMessageId_Test()
        {
            using var context = ServiceFactory.Create();
            var ids = new HashSet<string>(StringComparer.Ordinal);

            for (var i = 0; i < 50; i++)
            {
                var result = await context.Auth.GenerateAuthRequestAsync(new GenerateAuthRequestDto { RelayState = "rs" }, Ct);
                AssertAccepted(result);
                var document = FixtureEncoding.LoadXml(HtmlFormReader.GetSamlXml(result.Response.HtmlDocument, "SAMLRequest"));

                Assert.Equal(result.Response.AuthRequestId, document.DocumentElement.GetAttribute("ID"));
                Assert.Matches("^_[0-9a-f]{32}$", result.Response.AuthRequestId);
                Assert.True(ids.Add(result.Response.AuthRequestId));
            }
        }

        private static int CountOccurrences(string text, string fragment)
        {
            var count = 0;
            var index = text.IndexOf(fragment, StringComparison.OrdinalIgnoreCase);
            while (index >= 0)
            {
                count++;
                index = text.IndexOf(fragment, index + fragment.Length, StringComparison.OrdinalIgnoreCase);
            }

            return count;
        }
    }
}
