using System;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using MPassHelperDotNet.Helpers.Messages;
using MPassHelperDotNet.Helpers.SAML;
using MPassHelperDotNet.Tests.Helpers.Hosting;
using MPassHelperDotNet.Tests.Helpers.Http;
using MPassHelperDotNet.Tests.Helpers.Runtime;
using MPassHelperDotNet.Tests.Helpers.Saml;
using MPassHelperDotNet.Tests.Helpers.Signing;
using MPassHelperDotNet.Tests.Models.Hosting;
using Xunit;
using static MPassHelperDotNet.Tests.Helpers.Kits.SecurityTestKit;

namespace MPassHelperDotNet.Tests.Tests.Security
{
    [Trait(TestAreas.Trait, TestAreas.Security)]
    public class XmlLoadingSecurityTests
    {
        [Fact]
        public async Task Doctype_RejectedByLoaderAndFacade_Test()
        {
            using var context = ServiceFactory.Create();
            var requestId = NewRequestId();
            var signedXml = SignedLoginXml(context, requestId);
            var xml = "<!DOCTYPE Response [<!ELEMENT Response ANY>]>" + signedXml;

            var load = SamlXmlLoadHelper.LoadFromBase64(FixtureEncoding.ToBase64(xml), 0);
            var result = await SubmitLoginAsync(context, FixtureEncoding.ToBase64(xml), requestId);

            AssertRejectedWith(load, SamlLoadValidationMessages.SamlXmlInvalid);
            AssertRejected(result);
            Assert.Null(result.Response?.UserInfo);
        }

        [Fact]
        public async Task ExternalEntity_RejectedNeverResolved_Test()
        {
            using var server = LoopbackHttpServer.Start();
            using var context = ServiceFactory.Create();
            var requestId = NewRequestId();
            var entityUrl = server.Url("entity.txt");
            var xml = "<!DOCTYPE r [<!ENTITY ext SYSTEM \"" + entityUrl + "\">]>" +
                      "<r xmlns=\"urn:oasis:names:tc:SAML:2.0:protocol\">&ext;</r>";

            var load = SamlXmlLoadHelper.LoadFromBase64(FixtureEncoding.ToBase64(xml), 0);
            var result = await SubmitLoginAsync(context, FixtureEncoding.ToBase64(xml), requestId);
            var logoutResult = await SubmitLogoutRequestAsync(context, FixtureEncoding.ToBase64(xml));

            AssertRejected(load);
            AssertRejected(result);
            AssertRejected(logoutResult);
            Assert.Equal(0, server.RequestCount);
        }

        [Fact]
        public async Task ParameterEntityInSigned_RejectedNotResolved_Test()
        {
            using var server = LoopbackHttpServer.Start();
            using var context = ServiceFactory.Create();
            var requestId = NewRequestId();
            var xml = "<!DOCTYPE Response [<!ENTITY % pe SYSTEM \"" + server.Url("pe.dtd") + "\"> %pe;]>" + SignedLoginXml(context, requestId);

            var result = await SubmitLoginAsync(context, FixtureEncoding.ToBase64(xml), requestId);

            AssertRejected(result);
            Assert.Equal(0, server.RequestCount);
        }

        [Theory]
        [InlineData("%%%not-base64%%%")]
        [InlineData("PHI+")]
        [InlineData("QUJD=")]
        public async Task InvalidBase64OrXml_RejectedFixedMessages_Test(string samlResponse)
        {
            using var context = ServiceFactory.Create();

            var load = SamlXmlLoadHelper.LoadFromBase64(samlResponse, 0);
            var result = await SubmitLoginAsync(context, samlResponse, NewRequestId());

            AssertRejected(load);
            Assert.True(MessageTexts(load).Any(t => t == SamlLoadValidationMessages.SamlMessageEncodingInvalid
                                                    || t == SamlLoadValidationMessages.SamlXmlInvalid), Describe(load));
            AssertRejected(result);
            AssertOnlyFixedMessages(result);
        }

        [Fact]
        public async Task NonUtf8Payload_RejectedEncodingInvalid_Test()
        {
            using var context = ServiceFactory.Create();
            var prefix = Encoding.UTF8.GetBytes("<saml2p:Response xmlns:saml2p=\"urn:oasis:names:tc:SAML:2.0:protocol\" ID=\"_x\">");
            var invalid = new byte[] { 0xC3, 0x28, 0xFF, 0xFE };
            var suffix = Encoding.UTF8.GetBytes("</saml2p:Response>");
            var base64 = FixtureEncoding.ToBase64(prefix.Concat(invalid).Concat(suffix).ToArray());

            var load = SamlXmlLoadHelper.LoadFromBase64(base64, 0);
            var result = await SubmitLoginAsync(context, base64, NewRequestId());

            AssertRejectedWith(load, SamlLoadValidationMessages.SamlMessageEncodingInvalid);
            AssertRejected(result);
        }

        [Fact]
        public async Task Inbound_Oversize_RejectedBeforeDecoding_Test()
        {
            using var context = ServiceFactory.Create(new MPassTestSettings
            {
                SamlMessageMaxLength = 4096
            });
            var requestId = NewRequestId();
            var valid = context.SignedBase64(context.NewLoginResponse(requestId));
            Assert.True(valid.Length > 4096, "fixture too small for the test");

            var garbage = new string('%', 4097);

            var validResult = await SubmitLoginAsync(context, valid, requestId);
            var garbageResult = await SubmitLoginAsync(context, garbage, requestId);
            var load = SamlXmlLoadHelper.LoadFromBase64(garbage, 4096);

            AssertRejectedWith(validResult, SamlLoadValidationMessages.SamlMessageTooLarge);
            AssertRejectedWith(garbageResult, SamlLoadValidationMessages.SamlMessageTooLarge);
            AssertRejectedWith(load, SamlLoadValidationMessages.SamlMessageTooLarge);
        }

        [Fact]
        public async Task Logout_OversizeMessage_Rejected_Test()
        {
            using var context = ServiceFactory.Create(new MPassTestSettings
            {
                SamlMessageMaxLength = 1024
            });
            var requestId = NewRequestId();

            var responseResult = await SubmitLogoutResponseAsync(context, context.SignedBase64(context.NewLogoutResponse(requestId)), requestId);
            var requestResult = await SubmitLogoutRequestAsync(context, context.SignedBase64(context.NewLogoutRequest()));

            AssertRejectedWith(responseResult, SamlLoadValidationMessages.SamlMessageTooLarge);
            AssertRejectedWith(requestResult, SamlLoadValidationMessages.SamlMessageTooLarge);
        }

        [Fact]
        public void DefaultLimit_256KiB_AppliesWhenUnset_Test()
        {
            var tooLarge = new string('A', 262144 + 4);

            var load = SamlXmlLoadHelper.LoadFromBase64(tooLarge, 0);

            AssertRejectedWith(load, SamlLoadValidationMessages.SamlMessageTooLarge);
        }

        [Fact]
        public void DeeplyNestedDocument_Rejected_Test()
        {
            var depth = 200;
            var xml = string.Concat(System.Linq.Enumerable.Repeat("<e>", depth)) + string.Concat(System.Linq.Enumerable.Repeat("</e>", depth));

            var load = SamlXmlLoadHelper.LoadFromBase64(FixtureEncoding.ToBase64(xml), 0);

            AssertRejectedWith(load, SamlLoadValidationMessages.SamlXmlInvalid);
        }

        [Fact]
        public async Task LoginResponse_PrettyPrinted_Accepted_Test()
        {
            using var context = ServiceFactory.Create();
            var requestId = NewRequestId();

            var result = await SubmitLoginAsync(context, context.SignedBase64(context.NewLoginResponse(requestId), indent: true), requestId);

            AssertAccepted(result);
            Assert.Equal(SamlFixtures.DefaultNameId, result.Response.UserInfo.Idnp);
        }

        [Theory]
        [InlineData(true)]
        [InlineData(false)]
        public async Task ProcessingInstruction_Rejected_Test(bool beforeRoot)
        {
            using var context = ServiceFactory.Create();
            var requestId = NewRequestId();
            var signedXml = SignedLoginXml(context, requestId);
            const string pi = "<?xml-stylesheet type=\"text/xsl\" href=\"https://idp.test.local/x.xsl\"?>";
            var xml = beforeRoot
                ? "<?xml version=\"1.0\" encoding=\"UTF-8\"?>" + pi + signedXml
                : signedXml.Insert(signedXml.LastIndexOf("</saml2p:Response>", StringComparison.Ordinal), pi);

            var load = SamlXmlLoadHelper.LoadFromBase64(FixtureEncoding.ToBase64(xml), 0);
            var result = await SubmitLoginAsync(context, FixtureEncoding.ToBase64(xml), requestId);

            AssertRejectedWith(load, SamlLoadValidationMessages.SamlProcessingInstructionNotAllowed);
            AssertRejectedWith(result, SamlLoadValidationMessages.SamlProcessingInstructionNotAllowed);
        }

        [Fact]
        public void XmlDeclaration_NotProcessingInstruction_Test()
        {
            var settings = new MPassTestSettings();
            var signed = FixtureSigner.Sign(SamlFixtureBuilder.Build(SamlFixtures.LoginResponse(settings, TestClock.Epoch, NewRequestId())));
            var xml = "<?xml version=\"1.0\" encoding=\"UTF-8\"?>" + signed.OuterXml;

            var load = SamlXmlLoadHelper.LoadFromBase64(FixtureEncoding.ToBase64(xml), 0);

            AssertAccepted(load);
        }

        private static string SignedLoginXml(MPassTestContext context, string requestId)
            => FixtureSigner.Sign(SamlFixtureBuilder.Build(context.NewLoginResponse(requestId))).OuterXml;
    }
}
