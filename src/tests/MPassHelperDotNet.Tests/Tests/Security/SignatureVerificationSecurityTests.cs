using System.Security.Cryptography.X509Certificates;
using System.Threading.Tasks;
using System.Xml;
using MPassHelperDotNet.Helpers.Messages;
using MPassHelperDotNet.Helpers.SAML;
using MPassHelperDotNet.Tests.Helpers.Certificates;
using MPassHelperDotNet.Tests.Helpers.Hosting;
using MPassHelperDotNet.Tests.Helpers.Runtime;
using MPassHelperDotNet.Tests.Helpers.Saml;
using MPassHelperDotNet.Tests.Helpers.Signing;
using MPassHelperDotNet.Tests.Models.Hosting;
using MPassHelperDotNet.Tests.Models.Saml;
using MPassHelperDotNet.Tests.Models.Signing;
using Xunit;
using static MPassHelperDotNet.Tests.Helpers.Kits.SecurityTestKit;

namespace MPassHelperDotNet.Tests.Tests.Security
{
    [Trait(TestAreas.Trait, TestAreas.Security)]
    public class SignatureVerificationSecurityTests
    {
        public static TheoryData<string> RejectedVariants => CommonRejectedVariantData();

        [Theory]
        [MemberData(nameof(RejectedVariants))]
        public async Task LoginResponse_SignatureVariant_NoUserData_Test(string variant)
        {
            using var context = ServiceFactory.Create();
            var requestId = NewRequestId();
            var document = ApplyVariant(SamlFixtureBuilder.Build(context.NewLoginResponse(requestId)), variant);

            var result = await SubmitLoginAsync(context, FixtureEncoding.ToBase64(document), requestId);

            AssertRejectedWith(result, SamlLoadValidationMessages.InvalidSamlResponseSignature);
            Assert.Null(result.Response?.UserInfo);
        }

        [Fact]
        public async Task LoginResponse_AssertionOnlySigned_Rejected_Test()
        {
            using var context = ServiceFactory.Create();
            var requestId = NewRequestId();

            var saml = context.SignedBase64(context.NewLoginResponse(requestId), new FixtureSigningOptions
            {
                Placement = SignaturePlacement.Assertion
            });
            var result = await SubmitLoginAsync(context, saml, requestId);

            AssertRejectedWith(result, SamlLoadValidationMessages.InvalidSamlResponseSignature);
            Assert.Null(result.Response?.UserInfo);
        }

        [Fact]
        public async Task LoginResponse_BothSigned_Accepted_Test()
        {
            using var context = ServiceFactory.Create();
            var requestId = NewRequestId();

            var saml = context.SignedBase64(context.NewLoginResponse(requestId),
                new FixtureSigningOptions { Placement = SignaturePlacement.RootAndAssertion });
            var result = await SubmitLoginAsync(context, saml, requestId);

            AssertAccepted(result);
            Assert.Equal(SamlFixtures.DefaultNameId, result.Response.UserInfo.Idnp);
        }

        [Fact]
        public async Task LoginResponse_TwoReferences_Rejected_Test()
        {
            using var context = ServiceFactory.Create();
            var requestId = NewRequestId();
            var fixture = context.NewLoginResponse(requestId);

            var saml = context.SignedBase64(fixture, new FixtureSigningOptions
            {
                ExtraReferenceUri = "#" + fixture.Assertions[0].Id
            });
            var result = await SubmitLoginAsync(context, saml, requestId);

            AssertRejected(result);
        }

        [Fact]
        public async Task LoginResponse_RootSignsAssertion_Rejected_Test()
        {
            using var context = ServiceFactory.Create();
            var requestId = NewRequestId();
            var fixture = context.NewLoginResponse(requestId);

            var saml = context.SignedBase64(fixture, new FixtureSigningOptions
            {
                ReferenceUri = "#" + fixture.Assertions[0].Id
            });
            var result = await SubmitLoginAsync(context, saml, requestId);

            AssertRejected(result);
        }

        [Theory]
        [InlineData("ID")]
        [InlineData("Id")]
        [InlineData("id")]
        public async Task LoginResponse_DuplicateRootId_Rejected_Test(string attributeName)
        {
            using var context = ServiceFactory.Create();
            var requestId = NewRequestId();
            var fixture = context.NewLoginResponse(requestId);
            fixture.DuplicateIdAttributeName = attributeName;

            var result = await SubmitLoginAsync(context, context.SignedBase64(fixture), requestId);

            AssertRejected(result);
        }

        [Fact]
        public async Task LoginResponse_AssertionWithRootId_Rejected_Test()
        {
            using var context = ServiceFactory.Create();
            var requestId = NewRequestId();
            var fixture = context.NewLoginResponse(requestId);
            fixture.Assertions[0].Id = fixture.Id;

            var result = await SubmitLoginAsync(context, context.SignedBase64(fixture), requestId);

            AssertRejected(result);
        }

        [Fact]
        public async Task LoginResponse_UnsignedOuter_RejectedNoUser_Test()
        {
            using var context = ServiceFactory.Create();
            var requestId = NewRequestId();
            var original = FixtureSigner.Sign(SamlFixtureBuilder.Build(context.NewLoginResponse(requestId)));

            var outer = context.NewLoginResponse(requestId);
            outer.Assertions[0].NameId = "2999999999999";
            outer.EmbeddedDocument = original;
            var result = await SubmitLoginAsync(context, ResponseBase64(outer), requestId);

            AssertRejected(result);
            Assert.Null(result.Response?.UserInfo);
        }

        [Fact]
        public async Task LoginResponse_CopiedIdAndSignature_Rejected_Test()
        {
            using var context = ServiceFactory.Create();
            var requestId = NewRequestId();
            var originalFixture = context.NewLoginResponse(requestId);
            var original = FixtureSigner.Sign(SamlFixtureBuilder.Build(originalFixture));

            var outerFixture = context.NewLoginResponse(requestId);
            outerFixture.Id = originalFixture.Id;
            outerFixture.Assertions[0].NameId = "2999999999999";
            outerFixture.EmbeddedDocument = original;
            var outer = SamlFixtureBuilder.Build(outerFixture);
            var originalSignature = Assert.Single(FixtureSigner.DirectSignatures(original.DocumentElement));
            outer.DocumentElement.InsertAfter(outer.ImportNode(originalSignature, true), outer.DocumentElement.FirstChild);

            var result = await SubmitLoginAsync(context, FixtureEncoding.ToBase64(outer), requestId);

            AssertRejected(result);
            Assert.Null(result.Response?.UserInfo);
        }

        [Fact]
        public async Task LoginResponse_NameIdAltered_Rejected_Test()
        {
            using var context = ServiceFactory.Create();
            var requestId = NewRequestId();
            var signed = FixtureSigner.Sign(SamlFixtureBuilder.Build(context.NewLoginResponse(requestId)));
            var nameId = signed.SelectSingleNode("/saml2p:Response/saml2:Assertion/saml2:Subject/saml2:NameID", SamlNs.CreateNamespaceManager(signed));
            nameId.InnerText = "2999999999999";

            var result = await SubmitLoginAsync(context, FixtureEncoding.ToBase64(signed), requestId);

            AssertRejected(result);
            Assert.Null(result.Response?.UserInfo);
        }

        [Fact]
        public async Task LoginResponse_RotationCertSecond_Accepted_Test()
        {
            var settings = new MPassTestSettings
            {
                IdentityProviderCertificate = TestCertificates.WrongKey
            };
            settings.IdentityProviderAdditionalCertificates.Add(TestCertificates.IdpRotation);
            using var context = ServiceFactory.Create(settings);
            var requestId = NewRequestId();

            var saml = FixtureEncoding.ToBase64(ApplyVariant(SamlFixtureBuilder.Build(context.NewLoginResponse(requestId)), "rotation-cert"));
            var result = await SubmitLoginAsync(context, saml, requestId);

            AssertAccepted(result);
            Assert.Equal(SamlFixtures.DefaultNameId, result.Response.UserInfo.Idnp);
        }

        [Fact]
        public async Task LoginResponse_RotationCertNotSet_Rejected_Test()
        {
            using var context = ServiceFactory.Create();
            var requestId = NewRequestId();

            var saml = FixtureEncoding.ToBase64(ApplyVariant(SamlFixtureBuilder.Build(context.NewLoginResponse(requestId)), "rotation-cert"));
            var result = await SubmitLoginAsync(context, saml, requestId);

            AssertRejected(result);
        }

        [Fact]
        public async Task LoginResponse_Sha1Default_AlgorithmNotAllowed_Test()
        {
            using var context = ServiceFactory.Create();
            var requestId = NewRequestId();

            var saml = context.SignedBase64(context.NewLoginResponse(requestId), FixtureSigningOptions.Sha1());
            var result = await SubmitLoginAsync(context, saml, requestId);

            AssertRejectedWith(result, SamlLoadValidationMessages.SamlSignatureAlgorithmNotAllowed);
        }

        [Fact]
        public async Task LoginResponse_Sha1WhenAllowed_Accepted_Test()
        {
            using var context = ServiceFactory.Create(new MPassTestSettings
            {
                AllowSha1Signatures = true
            });
            var requestId = NewRequestId();

            var saml = context.SignedBase64(context.NewLoginResponse(requestId), FixtureSigningOptions.Sha1());
            var result = await SubmitLoginAsync(context, saml, requestId);

            AssertAccepted(result);
        }

        [Fact]
        public async Task LoginResponse_EnvelopedOnly_Accepted_Test()
        {
            using var context = ServiceFactory.Create();
            var requestId = NewRequestId();

            var saml = context.SignedBase64(context.NewLoginResponse(requestId), FixtureSigningOptions.EnvelopedOnly());
            var result = await SubmitLoginAsync(context, saml, requestId);

            AssertAccepted(result);
        }

        [Theory]
        [InlineData("LogoutResponse")]
        [InlineData("LogoutRequest")]
        public async Task LoginResponseEndpoint_LogoutMessage_Rejected_Test(string rootType)
        {
            using var context = ServiceFactory.Create();
            var requestId = NewRequestId();
            var saml = rootType == "LogoutResponse"
                ? context.SignedBase64(context.NewLogoutResponse(requestId))
                : context.SignedBase64(context.NewLogoutRequest());

            var result = await SubmitLoginAsync(context, saml, requestId);

            AssertRejected(result);
            Assert.Null(result.Response?.UserInfo);
        }

        [Fact]
        public async Task LoginResponse_CommentInNameId_FullOrRejected_Test()
        {
            using var context = ServiceFactory.Create();
            var requestId = NewRequestId();
            var fixture = context.NewLoginResponse(requestId);
            fixture.Assertions[0].NameIdCommentPosition = 5;

            var result = await SubmitLoginAsync(context, context.SignedBase64(fixture), requestId);

            if (result.IsSuccess)
                Assert.Equal(SamlFixtures.DefaultNameId, result.Response.UserInfo.Idnp);
            else
                AssertRejected(result);
        }

        [Theory]
        [MemberData(nameof(RejectedVariants))]
        public async Task LogoutResponse_SignatureVariant_Rejected_Test(string variant)
        {
            using var context = ServiceFactory.Create();
            var requestId = NewRequestId();
            var document = ApplyVariant(SamlFixtureBuilder.Build(context.NewLogoutResponse(requestId)), variant);

            var result = await SubmitLogoutResponseAsync(context, FixtureEncoding.ToBase64(document), requestId);

            AssertRejectedWith(result, SamlLoadValidationMessages.InvalidSamlResponseSignature);
        }

        [Theory]
        [MemberData(nameof(RejectedVariants))]
        public async Task LogoutRequest_SignatureVariant_NoResponse_Test(string variant)
        {
            using var context = ServiceFactory.Create();
            var document = ApplyVariant(SamlFixtureBuilder.Build(context.NewLogoutRequest()), variant);

            var result = await SubmitLogoutRequestAsync(context, FixtureEncoding.ToBase64(document));

            AssertRejectedWith(result, SamlLoadValidationMessages.SamlLogOutRequestInvalidSignature);
            Assert.Null(result.Response?.HtmlDocument);
        }

        [Fact]
        public async Task LogoutResponseEndpoint_LoginResponse_Rejected_Test()
        {
            using var context = ServiceFactory.Create();
            var requestId = NewRequestId();

            var result = await SubmitLogoutResponseAsync(context, context.SignedBase64(context.NewLoginResponse(requestId)), requestId);

            AssertRejected(result);
        }

        [Fact]
        public async Task LogoutRequestEndpoint_LoginResponse_Rejected_Test()
        {
            using var context = ServiceFactory.Create();

            var result = await SubmitLogoutRequestAsync(context, context.SignedBase64(context.NewLoginResponse(NewRequestId())));

            AssertRejected(result);
        }

        [Fact]
        public async Task Logout_RotationCert_Accepted_Test()
        {
            var settings = new MPassTestSettings
            {
                IdentityProviderCertificate = TestCertificates.WrongKey
            };
            settings.IdentityProviderAdditionalCertificates.Add(TestCertificates.IdpRotation);
            using var context = ServiceFactory.Create(settings);
            var requestId = NewRequestId();
            var rotation = new FixtureSigningOptions
            {
                Certificate = TestCertificates.IdpRotation
            };

            var responseResult = await SubmitLogoutResponseAsync(context, context.SignedBase64(context.NewLogoutResponse(requestId), rotation), requestId);
            var requestResult = await SubmitLogoutRequestAsync(context, context.SignedBase64(context.NewLogoutRequest(), rotation));

            AssertAccepted(responseResult);
            AssertAccepted(requestResult);
        }

        [Theory]
        [MemberData(nameof(RejectedVariants))]
        public void VerifySignature_RejectedVariant_NotVerified_Test(string variant)
        {
            var settings = new MPassTestSettings();
            var now = TestClock.Epoch;
            var requestId = NewRequestId();
            var cases = new (XmlDocument Document, string Root)[]
            {
                (SamlFixtureBuilder.Build(SamlFixtures.LoginResponse(settings, now, requestId)), "Response"),
                (SamlFixtureBuilder.Build(SamlFixtures.LogoutResponse(settings, now, requestId)), "LogoutResponse"),
                (SamlFixtureBuilder.Build(SamlFixtures.LogoutRequest(settings, now)), "LogoutRequest")
            };

            foreach (var (unsigned, root) in cases)
            {
                var result = VerifyDirect(ApplyVariant(unsigned, variant), root, TestCertificates.Collection(TestCertificates.Idp), false);

                Assert.False(result.IsSuccess && result.Response, variant + " was verified on " + root);
            }
        }

        [Theory]
        [InlineData("rotation-cert", false)]
        [InlineData("sha1-allowed", true)]
        [InlineData("enveloped-only", false)]
        public void VerifySignature_AcceptedVariant_Verified_Test(string variant, bool allowSha1)
        {
            var unsigned = SamlFixtureBuilder.Build(SamlFixtures.LoginResponse(new MPassTestSettings(), TestClock.Epoch, NewRequestId()));
            var certificates = TestCertificates.Collection(TestCertificates.WrongKey, TestCertificates.Idp, TestCertificates.IdpRotation);

            var result = VerifyDirect(ApplyVariant(unsigned, variant), "Response", certificates, allowSha1);

            Assert.True(result.IsSuccess && result.Response, Describe(result));
        }

        [Fact]
        public void VerifySignature_AssertionOnlyFails_RootOk_Test()
        {
            var unsigned = SamlFixtureBuilder.Build(SamlFixtures.LoginResponse(new MPassTestSettings(), TestClock.Epoch, NewRequestId()));
            var certificates = TestCertificates.Collection(TestCertificates.Idp);

            var both = VerifyDirect(FixtureSigner.Sign(unsigned, new FixtureSigningOptions { Placement = SignaturePlacement.RootAndAssertion }),
                "Response", certificates, false);
            var assertionOnly = VerifyDirect(FixtureSigner.Sign(unsigned, new FixtureSigningOptions { Placement = SignaturePlacement.Assertion }),
                "Response", certificates, false);

            Assert.True(both.IsSuccess && both.Response, Describe(both));
            Assert.False(assertionOnly.IsSuccess && assertionOnly.Response);
        }

        [Fact]
        public void VerifySignature_WrongExpectedRoot_NotVerified_Test()
        {
            var signed = FixtureSigner.Sign(SamlFixtureBuilder.Build(SamlFixtures.LogoutResponse(new MPassTestSettings(), TestClock.Epoch, NewRequestId())));

            var result = VerifyDirect(signed, "Response", TestCertificates.Collection(TestCertificates.Idp), false);

            Assert.False(result.IsSuccess && result.Response);
        }

        [Fact]
        public void VerifySignature_MissingCert_NotVerified_Test()
        {
            var signed = FixtureSigner.Sign(SamlFixtureBuilder.Build(SamlFixtures.LoginResponse(new MPassTestSettings(), TestClock.Epoch, NewRequestId())));

            var empty = VerifyDirect(signed, "Response", new X509Certificate2Collection(), false);
            var none = VerifyDirect(signed, "Response", null, false);

            Assert.False(empty.IsSuccess && empty.Response);
            Assert.False(none.IsSuccess && none.Response);
        }

        private static RzR.ResultMessage.Abstractions.IResult<bool> VerifyDirect(XmlDocument document, string expectedRoot,
            X509Certificate2Collection certificates, bool allowSha1)
        {
            var load = SamlXmlLoadHelper.LoadFromBase64(FixtureEncoding.ToBase64(document), 0);
            Assert.True(load.IsSuccess, "fixture did not load: " + Describe(load));

            return SamlMessageLoadAndVerifyHelper.VerifySignature(load.Response, certificates, expectedRoot, allowSha1);
        }

        private static string ResponseBase64(ResponseFixture fixture) => FixtureEncoding.ToBase64(SamlFixtureBuilder.Build(fixture));
    }
}
