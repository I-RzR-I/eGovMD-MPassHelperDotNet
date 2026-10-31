using System;
using System.Threading.Tasks;
using MPassHelperDotNet.Helpers;
using MPassHelperDotNet.Helpers.Messages;
using MPassHelperDotNet.Models.Dto.AuthService.LoginResponse;
using MPassHelperDotNet.Tests.Helpers.Hosting;
using MPassHelperDotNet.Tests.Helpers.Runtime;
using MPassHelperDotNet.Tests.Helpers.Saml;
using RzR.ResultMessage.Abstractions;
using Xunit;
using static MPassHelperDotNet.Tests.Helpers.Kits.SecurityTestKit;

namespace MPassHelperDotNet.Tests.Tests.Security
{
    [Trait(TestAreas.Trait, TestAreas.Security)]
    public class NoPassiveStatusSecurityTests
    {
        private const string NoPassive = "urn:oasis:names:tc:SAML:2.0:status:NoPassive";
        private const string StatusMarker = "idp-status-marker <b>x</b>";

        public static TheoryData<string, bool> TopLevelStatuses => new TheoryData<string, bool>
        {
            { SamlNs.StatusRequester, false },
            { SamlNs.StatusRequester, true },
            { SamlNs.StatusResponder, false },
            { SamlNs.StatusResponder, true }
        };

        [Theory]
        [MemberData(nameof(TopLevelStatuses))]
        public async Task SignedNoPassive_FixedMessageNoUserData_Test(string topLevelStatus, bool keepAssertion)
        {
            using var context = ServiceFactory.Create();
            var requestId = NewRequestId();
            var fixture = context.NewLoginResponse(requestId);
            fixture.StatusCode = topLevelStatus;
            fixture.SubStatusCode = NoPassive;
            fixture.StatusMessage = StatusMarker;
            if (!keepAssertion)
                fixture.Assertions.Clear();

            var result = await SubmitLoginAsync(context, context.SignedBase64(fixture), requestId);

            AssertOnlyNoPassive(result);
        }

        [Fact]
        public void NoPassiveConstants_FixedNoPlaceholders_Test()
        {
            Assert.Equal(NoPassive, DefaultStaticInfo.SamlUrnStatusNoPassive);
            Assert.DoesNotContain("{", SamlLoadValidationMessages.InvalidSamlResponseNoPassive, StringComparison.Ordinal);
        }

        [Fact]
        public async Task UnsignedNoPassive_SignatureFailed_Test()
        {
            using var context = ServiceFactory.Create();
            var requestId = NewRequestId();
            var fixture = context.NewLoginResponse(requestId);
            fixture.StatusCode = SamlNs.StatusRequester;
            fixture.SubStatusCode = NoPassive;
            fixture.StatusMessage = StatusMarker;
            fixture.Assertions.Clear();

            var result = await SubmitLoginAsync(context, MPassTestContext.UnsignedBase64(SamlFixtureBuilder.Build(fixture)), requestId);

            AssertRejectedWith(result, SamlLoadValidationMessages.InvalidSamlResponseSignature);
            AssertOnlyFixedMessages(result);
            Assert.DoesNotContain(MessageTexts(result), t => t == SamlLoadValidationMessages.InvalidSamlResponseNoPassive);
        }

        [Fact]
        public async Task LoginResponse_NoPassiveUpperCase_NotMapped_Test()
        {
            using var context = ServiceFactory.Create();
            var requestId = NewRequestId();
            var fixture = context.NewLoginResponse(requestId);
            fixture.StatusCode = SamlNs.StatusRequester;
            fixture.SubStatusCode = NoPassive.ToUpperInvariant();
            fixture.Assertions.Clear();

            var result = await SubmitLoginAsync(context, context.SignedBase64(fixture), requestId);

            AssertRejected(result);
            AssertOnlyFixedMessages(result);
            Assert.Null(result.Response?.UserInfo);
            Assert.DoesNotContain(MessageTexts(result), t => t == SamlLoadValidationMessages.InvalidSamlResponseNoPassive);
        }

        private static void AssertOnlyNoPassive(IResult<GetUserDataFromAuthResponseResultDto> result)
        {
            AssertRejectedWith(result, SamlLoadValidationMessages.InvalidSamlResponseNoPassive);
            AssertOnlyFixedMessages(result);
            Assert.All(MessageTexts(result), t => Assert.Equal(SamlLoadValidationMessages.InvalidSamlResponseNoPassive, t));
            Assert.Null(result.Response?.UserInfo);

            foreach (var text in MessageTexts(result))
            {
                Assert.DoesNotContain("idp-status-marker", text, StringComparison.Ordinal);
                Assert.DoesNotContain("<b>", text, StringComparison.Ordinal);
                Assert.DoesNotContain(SamlFixtures.DefaultNameId, text, StringComparison.Ordinal);
                Assert.DoesNotContain("TestFirstName", text, StringComparison.Ordinal);
                Assert.DoesNotContain(SamlFixtures.DefaultAuthIp, text, StringComparison.Ordinal);
            }
        }
    }
}
