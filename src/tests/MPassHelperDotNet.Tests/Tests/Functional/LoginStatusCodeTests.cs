using System;
using System.Threading.Tasks;
using MPassHelperDotNet.Helpers;
using MPassHelperDotNet.Helpers.Messages;
using MPassHelperDotNet.Models.Dto.AuthService.LoginResponse;
using MPassHelperDotNet.Tests.Helpers.Hosting;
using MPassHelperDotNet.Tests.Helpers.Kits;
using MPassHelperDotNet.Tests.Helpers.Runtime;
using MPassHelperDotNet.Tests.Helpers.Saml;
using RzR.ResultMessage.Abstractions;
using Xunit;

namespace MPassHelperDotNet.Tests.Tests.Functional
{
    [Trait(TestAreas.Trait, TestAreas.Functional)]
    public class LoginStatusCodeTests
    {
        private const string NoPassive = "urn:oasis:names:tc:SAML:2.0:status:NoPassive";

        [Theory]
        [InlineData(SamlNs.StatusResponder)]
        [InlineData(SamlNs.StatusRequester)]
        public async Task GetUserData_NoPassiveStatus_FailsWithoutUser_Test(string topLevelStatus)
        {
            using var context = ServiceFactory.Create();

            var result = await LoginWithStatus(context, topLevelStatus, NoPassive);

            FunctionalTestKit.AssertFailureWith(result, SamlLoadValidationMessages.InvalidSamlResponseNoPassive);
            Assert.Contains(SamlLoadValidationMessages.InvalidSamlResponseNoPassive, FunctionalTestKit.Texts(result));
            Assert.Null(result.Response);
        }

        [Fact]
        public void NoPassiveResponse_Constants_FixedMessage_Test()
        {
            Assert.Equal("Passive authentication is not possible, the user is not signed in at MPass!", SamlLoadValidationMessages.InvalidSamlResponseNoPassive);
            Assert.Equal(NoPassive, DefaultStaticInfo.SamlUrnStatusNoPassive);
        }

        [Fact]
        public async Task GetUserData_NoPassiveMessage_FixedMessageOnly_Test()
        {
            using var context = ServiceFactory.Create();
            const string marker = "StatusMarker4c2d";

            var result = await LoginWithStatus(context, SamlNs.StatusResponder, NoPassive, marker);

            FunctionalTestKit.AssertFailureWith(result, SamlLoadValidationMessages.InvalidSamlResponseNoPassive);
            Assert.DoesNotContain(FunctionalTestKit.Texts(result), text => text.Contains(marker, StringComparison.Ordinal));
            Assert.Null(result.Response);
        }

        [Fact]
        public async Task GetUserData_AuthnFailed_MapsToAuthCanceled_Test()
        {
            using var context = ServiceFactory.Create();

            var result = await LoginWithStatus(context, SamlNs.StatusResponder, SamlNs.StatusAuthnFailed);

            FunctionalTestKit.AssertFailureWith(result, DefaultMessages.AuthCanceled);
            Assert.DoesNotContain(SamlLoadValidationMessages.InvalidSamlResponseNoPassive, FunctionalTestKit.Texts(result));
            Assert.Null(result.Response);
        }

        [Fact]
        public async Task GetUserData_UnknownPrincipal_FailsOwnMessage_Test()
        {
            using var context = ServiceFactory.Create();

            var result = await LoginWithStatus(context, SamlNs.StatusRequester, SamlNs.StatusUnknownPrincipal);

            FunctionalTestKit.AssertFailureWith(result, SamlLoadValidationMessages.InvalidSamlResponseUnknownPrincipal);
            Assert.DoesNotContain(SamlLoadValidationMessages.InvalidSamlResponseNoPassive, FunctionalTestKit.Texts(result));
            Assert.Null(result.Response);
        }

        [Theory]
        [InlineData("urn:oasis:names:tc:SAML:2.0:status:RequestDenied")]
        [InlineData("urn:oasis:names:tc:SAML:2.0:status:nopassive")]
        [InlineData("urn:oasis:names:tc:SAML:2.0:status:NoPassive ")]
        [InlineData("NoPassive")]
        [InlineData(null)]
        public async Task GetUserData_OtherSubStatus_FailsGenericText_Test(string subStatus)
        {
            using var context = ServiceFactory.Create();

            var result = await LoginWithStatus(context, SamlNs.StatusResponder, subStatus, "Temporary error");

            var expected = string.Format(SamlLoadValidationMessages.InvalidSamlResponseStatusCode, SamlNs.StatusResponder, "Temporary error");
            FunctionalTestKit.AssertFailureWith(result, expected);
            Assert.DoesNotContain(SamlLoadValidationMessages.InvalidSamlResponseNoPassive, FunctionalTestKit.Texts(result));
            Assert.Null(result.Response);
        }

        [Fact]
        public async Task GetUserData_SuccessNoPassive_Succeeds_Test()
        {
            using var context = ServiceFactory.Create();
            var requestId = FunctionalTestKit.NewRequestId();
            var fixture = context.NewLoginResponse(requestId);
            fixture.SubStatusCode = NoPassive;

            var result = await context.Auth.GetUserDataFromAuthResponseAsync(
                new GetUserDataFromAuthResponseDto { SamlResponse = context.SignedBase64(fixture), AuthRequestId = requestId },
                TestContext.Current.CancellationToken);

            FunctionalTestKit.AssertSuccess(result);
            Assert.Equal(requestId, result.Response.UserInfo.RequestId);
        }

        private static Task<IResult<GetUserDataFromAuthResponseResultDto>> LoginWithStatus(MPassTestContext context, string topLevelStatus,
            string subStatus, string statusMessage = null)
        {
            var requestId = FunctionalTestKit.NewRequestId();
            var fixture = context.NewLoginResponse(requestId);
            fixture.StatusCode = topLevelStatus;
            fixture.SubStatusCode = subStatus;
            fixture.StatusMessage = statusMessage;
            fixture.Assertions.Clear();

            return context.Auth.GetUserDataFromAuthResponseAsync(
                new GetUserDataFromAuthResponseDto { SamlResponse = context.SignedBase64(fixture), AuthRequestId = requestId },
                TestContext.Current.CancellationToken);
        }
    }
}
