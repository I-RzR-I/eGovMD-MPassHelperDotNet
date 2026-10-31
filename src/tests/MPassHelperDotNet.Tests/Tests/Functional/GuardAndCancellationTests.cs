using System;
using System.Collections.Generic;
using System.Threading;
using System.Threading.Tasks;
using MPassHelperDotNet.Extensions;
using MPassHelperDotNet.Helpers.Messages;
using MPassHelperDotNet.Models.Dto.AuthService.ExternalLogoutRequest;
using MPassHelperDotNet.Models.Dto.AuthService.LoginRequest;
using MPassHelperDotNet.Models.Dto.AuthService.LoginResponse;
using MPassHelperDotNet.Models.Dto.AuthService.LogoutRequest;
using MPassHelperDotNet.Models.Dto.AuthService.LogoutResponse;
using MPassHelperDotNet.Models.Dto.RequestBuilder.LoginRequest;
using MPassHelperDotNet.Models.Dto.RequestBuilder.LogoutRequest;
using MPassHelperDotNet.Models.Dto.RequestBuilder.LogOutResponse;
using MPassHelperDotNet.Tests.Helpers.Hosting;
using MPassHelperDotNet.Tests.Helpers.Kits;
using MPassHelperDotNet.Tests.Helpers.Runtime;
using MPassHelperDotNet.Tests.Helpers.Saml;
using RzR.ResultMessage.Abstractions;
using Xunit;

namespace MPassHelperDotNet.Tests.Tests.Functional
{
    [Trait(TestAreas.Trait, TestAreas.Functional)]
    public class GuardAndCancellationTests
    {
        private const string SessionIndex = "_session-guard-01";

        [Theory]
        [InlineData("GenerateAuthRequestAsync")]
        [InlineData("GetUserDataFromAuthResponseAsync")]
        [InlineData("GenerateLogoutRequestAsync")]
        [InlineData("ValidateLogoutResponseAsync")]
        [InlineData("ProcessExternalLogoutRequestAsync")]
        [InlineData("PingAsync")]
        [InlineData("BuildLogInRequestAsync")]
        [InlineData("BuildLogOutRequestAsync")]
        [InlineData("BuildLogOutResponseAsync")]
        public async Task AllMethods_PreCancelledToken_Throws_Test(string method)
        {
            using var context = ServiceFactory.Create();
            using var cts = new CancellationTokenSource();
            cts.Cancel();
            var requestId = FunctionalTestKit.NewRequestId();
            var loginResponse = context.SignedBase64(context.NewLoginResponse(requestId));
            var logoutResponse = context.SignedBase64(context.NewLogoutResponse(requestId));
            var logoutRequest = context.SignedBase64(context.NewLogoutRequest(SamlFixtures.DefaultNameId, SessionIndex));
            var calls = new Dictionary<string, Func<Task>>
            {
                ["GenerateAuthRequestAsync"] = () => context.Auth.GenerateAuthRequestAsync(new GenerateAuthRequestDto { RelayState = "rs" }, cts.Token),
                ["GetUserDataFromAuthResponseAsync"] = () => context.Auth.GetUserDataFromAuthResponseAsync(
                    new GetUserDataFromAuthResponseDto { SamlResponse = loginResponse, AuthRequestId = requestId }, cts.Token),
                ["GenerateLogoutRequestAsync"] = () => context.Auth.GenerateLogoutRequestAsync(new GenerateLogOutRequestDto
                    { RelayState = "rs", SessionIndexId = SessionIndex, UserIdentifierId = SamlFixtures.DefaultNameId }, cts.Token),
                ["ValidateLogoutResponseAsync"] = () => context.Auth.ValidateLogoutResponseAsync(
                    new ValidateLogoutResponseDto { SamlResponse = logoutResponse, LogOutRequestId = requestId }, cts.Token),
                ["ProcessExternalLogoutRequestAsync"] = () => context.Auth.ProcessExternalLogoutRequestAsync(new ProcessExternalLogoutRequestDto
                    { SamlRequest = logoutRequest, SessionIndexId = SessionIndex, UserIdentifierId = SamlFixtures.DefaultNameId }, cts.Token),
                ["PingAsync"] = () => context.Auth.PingAsync(cts.Token),
                ["BuildLogInRequestAsync"] = () => context.Builder.BuildLogInRequestAsync(new BuildLogInRequestDto { RelayState = "rs" }, cts.Token),
                ["BuildLogOutRequestAsync"] = () => context.Builder.BuildLogOutRequestAsync(new BuildLogOutRequestDto
                    { RelayState = "rs", UserIdentifierId = SamlFixtures.DefaultNameId, UserSessionId = SessionIndex }, cts.Token),
                ["BuildLogOutResponseAsync"] = () => context.Builder.BuildLogOutResponseAsync(new BuildLogOutResponseDto
                    { SamlRequest = logoutRequest, UserIdentifierId = SamlFixtures.DefaultNameId, UserSessionIndexId = SessionIndex }, cts.Token)
            };

            await Assert.ThrowsAnyAsync<OperationCanceledException>(calls[method]);
        }

        [Fact]
        public async Task GetUserData_PreCancelled_NoConsume_Test()
        {
            using var context = ServiceFactory.Create();
            var requestId = FunctionalTestKit.NewRequestId();
            var dto = new GetUserDataFromAuthResponseDto { SamlResponse = context.SignedBase64(context.NewLoginResponse(requestId)), AuthRequestId = requestId };
            using var cts = new CancellationTokenSource();
            cts.Cancel();

            await Assert.ThrowsAnyAsync<OperationCanceledException>(() => context.Auth.GetUserDataFromAuthResponseAsync(dto, cts.Token));
            var retry = await context.Auth.GetUserDataFromAuthResponseAsync(dto, TestContext.Current.CancellationToken);

            FunctionalTestKit.AssertSuccess(retry);
        }

        [Fact]
        public async Task AllMethods_NullDto_FailsArgumentNull_Test()
        {
            using var context = ServiceFactory.Create();
            var ct = TestContext.Current.CancellationToken;
            var expected = string.Format(DefaultMessages.ArgumentNullMessage, "request");

            var results = new IResult[]
            {
                await context.Auth.GenerateAuthRequestAsync(null, ct),
                await context.Auth.GetUserDataFromAuthResponseAsync(null, ct),
                await context.Auth.GenerateLogoutRequestAsync(null, ct),
                await context.Auth.ValidateLogoutResponseAsync(null, ct),
                await context.Auth.ProcessExternalLogoutRequestAsync(null, ct),
                await context.Builder.BuildLogInRequestAsync(null, ct),
                await context.Builder.BuildLogOutRequestAsync(null, ct),
                await context.Builder.BuildLogOutResponseAsync(null, ct)
            };

            foreach (var result in results)
                FunctionalTestKit.AssertFailureWith(result, expected);
        }

        [Theory]
        [InlineData(null)]
        [InlineData("")]
        public async Task Inbound_BlankSamlMessage_Fails_Test(string saml)
        {
            using var context = ServiceFactory.Create();
            var ct = TestContext.Current.CancellationToken;
            var requestId = FunctionalTestKit.NewRequestId();

            var login = await context.Auth.GetUserDataFromAuthResponseAsync(new GetUserDataFromAuthResponseDto { SamlResponse = saml, AuthRequestId = requestId }, ct);
            var logout = await context.Auth.ValidateLogoutResponseAsync(new ValidateLogoutResponseDto { SamlResponse = saml, LogOutRequestId = requestId }, ct);
            var slo = await context.Auth.ProcessExternalLogoutRequestAsync(new ProcessExternalLogoutRequestDto
                { SamlRequest = saml, SessionIndexId = SessionIndex, UserIdentifierId = SamlFixtures.DefaultNameId }, ct);
            var build = await context.Builder.BuildLogOutResponseAsync(new BuildLogOutResponseDto
                { SamlRequest = saml, UserIdentifierId = SamlFixtures.DefaultNameId, UserSessionIndexId = SessionIndex }, ct);

            FunctionalTestKit.AssertFailure(login);
            Assert.Null(login.Response);
            FunctionalTestKit.AssertFailure(logout);
            FunctionalTestKit.AssertFailure(slo);
            FunctionalTestKit.AssertFailure(build);
        }

        [Theory]
        [InlineData(null)]
        [InlineData("")]
        [InlineData("   ")]
        public async Task Inbound_BlankRequestId_FailsIdRequired_Test(string requestId)
        {
            using var context = ServiceFactory.Create();
            var ct = TestContext.Current.CancellationToken;
            var anyId = FunctionalTestKit.NewRequestId();
            var loginResponse = context.SignedBase64(context.NewLoginResponse(anyId));
            var logoutResponse = context.SignedBase64(context.NewLogoutResponse(anyId));

            var login = await context.Auth.GetUserDataFromAuthResponseAsync(
                new GetUserDataFromAuthResponseDto { SamlResponse = loginResponse, AuthRequestId = requestId }, ct);
            var logout = await context.Auth.ValidateLogoutResponseAsync(
                new ValidateLogoutResponseDto { SamlResponse = logoutResponse, LogOutRequestId = requestId }, ct);

            FunctionalTestKit.AssertFailureWith(login, DefaultMessages.ExpectedRequestIdRequired);
            FunctionalTestKit.AssertFailureWith(logout, DefaultMessages.ExpectedRequestIdRequired);
        }

        [Theory]
        [InlineData(null, SamlFixtures.DefaultNameId)]
        [InlineData("", SamlFixtures.DefaultNameId)]
        [InlineData(SessionIndex, null)]
        [InlineData(SessionIndex, "")]
        public async Task ExternalLogout_BlankExpectations_Fails_Test(string sessionIndex, string userIdentifier)
        {
            using var context = ServiceFactory.Create();
            var samlRequest = context.SignedBase64(context.NewLogoutRequest(SamlFixtures.DefaultNameId, SessionIndex));

            var result = await context.Auth.ProcessExternalLogoutRequestAsync(new ProcessExternalLogoutRequestDto
            {
                SamlRequest = samlRequest,
                SessionIndexId = sessionIndex,
                UserIdentifierId = userIdentifier
            }, TestContext.Current.CancellationToken);

            FunctionalTestKit.AssertFailure(result);
            Assert.Null(result.Response);
        }

        [Theory]
        [InlineData(null, SamlFixtures.DefaultNameId)]
        [InlineData(SessionIndex, null)]
        public async Task BuildLogoutResponse_MissingExpectations_Fails_Test(string sessionIndex, string userIdentifier)
        {
            using var context = ServiceFactory.Create();
            var samlRequest = context.SignedBase64(context.NewLogoutRequest(SamlFixtures.DefaultNameId, SessionIndex));

            var result = await context.Builder.BuildLogOutResponseAsync(new BuildLogOutResponseDto
            {
                SamlRequest = samlRequest,
                UserIdentifierId = userIdentifier,
                UserSessionIndexId = sessionIndex
            }, TestContext.Current.CancellationToken);

            FunctionalTestKit.AssertFailureWith(result, SamlLoadValidationMessages.SamlLogOutExpectationRequired);
        }

        [Theory]
        [InlineData(null, "_s", "2000000000001")]
        [InlineData("rs", null, "2000000000001")]
        [InlineData("rs", "_s", null)]
        public async Task GenerateLogout_MissingField_Fails_Test(string relayState, string sessionIndex, string userIdentifier)
        {
            using var context = ServiceFactory.Create();

            var result = await context.Auth.GenerateLogoutRequestAsync(new GenerateLogOutRequestDto
            {
                RelayState = relayState,
                SessionIndexId = sessionIndex,
                UserIdentifierId = userIdentifier
            }, TestContext.Current.CancellationToken);

            FunctionalTestKit.AssertFailure(result);
        }

        [Fact]
        public async Task GenerateAuth_EmptyRelayState_FailsRequired_Test()
        {
            using var context = ServiceFactory.Create();

            var result = await context.Auth.GenerateAuthRequestAsync(new GenerateAuthRequestDto { RelayState = "" }, TestContext.Current.CancellationToken);

            FunctionalTestKit.AssertFailureWith(result, string.Format(DefaultMessages.ArgumentNullMessage, "RelayState"));
        }

        [Fact]
        public async Task GenerateAuth_RelayStateOver80Bytes_Fails_Test()
        {
            using var context = ServiceFactory.Create();
            var relayState = new string('ă', 41);

            var result = await context.Auth.GenerateAuthRequestAsync(new GenerateAuthRequestDto { RelayState = relayState }, TestContext.Current.CancellationToken);

            FunctionalTestKit.AssertFailureWith(result, RequestBuilderMessages.RelayStateTooLong);
        }

        [Fact]
        public async Task Inbound_InvalidBase64_FailsWithoutThrow_Test()
        {
            using var context = ServiceFactory.Create();
            var requestId = FunctionalTestKit.NewRequestId();

            var login = await context.Auth.GetUserDataFromAuthResponseAsync(
                new GetUserDataFromAuthResponseDto { SamlResponse = "%%%not-base64%%%", AuthRequestId = requestId }, TestContext.Current.CancellationToken);
            var logout = await context.Auth.ValidateLogoutResponseAsync(
                new ValidateLogoutResponseDto { SamlResponse = "%%%not-base64%%%", LogOutRequestId = requestId }, TestContext.Current.CancellationToken);

            FunctionalTestKit.AssertFailure(login);
            FunctionalTestKit.AssertFailure(logout);
        }

        [Fact]
        public void GenerateRequestId_10000Ids_UniqueLowerHex32_Test()
        {
            var ids = new HashSet<string>(StringComparer.Ordinal);
            for (var i = 0; i < 10000; i++)
                Assert.True(ids.Add(StringExtensions.GenerateRequestId()), "Duplicate request id generated.");

            Assert.All(ids, id =>
            {
                Assert.Matches(FunctionalTestKit.RequestIdPattern, id);
                System.Xml.XmlConvert.VerifyNCName(id);
            });
        }
    }
}
