using System;
using System.Threading.Tasks;
using Microsoft.Extensions.Logging.Abstractions;
using Microsoft.Extensions.Options;
using MPassHelperDotNet.Abstractions.Services.Replay;
using MPassHelperDotNet.Helpers.Messages;
using MPassHelperDotNet.Models.Client;
using MPassHelperDotNet.Models.Dto.AuthService.ExternalLogoutRequest;
using MPassHelperDotNet.Models.Dto.AuthService.LogoutRequest;
using MPassHelperDotNet.Models.Dto.AuthService.LogoutResponse;
using MPassHelperDotNet.Models.Dto.RequestBuilder.LoginRequest;
using MPassHelperDotNet.Models.Dto.RequestBuilder.LogoutRequest;
using MPassHelperDotNet.Models.Dto.RequestBuilder.LogOutResponse;
using MPassHelperDotNet.Services;
using MPassHelperDotNet.Services.Replay;
using MPassHelperDotNet.Tests.Helpers.Certificates;
using MPassHelperDotNet.Tests.Helpers.Hosting;
using MPassHelperDotNet.Tests.Helpers.Kits;
using MPassHelperDotNet.Tests.Helpers.Runtime;
using MPassHelperDotNet.Tests.Helpers.Saml;
using Xunit;

namespace MPassHelperDotNet.Tests.Tests.Functional
{
    [Trait(TestAreas.Trait, TestAreas.Functional)]
    public class LogoutFlowTests
    {
        private const string SessionIndex = "_session-functional-01";

        [Theory]
        [MemberData(nameof(Cultures))]
        public async Task GenerateLogout_ThenValidateLogout_Succeeds_Test(string culture)
        {
            using var scope = new CultureScope(culture);
            using var context = ServiceFactory.Create();
            var ct = TestContext.Current.CancellationToken;

            var generated = await context.Auth.GenerateLogoutRequestAsync(new GenerateLogOutRequestDto
            {
                RelayState = "rs-logout",
                SessionIndexId = SessionIndex,
                UserIdentifierId = SamlFixtures.DefaultNameId
            }, ct);

            FunctionalTestKit.AssertSuccess(generated);
            
            var logoutRequestId = generated.Response.LogOutRequestId;
            Assert.Matches(FunctionalTestKit.RequestIdPattern, logoutRequestId);
            
            var html = generated.Response.HtmlDocument;
            Assert.Equal(1, HtmlFormReader.CountForms(html));
            Assert.Equal(context.Settings.SamlLogoutDestination, HtmlFormReader.GetFormAction(html));
            Assert.Equal("rs-logout", HtmlFormReader.GetInputValue(html, "RelayState"));
            
            var logoutRequest = FunctionalTestKit.DecodeOnceToXml(HtmlFormReader.GetInputValue(html, "SAMLRequest"));
            var root = logoutRequest.DocumentElement;
            var ns = SamlNs.CreateNamespaceManager(logoutRequest);
            Assert.Equal("LogoutRequest", root.LocalName);
            Assert.Equal(logoutRequestId, root.GetAttribute("ID"));
            Assert.Equal(context.Settings.SamlLogoutDestination, root.GetAttribute("Destination"));
            Assert.Equal(context.Settings.SamlRequestIssuer, root.SelectSingleNode("saml2:Issuer", ns)?.InnerText);
            Assert.Equal(SamlFixtures.DefaultNameId, root.SelectSingleNode("saml2:NameID", ns)?.InnerText);
            Assert.Equal(SessionIndex, root.SelectSingleNode("saml2p:SessionIndex", ns)?.InnerText);
            Assert.NotNull(root.SelectSingleNode("ds:Signature", ns));

            var response = context.SignedBase64(context.NewLogoutResponse(logoutRequestId));
            var validation = await context.Auth.ValidateLogoutResponseAsync(
                new ValidateLogoutResponseDto { SamlResponse = response, LogOutRequestId = logoutRequestId }, ct);

            FunctionalTestKit.AssertSuccess(validation);
        }

        [Fact]
        public async Task ValidateLogout_PrettyPrinted_Succeeds_Test()
        {
            using var context = ServiceFactory.Create();
            var requestId = FunctionalTestKit.NewRequestId();
            var response = context.SignedBase64(context.NewLogoutResponse(requestId), indent: true);

            var validation = await context.Auth.ValidateLogoutResponseAsync(
                new ValidateLogoutResponseDto { SamlResponse = response, LogOutRequestId = requestId },
                TestContext.Current.CancellationToken);

            FunctionalTestKit.AssertSuccess(validation);
        }

        [Fact]
        public async Task ValidateLogout_WrongRequestId_Fails_Test()
        {
            using var context = ServiceFactory.Create();
            var response = context.SignedBase64(context.NewLogoutResponse(FunctionalTestKit.NewRequestId()));

            var validation = await context.Auth.ValidateLogoutResponseAsync(
                new ValidateLogoutResponseDto { SamlResponse = response, LogOutRequestId = FunctionalTestKit.NewRequestId() },
                TestContext.Current.CancellationToken);

            FunctionalTestKit.AssertFailure(validation);
        }

        [Theory]
        [MemberData(nameof(Cultures))]
        public async Task ExternalLogout_Request_ReturnsSignedForm_Test(string culture)
        {
            using var scope = new CultureScope(culture);
            using var context = ServiceFactory.Create();
            var fixture = context.NewLogoutRequest(SamlFixtures.DefaultNameId, SessionIndex);
            var samlRequest = context.SignedBase64(fixture);

            var result = await context.Auth.ProcessExternalLogoutRequestAsync(new ProcessExternalLogoutRequestDto
            {
                SamlRequest = samlRequest,
                RelayState = "rs-slo",
                SessionIndexId = SessionIndex,
                UserIdentifierId = SamlFixtures.DefaultNameId
            }, TestContext.Current.CancellationToken);

            FunctionalTestKit.AssertSuccess(result);
            
            var html = result.Response.HtmlDocument;
            Assert.Equal(1, HtmlFormReader.CountForms(html));
            Assert.Equal(context.Settings.SamlLogoutDestination, HtmlFormReader.GetFormAction(html));
            Assert.Equal("rs-slo", HtmlFormReader.GetInputValue(html, "RelayState"));
            
            var logoutResponse = FunctionalTestKit.DecodeOnceToXml(HtmlFormReader.GetInputValue(html, "SAMLResponse"));
            var root = logoutResponse.DocumentElement;
            var ns = SamlNs.CreateNamespaceManager(logoutResponse);
            Assert.Equal("LogoutResponse", root.LocalName);
            Assert.Equal(result.Response.LogoutResponseId, root.GetAttribute("ID"));
            Assert.Matches(FunctionalTestKit.RequestIdPattern, result.Response.LogoutResponseId);
            Assert.Equal(fixture.Id, root.GetAttribute("InResponseTo"));
            Assert.Equal(context.Settings.SamlLogoutDestination, root.GetAttribute("Destination"));
            Assert.Equal(context.Settings.SamlRequestIssuer, root.SelectSingleNode("saml2:Issuer", ns)?.InnerText);
            Assert.Equal(SamlNs.StatusSuccess, root.SelectSingleNode("saml2p:Status/saml2p:StatusCode/@Value", ns)?.Value);
            Assert.NotNull(root.SelectSingleNode("ds:Signature", ns));
        }

        [Fact]
        public async Task ExternalLogout_NullRelayState_Succeeds_Test()
        {
            using var context = ServiceFactory.Create();
            var samlRequest = context.SignedBase64(context.NewLogoutRequest(SamlFixtures.DefaultNameId, SessionIndex));

            var result = await context.Auth.ProcessExternalLogoutRequestAsync(new ProcessExternalLogoutRequestDto
            {
                SamlRequest = samlRequest,
                RelayState = null,
                SessionIndexId = SessionIndex,
                UserIdentifierId = SamlFixtures.DefaultNameId
            }, TestContext.Current.CancellationToken);

            FunctionalTestKit.AssertSuccess(result);
            Assert.Equal(string.Empty, HtmlFormReader.GetInputValue(result.Response.HtmlDocument, "RelayState"));
        }

        [Fact]
        public async Task ExternalLogout_IndexListWithMatch_Succeeds_Test()
        {
            using var context = ServiceFactory.Create();
            var fixture = context.NewLogoutRequest(SamlFixtures.DefaultNameId, "_other-session");
            fixture.SessionIndexes.Add(SessionIndex);

            var result = await context.Auth.ProcessExternalLogoutRequestAsync(new ProcessExternalLogoutRequestDto
            {
                SamlRequest = context.SignedBase64(fixture),
                SessionIndexId = SessionIndex,
                UserIdentifierId = SamlFixtures.DefaultNameId
            }, TestContext.Current.CancellationToken);

            FunctionalTestKit.AssertSuccess(result);
        }

        [Fact]
        public async Task ExternalLogout_WrongUser_Fails_Test()
        {
            using var context = ServiceFactory.Create();
            var samlRequest = context.SignedBase64(context.NewLogoutRequest("2000000000999", SessionIndex));

            var result = await context.Auth.ProcessExternalLogoutRequestAsync(new ProcessExternalLogoutRequestDto
            {
                SamlRequest = samlRequest,
                SessionIndexId = SessionIndex,
                UserIdentifierId = SamlFixtures.DefaultNameId
            }, TestContext.Current.CancellationToken);

            FunctionalTestKit.AssertFailure(result);
        }

        [Fact]
        public async Task BuildLogin_CertNoPrivateKey_Fails_Test()
        {
            var time = TestClock.CreateFake();
            var builder = NewBuilder(PublicOnlyServiceOptions(), new InMemorySamlReplayCache(time), time);

            var result = await builder.BuildLogInRequestAsync(new BuildLogInRequestDto { RelayState = "rs" },
                TestContext.Current.CancellationToken);

            FunctionalTestKit.AssertFailure(result);
            Assert.Null(result.Response);
        }

        [Fact]
        public async Task BuildLogoutRequest_CertNoPrivateKey_Fails_Test()
        {
            var time = TestClock.CreateFake();
            var builder = NewBuilder(PublicOnlyServiceOptions(), new InMemorySamlReplayCache(time), time);

            var result = await builder.BuildLogOutRequestAsync(new BuildLogOutRequestDto
            {
                RelayState = "rs",
                UserIdentifierId = SamlFixtures.DefaultNameId,
                UserSessionId = SessionIndex
            }, TestContext.Current.CancellationToken);

            FunctionalTestKit.AssertFailureWith(result, RequestBuilderMessages.ErrorSignRequest);
            Assert.Null(result.Response);
        }

        [Fact]
        public async Task BuildLogoutResponse_SignFails_NoConsume_Test()
        {
            using var context = ServiceFactory.Create();
            var time = context.Time;
            var sharedCache = new InMemorySamlReplayCache(time);
            var samlRequest = context.SignedBase64(context.NewLogoutRequest(SamlFixtures.DefaultNameId, SessionIndex));
            var dto = new BuildLogOutResponseDto
            {
                SamlRequest = samlRequest,
                RelayState = "rs",
                UserIdentifierId = SamlFixtures.DefaultNameId,
                UserSessionIndexId = SessionIndex
            };
            var failingBuilder = NewBuilder(CopyWithPublicOnlyServiceCertificate(context.Options), sharedCache, time);
            var workingBuilder = NewBuilder(context.Options, sharedCache, time);

            var failed = await failingBuilder.BuildLogOutResponseAsync(dto, TestContext.Current.CancellationToken);
            var retried = await workingBuilder.BuildLogOutResponseAsync(dto, TestContext.Current.CancellationToken);

            FunctionalTestKit.AssertFailureWith(failed, RequestBuilderMessages.ErrorSignRequest);
            FunctionalTestKit.AssertSuccess(retried);
        }

        public static TheoryData<string> Cultures => TestCultures.All;

        private static MPassBuilderService NewBuilder(MPassSamlOptions options, ISamlReplayCache cache, TimeProvider time)
            => new MPassBuilderService(Options.Create(options), cache, time, NullLogger<MPassBuilderService>.Instance);

        private static MPassSamlOptions PublicOnlyServiceOptions()
        {
            using var context = ServiceFactory.Create();

            return CopyWithPublicOnlyServiceCertificate(context.Options);
        }

        private static MPassSamlOptions CopyWithPublicOnlyServiceCertificate(MPassSamlOptions source)
            => new MPassSamlOptions
            {
                SamlRequestIssuer = source.SamlRequestIssuer,
                IdentityProviderIssuer = source.IdentityProviderIssuer,
                SamlLoginDestination = source.SamlLoginDestination,
                SamlLogoutDestination = source.SamlLogoutDestination,
                SamlServiceLoginDestination = source.SamlServiceLoginDestination,
                SamlServiceLogoutDestination = source.SamlServiceLogoutDestination,
                SamlServiceSingleLogoutDestination = source.SamlServiceSingleLogoutDestination,
                SamlMessageTimeout = source.SamlMessageTimeout,
                SamlClockSkew = source.SamlClockSkew,
                SamlMessageMaxLength = source.SamlMessageMaxLength,
                IdentityProviderCertificate = TestCertificates.PublicOnly(TestCertificates.Idp),
                IdentityProviderCertificates = TestCertificates.Collection(TestCertificates.Idp),
                ServiceCertificate = TestCertificates.PublicOnly(TestCertificates.Sp)
            };
    }
}
