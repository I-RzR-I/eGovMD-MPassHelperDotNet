using System;
using System.Linq;
using System.Threading.Tasks;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Logging;
using MPassHelperDotNet.Services;
using MPassHelperDotNet.Models.Dto.AuthService.LoginRequest;
using MPassHelperDotNet.Models.Dto.AuthService.LogoutRequest;
using MPassHelperDotNet.Tests.Helpers.Fakes;
using MPassHelperDotNet.Tests.Helpers.Hosting;
using MPassHelperDotNet.Tests.Helpers.Runtime;
using MPassHelperDotNet.Tests.Helpers.Saml;
using MPassHelperDotNet.Tests.Models.Hosting;
using RzR.ResultMessage.Abstractions;
using Xunit;
using static MPassHelperDotNet.Tests.Helpers.Kits.SecurityTestKit;
using MPassHelperDotNet.Helpers.Messages;

namespace MPassHelperDotNet.Tests.Tests.Security
{
    [Trait(TestAreas.Trait, TestAreas.Security)]
    public class ErrorAndLoggingSecurityTests
    {
        private const string Marker = "ZqMarker7731";

        public static TheoryData<string> MalformedInputs => new TheoryData<string>
        {
            "%%%",
            FixtureEncoding.ToBase64("<saml2p:Response xmlns:saml2p=\"urn:oasis:names:tc:SAML:2.0:protocol\"><" + Marker),
            FixtureEncoding.ToBase64("<!DOCTYPE x [<!ENTITY " + Marker + " \"v\">]><x>&" + Marker + ";</x>"),
            FixtureEncoding.ToBase64("<" + Marker + " a=\"1\" a=\"2\"/>"),
            FixtureEncoding.ToBase64(new byte[] { 0x3C, 0x61, 0xC3, 0x28, 0x3E })
        };

        [Theory]
        [MemberData(nameof(MalformedInputs))]
        public async Task Inbound_InvalidInput_RejectedFixedMessages_Test(string payload)
        {
            using var context = ServiceFactory.Create();
            var requestId = NewRequestId();

            var results = new IResult[]
            {
                await SubmitLoginAsync(context, payload, requestId),
                await SubmitLogoutResponseAsync(context, payload, requestId),
                await SubmitLogoutRequestAsync(context, payload)
            };

            foreach (var result in results)
            {
                AssertRejected(result);
                AssertOnlyFixedMessages(result);
                Assert.DoesNotContain(MessageTexts(result), t => t.Contains(Marker, StringComparison.Ordinal));
            }

            Assert.False(context.Logs.Contains(Marker), "input echoed into the logs");
        }

        [Fact]
        public async Task Inbound_SignatureOrProtocol_FixedMessages_Test()
        {
            using var context = ServiceFactory.Create();
            var requestId = NewRequestId();
            var wrongDestinationResponse = context.NewLoginResponse(requestId);
            wrongDestinationResponse.Destination = "https://other.example/" + Marker;

            var results = new IResult[]
            {
                await SubmitLoginAsync(context, context.SignedBase64(wrongDestinationResponse), requestId),
                await SubmitLoginAsync(context, FixtureEncoding.ToBase64(ApplyVariant(SamlFixtureBuilder.Build(context.NewLoginResponse(requestId)),
                    "wrong-key-with-keyinfo")), requestId),
                await SubmitLoginAsync(context, FixtureEncoding.ToBase64(ApplyVariant(SamlFixtureBuilder.Build(context.NewLoginResponse(requestId)),
                    "duplicate-ID-in-ds-Object")), requestId),
                await SubmitLogoutResponseAsync(context, context.SignedBase64(context.NewLogoutResponse(NewRequestId())), requestId),
                await SubmitLogoutRequestAsync(context, context.SignedBase64(context.NewLogoutRequest()), "2999999999999")
            };

            foreach (var result in results)
            {
                AssertRejected(result);
                AssertOnlyFixedMessages(result);
                Assert.DoesNotContain(MessageTexts(result), t => t.Contains(Marker, StringComparison.Ordinal));
            }
        }

        [Fact]
        public async Task Facade_NullOrEmptyDto_FailsFixedMessages_Test()
        {
            using var context = ServiceFactory.Create();

            var results = new IResult[]
            {
                await context.Auth.GenerateAuthRequestAsync(null, Ct),
                await context.Auth.GenerateAuthRequestAsync(new GenerateAuthRequestDto(), Ct),
                await context.Auth.GetUserDataFromAuthResponseAsync(null, Ct),
                await SubmitLoginAsync(context, null, NewRequestId()),
                await context.Auth.GenerateLogoutRequestAsync(null, Ct),
                await context.Auth.GenerateLogoutRequestAsync(new GenerateLogOutRequestDto { RelayState = "rs" }, Ct),
                await context.Auth.ValidateLogoutResponseAsync(null, Ct),
                await SubmitLogoutResponseAsync(context, string.Empty, NewRequestId()),
                await context.Auth.ProcessExternalLogoutRequestAsync(null, Ct),
                await SubmitLogoutRequestAsync(context, "x", null, null)
            };

            foreach (var result in results)
            {
                AssertRejected(result);
                AssertOnlyFixedMessages(result);
            }
        }

        [Fact]
        public async Task GetUserData_ForcedError_FixedMessageOneLog_Test()
        {
            var logger = new ThrowOnceLogger<AuthMPassService>();
            using var context = ServiceFactory.Create(configureAfter: services => services.AddSingleton<ILogger<AuthMPassService>>(logger));

            var result = await SubmitLoginAsync(context, "%%%" + Marker, NewRequestId());

            Assert.True(logger.Thrown, "the forced exception was not raised");
            AssertRejected(result);
            AssertOnlyFixedMessages(result);
            Assert.Contains(DefaultMessages.ErrorOnLoadAndVerifySamlResponse, MessageTexts(result));
            var entry = Assert.Single(logger.Entries, e => e.Message.Contains("LoadAndVerifyAnyResponse", StringComparison.Ordinal));
            Assert.IsType<InvalidOperationException>(entry.Exception);
            Assert.Single(logger.Entries);
            Assert.DoesNotContain(logger.Entries, e => e.Message.Contains(Marker, StringComparison.Ordinal));
        }

        [Fact]
        public async Task GetUserData_OutOfRangeDate_DateInvalid_Test()
        {
            using var context = ServiceFactory.Create();
            var requestId = NewRequestId();
            var fixture = context.NewLoginResponse(requestId);
            fixture.IssueInstantRaw = "0001-01-01T00:00:00+14:00";
            context.Logs.Clear();

            var result = await SubmitLoginAsync(context, context.SignedBase64(fixture), requestId);

            AssertRejectedWith(result, SamlLoadValidationMessages.SamlDateInvalid);
            AssertOnlyFixedMessages(result);
            Assert.DoesNotContain(DefaultMessages.ErrorOnLoadAndVerifySamlResponse, MessageTexts(result));
            Assert.False(context.Logs.Contains("0001-01-01"), "the input value was logged");
        }

        [Fact]
        public async Task AllFlows_PiiSecretsSamlRelayState_NotLogged_Test()
        {
            using var context = ServiceFactory.Create();
            var relayState = "rs-" + Marker;
            var loginRequestId = NewRequestId();
            var loginSaml = context.SignedBase64(context.NewLoginResponse(loginRequestId));
            var logoutRequestSaml = context.SignedBase64(context.NewLogoutRequest());

            var auth = await context.Auth.GenerateAuthRequestAsync(new GenerateAuthRequestDto { RelayState = relayState }, Ct);
            var login = await SubmitLoginAsync(context, loginSaml, loginRequestId);
            var replay = await SubmitLoginAsync(context, loginSaml, loginRequestId);
            var wrongUser = await SubmitLogoutRequestAsync(context, logoutRequestSaml, "2999999999999");
            var slo = await SubmitLogoutRequestAsync(context, logoutRequestSaml, relayState: relayState);
            var logout = await context.Auth.GenerateLogoutRequestAsync(new GenerateLogOutRequestDto
            {
                RelayState = relayState,
                SessionIndexId = "_session-1",
                UserIdentifierId = SamlFixtures.DefaultNameId
            }, Ct);

            AssertAccepted(auth);
            AssertAccepted(login);
            AssertRejected(replay);
            AssertRejected(wrongUser);
            AssertAccepted(slo);
            AssertAccepted(logout);

            var logs = context.Logs.AllText;
            Assert.DoesNotContain(SamlFixtures.DefaultNameId, logs, StringComparison.Ordinal);
            Assert.DoesNotContain("2999999999999", logs, StringComparison.Ordinal);
            foreach (var attributeValue in new[] { "TestLastName", "test.user@example.test", "+37360000000", "1990-05-17" })
                Assert.DoesNotContain(attributeValue, logs, StringComparison.Ordinal);
            Assert.DoesNotContain(Marker, logs, StringComparison.Ordinal);
            Assert.DoesNotContain(MPassTestSettings.DefaultPfxPassword, logs, StringComparison.Ordinal);
            Assert.DoesNotContain("<saml", logs, StringComparison.Ordinal);
            Assert.DoesNotContain(loginSaml.Substring(0, 40), logs, StringComparison.Ordinal);
            Assert.DoesNotContain(logoutRequestSaml.Substring(0, 40), logs, StringComparison.Ordinal);
        }

        [Fact]
        public async Task GetUserData_InvalidXml_LoggedTypeNotInput_Test()
        {
            using var context = ServiceFactory.Create();
            var payload = FixtureEncoding.ToBase64(
                "<saml2p:Response xmlns:saml2p=\"urn:oasis:names:tc:SAML:2.0:protocol\" ID=\"_x\"><" + Marker + "><unterminated>");
            context.Logs.Clear();

            var result = await SubmitLoginAsync(context, payload, NewRequestId());

            AssertRejectedWith(result, SamlLoadValidationMessages.SamlXmlInvalid);
            Assert.True(context.Logs.Contains("XmlException"), context.Logs.AllText);
            Assert.True(context.Logs.Contains("LoadFromBase64"), context.Logs.AllText);
            Assert.False(context.Logs.Contains(Marker), context.Logs.AllText);
            Assert.All(context.Logs.Entries, e => Assert.Null(e.Exception));
        }
    }
}
