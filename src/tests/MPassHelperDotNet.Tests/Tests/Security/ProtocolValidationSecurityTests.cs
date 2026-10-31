using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;
using MPassHelperDotNet.Helpers.Messages;
using MPassHelperDotNet.Models.Dto.RequestBuilder.LogOutResponse;
using MPassHelperDotNet.Tests.Helpers.Hosting;
using MPassHelperDotNet.Tests.Helpers.Runtime;
using MPassHelperDotNet.Tests.Helpers.Saml;
using MPassHelperDotNet.Tests.Models.Hosting;
using MPassHelperDotNet.Tests.Models.Saml;
using Xunit;
using static MPassHelperDotNet.Tests.Helpers.Kits.SecurityTestKit;

namespace MPassHelperDotNet.Tests.Tests.Security
{
    [Trait(TestAreas.Trait, TestAreas.Security)]
    public class ProtocolValidationSecurityTests
    {
        private static readonly TimeSpan Skew = TimeSpan.FromMinutes(2);
        private static readonly TimeSpan Timeout = TimeSpan.FromMinutes(10);
        private static readonly TimeSpan OneSecond = TimeSpan.FromSeconds(1);

        private static async Task<RzR.ResultMessage.Abstractions.IResult<MPassHelperDotNet.Models.Dto.AuthService.LoginResponse.GetUserDataFromAuthResponseResultDto>>
            LoginWith(Action<ResponseFixture, MPassTestContext> mutate, MPassTestContext context = null, string expectedRequestId = null)
        {
            var owned = context == null;
            context ??= ServiceFactory.Create();
            try
            {
                var requestId = NewRequestId();
                var fixture = context.NewLoginResponse(requestId);
                mutate(fixture, context);

                return await SubmitLoginAsync(context, context.SignedBase64(fixture), expectedRequestId ?? requestId);
            }
            finally
            {
                if (owned)
                    context.Dispose();
            }
        }

        private static async Task AssertLoginRejected(Action<ResponseFixture, MPassTestContext> mutate, string expectedMessage = null)
        {
            var result = await LoginWith(mutate);
            if (expectedMessage == null)
                AssertRejected(result);
            else
                AssertRejectedWith(result, expectedMessage);

            Assert.Null(result.Response?.UserInfo);
        }

        private static async Task AssertLoginAccepted(Action<ResponseFixture, MPassTestContext> mutate)
        {
            var result = await LoginWith(mutate);
            AssertAccepted(result);
            Assert.Equal(SamlFixtures.DefaultNameId, result.Response.UserInfo.Idnp);
        }

        [Fact]
        public async Task Inbound_ValidSignedMessages_Accepted_Test()
        {
            using var context = ServiceFactory.Create();
            var loginRequestId = NewRequestId();
            var logoutRequestId = NewRequestId();

            var login = await SubmitLoginAsync(context, context.SignedBase64(context.NewLoginResponse(loginRequestId)), loginRequestId);
            var logoutResponse = await SubmitLogoutResponseAsync(context, context.SignedBase64(context.NewLogoutResponse(logoutRequestId)), logoutRequestId);
            var logoutRequest = await SubmitLogoutRequestAsync(context, context.SignedBase64(context.NewLogoutRequest()));

            AssertAccepted(login);
            AssertAccepted(logoutResponse);
            AssertAccepted(logoutRequest);
        }

        [Fact]
        public Task LoginResponse_TwoAssertions_Rejected_Test()
            => AssertLoginRejected((f, c) =>
            {
                var second = c.NewLoginResponse(f.InResponseTo).Assertions[0];
                second.NameId = "2999999999999";
                f.Assertions.Add(second);
            });

        [Fact]
        public Task LoginResponse_EncryptedAtRoot_Rejected_Test()
            => AssertLoginRejected((f, c) => f.EncryptedAssertionCount = 1, SamlLoadValidationMessages.SamlEncryptedAssertionNotSupported);

        [Fact]
        public Task LoginResponse_EncryptedInAdvice_Rejected_Test()
            => AssertLoginRejected((f, c) => f.Assertions[0].AdviceEncryptedAssertionCount = 1,
                SamlLoadValidationMessages.SamlEncryptedAssertionNotSupported);

        [Fact]
        public Task LoginResponse_EncryptedOnly_Rejected_Test()
            => AssertLoginRejected((f, c) =>
            {
                f.Assertions.Clear();
                f.EncryptedAssertionCount = 1;
            });

        [Theory]
        [InlineData("https://other.example/metadata")]
        [InlineData("https://IDP.test.local/metadata")]
        [InlineData("https://idp.test.local/metadata ")]
        [InlineData("")]
        public Task LoginResponse_WrongAssertionIssuer_Rejected_Test(string issuer)
            => AssertLoginRejected((f, c) => f.Assertions[0].Issuer = issuer);

        [Fact]
        public Task LoginResponse_MissingAssertionIssuer_Rejected_Test()
            => AssertLoginRejected((f, c) => f.Assertions[0].Issuer = null, SamlLoadValidationMessages.SamlIssuerInvalid);

        [Theory]
        [InlineData(null)]
        [InlineData("https://other.example/metadata")]
        public Task LoginResponse_UnmatchedIssuer_Rejected_Test(string issuer)
            => AssertLoginRejected((f, c) => f.Issuer = issuer, SamlLoadValidationMessages.SamlIssuerInvalid);

        [Theory]
        [InlineData(null)]
        [InlineData("https://other.example/metadata")]
        public async Task LogoutResponse_UnmatchedIssuer_Rejected_Test(string issuer)
        {
            using var context = ServiceFactory.Create();
            var requestId = NewRequestId();
            var fixture = context.NewLogoutResponse(requestId);
            fixture.Issuer = issuer;

            var result = await SubmitLogoutResponseAsync(context, context.SignedBase64(fixture), requestId);

            AssertRejectedWith(result, SamlLoadValidationMessages.SamlIssuerInvalid);
        }

        [Theory]
        [InlineData(null)]
        [InlineData("https://other.example/metadata")]
        public async Task LogoutRequest_UnmatchedIssuer_Rejected_Test(string issuer)
        {
            using var context = ServiceFactory.Create();
            var fixture = context.NewLogoutRequest();
            fixture.Issuer = issuer;

            var result = await SubmitLogoutRequestAsync(context, context.SignedBase64(fixture));

            AssertRejectedWith(result, SamlLoadValidationMessages.SamlIssuerInvalid);
        }

        [Theory]
        [InlineData(null)]
        [InlineData("")]
        [InlineData("https://other.example/saml/acs")]
        [InlineData("https://sp.test.local/saml/acs/other")]
        public Task LoginResponse_UnmatchedDestination_Rejected_Test(string destination)
            => AssertLoginRejected((f, c) => f.Destination = destination);

        [Theory]
        [InlineData(null)]
        [InlineData("https://other.example/saml/logout-response")]
        public async Task LogoutResponse_UnmatchedDestination_Rejected_Test(string destination)
        {
            using var context = ServiceFactory.Create();
            var requestId = NewRequestId();
            var fixture = context.NewLogoutResponse(requestId);
            fixture.Destination = destination;

            var result = await SubmitLogoutResponseAsync(context, context.SignedBase64(fixture), requestId);

            AssertRejected(result);
        }

        [Fact]
        public Task LoginResponse_UpperCaseDestination_Accepted_Test()
            => AssertLoginAccepted((f, c) => f.Destination = f.Destination.ToUpperInvariant());

        [Fact]
        public Task LoginResponse_WrongInResponseTo_Rejected_Test()
            => AssertLoginRejected((f, c) => f.InResponseTo = NewRequestId());

        [Fact]
        public Task LoginResponse_UpperCaseInResponseTo_Rejected_Test()
            => AssertLoginRejected((f, c) =>
            {
                f.InResponseTo = f.InResponseTo.ToUpperInvariant();
                f.Assertions[0].SubjectConfirmations[0].Data[0].InResponseTo = f.InResponseTo;
            });

        [Fact]
        public Task LoginResponse_MissingInResponseTo_Rejected_Test()
            => AssertLoginRejected((f, c) => f.InResponseTo = null);

        [Fact]
        public async Task LogoutResponse_UnmatchedInResponseTo_Rejected_Test()
        {
            using var context = ServiceFactory.Create();
            var requestId = NewRequestId();
            var wrong = context.NewLogoutResponse(NewRequestId());
            var missing = context.NewLogoutResponse(null);

            var wrongResult = await SubmitLogoutResponseAsync(context, context.SignedBase64(wrong), requestId);
            var missingResult = await SubmitLogoutResponseAsync(context, context.SignedBase64(missing), requestId);

            AssertRejected(wrongResult);
            AssertRejected(missingResult);
        }

        [Theory]
        [InlineData(null)]
        [InlineData("")]
        [InlineData("   ")]
        public async Task Inbound_BlankExpectedId_UnsolicitedRejected_Test(string expectedRequestId)
        {
            using var context = ServiceFactory.Create();
            var login = context.NewLoginResponse(expectedRequestId);
            var logout = context.NewLogoutResponse(expectedRequestId);

            var loginResult = await SubmitLoginAsync(context, context.SignedBase64(login), expectedRequestId);
            var logoutResult = await SubmitLogoutResponseAsync(context, context.SignedBase64(logout), expectedRequestId);

            AssertRejectedWith(loginResult, DefaultMessages.ExpectedRequestIdRequired);
            AssertRejectedWith(logoutResult, DefaultMessages.ExpectedRequestIdRequired);
        }

        [Fact]
        public Task LoginResponse_DataWrongInResponseTo_Rejected_Test()
            => AssertLoginRejected((f, c) => f.Assertions[0].SubjectConfirmations[0].Data[0].InResponseTo = NewRequestId());

        [Fact]
        public Task LoginResponse_DataNoInResponseTo_Rejected_Test()
            => AssertLoginRejected((f, c) => f.Assertions[0].SubjectConfirmations[0].Data[0].InResponseTo = null);

        [Theory]
        [InlineData(null)]
        [InlineData("https://other.example/saml/acs")]
        public Task LoginResponse_DataUnmatchedRecipient_Rejected_Test(string recipient)
            => AssertLoginRejected((f, c) => f.Assertions[0].SubjectConfirmations[0].Data[0].Recipient = recipient);

        [Theory]
        [InlineData(SamlNs.MethodHolderOfKey)]
        [InlineData(SamlNs.MethodSenderVouches)]
        [InlineData("urn:oasis:names:tc:SAML:2.0:cm:BEARER")]
        public Task LoginResponse_OnlyNonBearer_Rejected_Test(string method)
            => AssertLoginRejected((f, c) => f.Assertions[0].SubjectConfirmations[0].Method = method);

        [Fact]
        public Task LoginResponse_NonBearerNextToBearer_Ignored_Test()
            => AssertLoginAccepted((f, c) =>
            {
                var nonBearer = new SubjectConfirmationFixture
                {
                    Method = SamlNs.MethodHolderOfKey
                };
                nonBearer.Data.Add(new SubjectConfirmationDataFixture
                {
                    Recipient = "https://other.example/acs", 
                    NotBefore = c.Now.AddHours(1)
                });
                f.Assertions[0].SubjectConfirmations.Insert(0, nonBearer);
            });

        [Fact]
        public Task LoginResponse_WrongAudience_Rejected_Test()
            => AssertLoginRejected((f, c) =>
            {
                f.Assertions[0].AudienceRestrictions.Clear();
                f.Assertions[0].AudienceRestrictions.Add(new List<string>
                {
                    "https://other-sp.test/metadata"
                });
            });

        [Fact]
        public Task LoginResponse_ExtraAudienceWithoutSp_Rejected_Test()
            => AssertLoginRejected((f, c) => f.Assertions[0].AudienceRestrictions.Add(new List<string>
            {
                "https://other-sp.test/metadata"
            }));

        [Fact]
        public Task LoginResponse_SpAmongOtherAudiences_Accepted_Test()
            => AssertLoginAccepted((f, c) => f.Assertions[0].AudienceRestrictions[0].Insert(0, "https://other-sp.test/metadata"));

        [Fact]
        public Task LoginResponse_UpperCaseAudience_Rejected_Test()
            => AssertLoginRejected((f, c) =>
            {
                f.Assertions[0].AudienceRestrictions.Clear();
                f.Assertions[0].AudienceRestrictions.Add(new List<string> { MPassTestSettings.DefaultSpIssuer.ToUpperInvariant() });
            });

        [Fact]
        public Task LoginResponse_NoAudienceRestriction_Rejected_Test()
            => AssertLoginRejected((f, c) => f.Assertions[0].AudienceRestrictions.Clear());

        [Fact]
        public Task LoginResponse_ConditionsNotYetValid_Rejected_Test()
            => AssertLoginRejected((f, c) => f.Assertions[0].ConditionsNotBefore = c.Now + Skew + OneSecond);

        [Fact]
        public Task LoginResponse_ConditionsExpired_Rejected_Test()
            => AssertLoginRejected((f, c) => f.Assertions[0].ConditionsNotOnOrAfter = c.Now - Skew);

        [Fact]
        public Task LoginResponse_DataExpired_Rejected_Test()
            => AssertLoginRejected((f, c) => f.Assertions[0].SubjectConfirmations[0].Data[0].NotOnOrAfter = c.Now - Skew);

        [Fact]
        public Task LoginResponse_TimesAtSkewEdge_Accepted_Test()
            => AssertLoginAccepted((f, c) =>
            {
                f.IssueInstant = c.Now + Skew;
                f.Assertions[0].ConditionsNotBefore = c.Now + Skew;
                f.Assertions[0].ConditionsNotOnOrAfter = c.Now - Skew + OneSecond;
                f.Assertions[0].SubjectConfirmations[0].Data[0].NotOnOrAfter = c.Now - Skew + OneSecond;
            });

        [Fact]
        public Task LoginResponse_FutureIssueInstant_Rejected_Test()
            => AssertLoginRejected((f, c) => f.IssueInstant = c.Now + Skew + OneSecond);

        [Fact]
        public Task LoginResponse_ExpiredIssueInstant_Rejected_Test()
            => AssertLoginRejected((f, c) => f.IssueInstant = c.Now - Timeout - Skew - OneSecond);

        [Fact]
        public Task LoginResponse_IssueInstantAtLimit_Accepted_Test()
            => AssertLoginAccepted((f, c) => f.IssueInstant = c.Now - Timeout - Skew);

        [Fact]
        public Task LoginResponse_MissingIssueInstant_Rejected_Test()
            => AssertLoginRejected((f, c) =>
            {
                f.IssueInstant = null;
                f.IssueInstantRaw = null;
            });

        [Theory]
        [InlineData(13)]
        [InlineData(-13)]
        public async Task Logout_IssueInstantOutsideWindow_Rejected_Test(int minutesFromNow)
        {
            using var context = ServiceFactory.Create();
            var requestId = NewRequestId();
            var response = context.NewLogoutResponse(requestId);
            response.IssueInstant = context.Now.AddMinutes(minutesFromNow);
            var request = context.NewLogoutRequest();
            request.IssueInstant = context.Now.AddMinutes(minutesFromNow);

            var responseResult = await SubmitLogoutResponseAsync(context, context.SignedBase64(response), requestId);
            var requestResult = await SubmitLogoutRequestAsync(context, context.SignedBase64(request));

            AssertRejected(responseResult);
            AssertRejected(requestResult);
        }

        [Theory]
        [InlineData("not-a-date")]
        [InlineData("2026-13-45T99:00:00Z")]
        [InlineData("01/06/2026 10:00:00")]
        public async Task Inbound_InvalidIssueInstant_DateInvalid_Test(string raw)
        {
            using var context = ServiceFactory.Create();
            var loginRequestId = NewRequestId();
            var logoutRequestId = NewRequestId();
            var login = context.NewLoginResponse(loginRequestId);
            login.IssueInstantRaw = raw;
            var logoutResponse = context.NewLogoutResponse(logoutRequestId);
            logoutResponse.IssueInstantRaw = raw;
            var logoutRequest = context.NewLogoutRequest();
            logoutRequest.IssueInstantRaw = raw;

            var loginResult = await SubmitLoginAsync(context, context.SignedBase64(login), loginRequestId);
            var logoutResponseResult = await SubmitLogoutResponseAsync(context, context.SignedBase64(logoutResponse), logoutRequestId);
            var logoutRequestResult = await SubmitLogoutRequestAsync(context, context.SignedBase64(logoutRequest));

            AssertRejectedWith(loginResult, SamlLoadValidationMessages.SamlDateInvalid);
            AssertRejectedWith(logoutResponseResult, SamlLoadValidationMessages.SamlDateInvalid);
            AssertRejectedWith(logoutRequestResult, SamlLoadValidationMessages.SamlDateInvalid);
        }

        [Fact]
        public Task LoginResponse_NonSuccessStatus_NoUserData_Test()
            => AssertLoginRejected((f, c) =>
            {
                f.StatusCode = SamlNs.StatusResponder;
                f.StatusMessage = "Temporary error";
            });

        [Fact]
        public Task LoginResponse_AuthnFailed_MapsToAuthCanceled_Test()
            => AssertLoginRejected((f, c) =>
            {
                f.StatusCode = SamlNs.StatusResponder;
                f.SubStatusCode = SamlNs.StatusAuthnFailed;
                f.Assertions.Clear();
            }, DefaultMessages.AuthCanceled);

        [Fact]
        public Task LoginResponse_UnknownPrincipal_MapsToMessage_Test()
            => AssertLoginRejected((f, c) =>
            {
                f.StatusCode = SamlNs.StatusRequester;
                f.SubStatusCode = SamlNs.StatusUnknownPrincipal;
                f.Assertions.Clear();
            }, SamlLoadValidationMessages.InvalidSamlResponseUnknownPrincipal);

        [Fact]
        public async Task LoginResponse_StatusMessage_StrippedCapped256_Test()
        {
            var longMessage = "<b>x</b>\t\n\t" + new string('M', 1000);
            var result = await LoginWith((f, c) =>
            {
                f.StatusCode = SamlNs.StatusResponder;
                f.StatusMessage = longMessage;
                f.Assertions.Clear();
            });

            AssertRejected(result);
            Assert.Null(result.Response?.UserInfo);
            foreach (var text in MessageTexts(result))
            {
                Assert.DoesNotContain(new string('M', 257), text, StringComparison.Ordinal);
                Assert.DoesNotContain("\t", text, StringComparison.Ordinal);
                Assert.DoesNotContain("\n", text, StringComparison.Ordinal);
            }
        }

        [Fact]
        public async Task LoginResponse_UnsignedStatus_SignatureFailed_Test()
        {
            using var context = ServiceFactory.Create();
            var requestId = NewRequestId();
            var fixture = context.NewLoginResponse(requestId);
            fixture.StatusCode = SamlNs.StatusResponder;
            fixture.SubStatusCode = SamlNs.StatusAuthnFailed;
            fixture.StatusMessage = "unsigned-status-marker";

            var result = await SubmitLoginAsync(context, MPassTestContext.UnsignedBase64(SamlFixtureBuilder.Build(fixture)), requestId);

            AssertRejectedWith(result, SamlLoadValidationMessages.InvalidSamlResponseSignature);
            Assert.DoesNotContain(MessageTexts(result), t => t == DefaultMessages.AuthCanceled || t.Contains("unsigned-status-marker"));
        }

        [Fact]
        public async Task LogoutResponse_UnsignedStatus_SignatureFailed_Test()
        {
            using var context = ServiceFactory.Create();
            var requestId = NewRequestId();
            var fixture = context.NewLogoutResponse(requestId);
            fixture.StatusCode = SamlNs.StatusResponder;
            fixture.StatusMessage = "unsigned-status-marker";

            var result = await SubmitLogoutResponseAsync(context, MPassTestContext.UnsignedBase64(SamlFixtureBuilder.Build(fixture)), requestId);

            AssertRejectedWith(result, SamlLoadValidationMessages.InvalidSamlResponseSignature);
            Assert.DoesNotContain(MessageTexts(result), t => t.Contains("unsigned-status-marker"));
        }

        [Fact]
        public async Task LoginResponse_SecondSubmission_Replay_Test()
        {
            using var context = ServiceFactory.Create();
            var requestId = NewRequestId();
            var saml = context.SignedBase64(context.NewLoginResponse(requestId));

            var first = await SubmitLoginAsync(context, saml, requestId);
            var second = await SubmitLoginAsync(context, saml, requestId);

            AssertAccepted(first);
            AssertRejectedWith(second, SamlLoadValidationMessages.SamlReplayDetected);
            Assert.Null(second.Response?.UserInfo);
        }

        [Fact]
        public async Task LoginResponse_ReusedAssertionId_Replay_Test()
        {
            using var context = ServiceFactory.Create();
            var requestId = NewRequestId();
            var firstFixture = context.NewLoginResponse(requestId);
            var secondFixture = context.NewLoginResponse(requestId);
            secondFixture.Assertions[0].Id = firstFixture.Assertions[0].Id;

            var first = await SubmitLoginAsync(context, context.SignedBase64(firstFixture), requestId);
            var second = await SubmitLoginAsync(context, context.SignedBase64(secondFixture), requestId);

            AssertAccepted(first);
            AssertRejectedWith(second, SamlLoadValidationMessages.SamlReplayDetected);
        }

        [Fact]
        public async Task LoginResponse_ClockAdvanced_StillReplay_Test()
        {
            using var context = ServiceFactory.Create();
            var requestId = NewRequestId();
            var saml = context.SignedBase64(context.NewLoginResponse(requestId));

            var first = await SubmitLoginAsync(context, saml, requestId);
            context.Time.Advance(TimeSpan.FromMinutes(4));
            var second = await SubmitLoginAsync(context, saml, requestId);

            AssertAccepted(first);
            AssertRejectedWith(second, SamlLoadValidationMessages.SamlReplayDetected);
        }

        [Fact]
        public async Task LogoutResponse_SecondSubmission_Replay_Test()
        {
            using var context = ServiceFactory.Create();
            var requestId = NewRequestId();
            var saml = context.SignedBase64(context.NewLogoutResponse(requestId));

            var first = await SubmitLogoutResponseAsync(context, saml, requestId);
            var second = await SubmitLogoutResponseAsync(context, saml, requestId);

            AssertAccepted(first);
            AssertRejectedWith(second, SamlLoadValidationMessages.SamlReplayDetected);
        }

        [Fact]
        public async Task LogoutRequest_SecondSubmission_Replay_Test()
        {
            using var context = ServiceFactory.Create();
            var saml = context.SignedBase64(context.NewLogoutRequest());

            var first = await SubmitLogoutRequestAsync(context, saml);
            var second = await SubmitLogoutRequestAsync(context, saml);

            AssertAccepted(first);
            AssertRejectedWith(second, SamlLoadValidationMessages.SamlReplayDetected);
            Assert.Null(second.Response?.HtmlDocument);
        }

        [Fact]
        public async Task BuildLogoutResponse_SecondSubmission_Replay_Test()
        {
            using var context = ServiceFactory.Create();
            var saml = context.SignedBase64(context.NewLogoutRequest());
            BuildLogOutResponseDto Dto() => new BuildLogOutResponseDto
            {
                SamlRequest = saml,
                RelayState = null,
                UserIdentifierId = SamlFixtures.DefaultNameId,
                UserSessionIndexId = DefaultLogoutSessionIndex
            };

            var first = await context.Builder.BuildLogOutResponseAsync(Dto(), Ct);
            var second = await context.Builder.BuildLogOutResponseAsync(Dto(), Ct);

            AssertAccepted(first);
            AssertRejectedWith(second, SamlLoadValidationMessages.SamlReplayDetected);
            Assert.Null(second.Response?.SamlResponse);
        }

        [Fact]
        public async Task Inbound_SameIdAcrossMessageTypes_Accepted_Test()
        {
            using var context = ServiceFactory.Create();
            var sharedId = SamlIds.New("_shared");
            var loginRequestId = NewRequestId();
            var logoutRequestId = NewRequestId();
            var logoutResponse = context.NewLogoutResponse(logoutRequestId);
            logoutResponse.Id = sharedId;
            var login = context.NewLoginResponse(loginRequestId);
            login.Id = sharedId;
            var logoutRequest = context.NewLogoutRequest();
            logoutRequest.Id = sharedId;

            var logoutResult = await SubmitLogoutResponseAsync(context, context.SignedBase64(logoutResponse), logoutRequestId);
            var loginResult = await SubmitLoginAsync(context, context.SignedBase64(login), loginRequestId);
            var sloResult = await SubmitLogoutRequestAsync(context, context.SignedBase64(logoutRequest));

            AssertAccepted(logoutResult);
            AssertAccepted(loginResult);
            AssertAccepted(sloResult);
        }

        [Fact]
        public async Task LoginResponse_RejectedMessage_NoConsume_Test()
        {
            using var context = ServiceFactory.Create();
            var requestId = NewRequestId();
            var fixture = context.NewLoginResponse(requestId);

            var rejected = await SubmitLoginAsync(context, context.SignedBase64(fixture), NewRequestId());
            var accepted = await SubmitLoginAsync(context, context.SignedBase64(fixture), requestId);

            AssertRejected(rejected);
            AssertAccepted(accepted);
        }

        [Theory]
        [InlineData("2999999999999", DefaultLogoutSessionIndex)]
        [InlineData(SamlFixtures.DefaultNameId, "_session-other")]
        [InlineData("2000000000001 ", DefaultLogoutSessionIndex)]
        public async Task LogoutRequest_WrongNameIdOrIndex_Rejected_Test(string expectedNameId, string expectedSessionIndex)
        {
            using var context = ServiceFactory.Create();

            var result = await SubmitLogoutRequestAsync(context, context.SignedBase64(context.NewLogoutRequest()), expectedNameId, expectedSessionIndex);

            AssertRejected(result);
            Assert.Null(result.Response?.HtmlDocument);
        }

        [Theory]
        [InlineData(null, DefaultLogoutSessionIndex)]
        [InlineData(SamlFixtures.DefaultNameId, null)]
        [InlineData("", "")]
        public async Task BuildLogoutResponse_BlankExpectations_Fails_Test(string expectedNameId, string expectedSessionIndex)
        {
            using var context = ServiceFactory.Create();
            var dto = new BuildLogOutResponseDto
            {
                SamlRequest = context.SignedBase64(context.NewLogoutRequest()),
                UserIdentifierId = expectedNameId,
                UserSessionIndexId = expectedSessionIndex
            };

            var result = await context.Builder.BuildLogOutResponseAsync(dto, Ct);

            AssertRejectedWith(result, SamlLoadValidationMessages.SamlLogOutExpectationRequired);
        }

        [Fact]
        public Task LogoutRequest_TwoNameIds_Rejected_Test()
            => AssertLogoutRequestRejected(f => f.NameIds.Add(SamlFixtures.DefaultNameId), SamlLoadValidationMessages.SamlLogOutNameIdInvalid);

        [Fact]
        public Task LogoutRequest_OnlyEncryptedId_Rejected_Test()
            => AssertLogoutRequestRejected(f =>
            {
                f.NameIds.Clear();
                f.EncryptedIdCount = 1;
            }, SamlLoadValidationMessages.SamlLogOutNameIdInvalid);

        [Fact]
        public Task LogoutRequest_EncryptedIdAndNameId_Rejected_Test()
            => AssertLogoutRequestRejected(f => f.EncryptedIdCount = 1, SamlLoadValidationMessages.SamlLogOutNameIdInvalid);

        [Fact]
        public Task LogoutRequest_BaseIdNextToNameId_Rejected_Test()
            => AssertLogoutRequestRejected(f => f.BaseIdCount = 1, SamlLoadValidationMessages.SamlLogOutNameIdInvalid);

        [Fact]
        public async Task LogoutRequest_IndexListWithMatch_Accepted_Test()
        {
            using var context = ServiceFactory.Create();
            var fixture = context.NewLogoutRequest();
            fixture.SessionIndexes.Clear();
            fixture.SessionIndexes.Add("_session-a");
            fixture.SessionIndexes.Add(DefaultLogoutSessionIndex);
            fixture.SessionIndexes.Add("_session-c");

            var result = await SubmitLogoutRequestAsync(context, context.SignedBase64(fixture));

            AssertAccepted(result);
        }

        [Fact]
        public Task LogoutRequest_MissingSessionIndex_Rejected_Test()
            => AssertLogoutRequestRejected(f => f.SessionIndexes.Clear());

        [Theory]
        [InlineData(null)]
        [InlineData("https://other.example/saml/slo")]
        public Task LogoutRequest_UnmatchedDestination_Rejected_Test(string destination)
            => AssertLogoutRequestRejected(f => f.Destination = destination);

        [Fact]
        public Task LogoutRequest_WrongIssuer_NoForm_Test()
            => AssertLogoutRequestRejected(f => f.Issuer = "https://other.example/metadata", SamlLoadValidationMessages.SamlIssuerInvalid);

        [Fact]
        public Task LogoutRequest_ExpiredNotOnOrAfter_Rejected_Test()
            => AssertLogoutRequestRejected(f => f.NotOnOrAfter = TestClock.Epoch - Skew);

        [Fact]
        public async Task LogoutRequest_NotOnOrAfterInSkew_Accepted_Test()
        {
            using var context = ServiceFactory.Create();
            var fixture = context.NewLogoutRequest();
            fixture.NotOnOrAfter = context.Now - Skew + OneSecond;

            var result = await SubmitLogoutRequestAsync(context, context.SignedBase64(fixture));

            AssertAccepted(result);
        }

        private static async Task AssertLogoutRequestRejected(Action<LogoutRequestFixture> mutate, string expectedMessage = null)
        {
            using var context = ServiceFactory.Create();
            var fixture = context.NewLogoutRequest();
            mutate(fixture);

            var result = await SubmitLogoutRequestAsync(context, context.SignedBase64(fixture));

            if (expectedMessage == null)
                AssertRejected(result);
            else
                AssertRejectedWith(result, expectedMessage);
            Assert.Null(result.Response?.HtmlDocument);
        }

        [Fact]
        public async Task LoginResponse_DuplicateAttributes_Merged_Test()
        {
            var result = await LoginWith((f, c) => f.Assertions[0].Attributes.Add(new AttributeFixture("Language", "en")));

            AssertAccepted(result);
            var values = result.Response.UserAttributes["Language"];
            Assert.Equal(new[] { "ro", "en" }, values.ToArray());
        }

        [Fact]
        public async Task LoginResponse_AttributeMarkup_ReturnsText_Test()
        {
            var result = await LoginWith((f, c) =>
            {
                var firstName = f.Assertions[0].Attributes.Single(a => a.Name == "FirstName");
                firstName.ValuesAsMarkup = true;
            });

            AssertAccepted(result);
            Assert.Equal("TestFirstName", Assert.Single(result.Response.UserAttributes["FirstName"]));
            Assert.Equal("TestFirstName", result.Response.UserInfo.FirstName);
            Assert.DoesNotContain(result.Response.UserAttributes.SelectMany(a => a.Value), v => v.Contains("<"));
        }

        [Fact]
        public Task LoginResponse_DataMissingExpiry_Rejected_Test()
            => AssertLoginRejected((f, c) => f.Assertions[0].SubjectConfirmations[0].Data[0].NotOnOrAfter = null);

        [Fact]
        public Task LoginResponse_DataWithNotBefore_Rejected_Test()
            => AssertLoginRejected((f, c) => f.Assertions[0].SubjectConfirmations[0].Data[0].NotBefore = c.Now.AddMinutes(-1));

        [Fact]
        public Task LoginResponse_TwoDataElements_Rejected_Test()
            => AssertLoginRejected((f, c) =>
            {
                var data = f.Assertions[0].SubjectConfirmations[0].Data[0];
                f.Assertions[0].SubjectConfirmations[0].Data.Add(new SubjectConfirmationDataFixture
                {
                    Recipient = data.Recipient,
                    NotOnOrAfter = data.NotOnOrAfter,
                    InResponseTo = data.InResponseTo
                });
            });

        [Fact]
        public Task LoginResponse_BearerMissingData_Rejected_Test()
            => AssertLoginRejected((f, c) => f.Assertions[0].SubjectConfirmations[0].Data.Clear());

        [Fact]
        public Task LoginResponse_SessionExpired_Rejected_Test()
            => AssertLoginRejected((f, c) => f.Assertions[0].SessionNotOnOrAfter = c.Now - Skew);

        [Fact]
        public Task LoginResponse_SessionNotExpired_Accepted_Test()
            => AssertLoginAccepted((f, c) => f.Assertions[0].SessionNotOnOrAfter = c.Now.AddHours(8));

        [Fact]
        public Task LoginResponse_TwoSubjects_Rejected_Test() => AssertLoginRejected((f, c) => f.Assertions[0].SubjectCount = 2);

        [Fact]
        public Task LoginResponse_TwoNameIds_Rejected_Test() => AssertLoginRejected((f, c) => f.Assertions[0].NameIdCount = 2);

        [Fact]
        public Task LoginResponse_TwoAuthnStatements_Rejected_Test() => AssertLoginRejected((f, c) => f.Assertions[0].AuthnStatementCount = 2);

        [Fact]
        public Task LoginResponse_TwoConditions_Rejected_Test() => AssertLoginRejected((f, c) => f.Assertions[0].ConditionsCount = 2);

        [Fact]
        public Task LoginResponse_MissingConditions_Rejected_Test() => AssertLoginRejected((f, c) => f.Assertions[0].ConditionsCount = 0);

        [Fact]
        public Task LoginResponse_MissingNameId_Rejected_Test() => AssertLoginRejected((f, c) => f.Assertions[0].NameId = null);

        [Fact]
        public Task LoginResponse_EmptyAssertionId_Rejected_Test() => AssertLoginRejected((f, c) => f.Assertions[0].Id = string.Empty);
    }
}
