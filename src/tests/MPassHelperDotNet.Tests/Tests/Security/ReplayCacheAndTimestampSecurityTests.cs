using System;
using System.Collections.Concurrent;
using System.Collections.Generic;
using System.Linq;
using System.Security.Cryptography.X509Certificates;
using System.Threading;
using System.Threading.Tasks;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Time.Testing;
using MPassHelperDotNet.Abstractions.Services.Replay;
using MPassHelperDotNet.Helpers.Messages;
using MPassHelperDotNet.Helpers.SAML;
using MPassHelperDotNet.Models.Internal.Request;
using MPassHelperDotNet.Services.Replay;
using MPassHelperDotNet.Tests.Helpers.Certificates;
using MPassHelperDotNet.Tests.Helpers.Fakes;
using MPassHelperDotNet.Tests.Helpers.Hosting;
using MPassHelperDotNet.Tests.Helpers.Runtime;
using MPassHelperDotNet.Tests.Helpers.Saml;
using MPassHelperDotNet.Tests.Helpers.Signing;
using MPassHelperDotNet.Tests.Models.Hosting;
using MPassHelperDotNet.Tests.Models.Saml;
using RzR.ResultMessage.Abstractions;
using Xunit;
using static MPassHelperDotNet.Tests.Helpers.Kits.SecurityTestKit;

namespace MPassHelperDotNet.Tests.Tests.Security
{
    [Trait(TestAreas.Trait, TestAreas.Security)]
    public class ReplayCacheAndTimestampSecurityTests
    {
        private static readonly TimeSpan Timeout = TimeSpan.FromMinutes(10);
        private static readonly TimeSpan Skew = TimeSpan.FromMinutes(2);

        private static async Task<IResult[]> SubmitWithRawIssueInstant(MPassTestContext context, string raw)
        {
            var loginRequestId = NewRequestId();
            var logoutRequestId = NewRequestId();
            var login = context.NewLoginResponse(loginRequestId);
            login.IssueInstantRaw = raw;
            var logoutResponse = context.NewLogoutResponse(logoutRequestId);
            logoutResponse.IssueInstantRaw = raw;
            var logoutRequest = context.NewLogoutRequest();
            logoutRequest.IssueInstantRaw = raw;

            return new IResult[]
            {
                await SubmitLoginAsync(context, context.SignedBase64(login), loginRequestId),
                await SubmitLogoutResponseAsync(context, context.SignedBase64(logoutResponse), logoutRequestId),
                await SubmitLogoutRequestAsync(context, context.SignedBase64(logoutRequest))
            };
        }

        [Theory]
        [InlineData("2026-06-01T10:00:00")]
        [InlineData("2026-06-01T10:01:30.5")]
        [InlineData("2026-06-01T09:59:00.1234567")]
        public async Task Inbound_MissingZone_AcceptedInWindow_Test(string raw)
        {
            using var context = ServiceFactory.Create();

            var results = await SubmitWithRawIssueInstant(context, raw);

            Assert.All(results, AssertAccepted);
        }

        [Theory]
        [InlineData("2026-06-01T10:02:01")]
        [InlineData("2026-06-01T09:47:59")]
        public async Task Inbound_MissingZone_RejectedOutsideWindow_Test(string raw)
        {
            using var context = ServiceFactory.Create();

            var results = await SubmitWithRawIssueInstant(context, raw);

            Assert.All(results, AssertRejected);
        }

        [Theory]
        [InlineData("2026-06-01")]
        [InlineData("2026")]
        [InlineData("2026-06")]
        [InlineData("2026-06-01T10:00:00.12345678Z")]
        [InlineData("2026-06-01T10:00Z")]
        [InlineData("2026-06-01 10:00:00Z")]
        [InlineData("10:00:00Z")]
        [InlineData("2026-06-01T10:00:00+14:60")]
        public async Task Inbound_NonDateTimeForms_DateInvalid_Test(string raw)
        {
            using var context = ServiceFactory.Create();

            var results = await SubmitWithRawIssueInstant(context, raw);

            Assert.All(results, r => AssertRejectedWith(r, SamlLoadValidationMessages.SamlDateInvalid));
        }

        [Fact]
        public async Task Inbound_SevenFractionDigitsWithZone_Accepted_Test()
        {
            using var context = ServiceFactory.Create();

            var results = await SubmitWithRawIssueInstant(context, "2026-06-01T10:00:00.1234567Z");

            Assert.All(results, AssertAccepted);
        }

        [Fact]
        public async Task Inbound_OffsetSameInstant_Accepted_Test()
        {
            using var context = ServiceFactory.Create();

            var results = await SubmitWithRawIssueInstant(context, "2026-06-01T13:00:00+03:00");

            Assert.All(results, AssertAccepted);
        }

        public static TheoryData<int> SkewSeconds => new TheoryData<int> { 0, 30, 120, 300 };

        [Theory]
        [MemberData(nameof(SkewSeconds))]
        public async Task LoginResponse_ReplayExpiry_FromIssueInstant_Test(int skewSeconds)
        {
            var skew = TimeSpan.FromSeconds(skewSeconds);
            var recorder = new ExpiryRecordingReplayCache();
            using var context = ServiceFactory.Create(new MPassTestSettings
                {
                    SamlClockSkew = skew
                },
                configureBefore: services => services.AddSingleton<ISamlReplayCache>(recorder));
            var requestId = NewRequestId();
            var issueInstant = context.Now.AddMinutes(-3);
            var fixture = context.NewLoginResponse(requestId);
            fixture.IssueInstant = issueInstant;
            var farFuture = context.Now.AddYears(5);
            fixture.Assertions[0].ConditionsNotOnOrAfter = farFuture;
            fixture.Assertions[0].SubjectConfirmations[0].Data[0].NotOnOrAfter = farFuture;
            fixture.Assertions[0].SessionNotOnOrAfter = farFuture;

            var result = await SubmitLoginAsync(context, context.SignedBase64(fixture), requestId);

            AssertAccepted(result);
            var expected = ExpectedExpiry(issueInstant, skew);
            Assert.Equal(expected, recorder.ExpiryOf("Response:" + fixture.Id));
            Assert.Equal(expected, recorder.ExpiryOf("Assertion:" + fixture.Assertions[0].Id));
            Assert.Equal(2, recorder.Calls.Count);
        }

        [Theory]
        [MemberData(nameof(SkewSeconds))]
        public async Task Logout_ReplayExpiry_FromIssueInstant_Test(int skewSeconds)
        {
            var skew = TimeSpan.FromSeconds(skewSeconds);
            var recorder = new ExpiryRecordingReplayCache();
            using var context = ServiceFactory.Create(new MPassTestSettings
                {
                    SamlClockSkew = skew
                },
                configureBefore: services => services.AddSingleton<ISamlReplayCache>(recorder));
            var requestId = NewRequestId();
            var issueInstant = context.Now.AddMinutes(-1);
            var logoutResponse = context.NewLogoutResponse(requestId);
            logoutResponse.IssueInstant = issueInstant;
            var logoutRequest = context.NewLogoutRequest();
            logoutRequest.IssueInstant = issueInstant;
            logoutRequest.NotOnOrAfter = context.Now.AddYears(5);

            var responseResult = await SubmitLogoutResponseAsync(context, context.SignedBase64(logoutResponse), requestId);
            var requestResult = await SubmitLogoutRequestAsync(context, context.SignedBase64(logoutRequest));

            AssertAccepted(responseResult);
            AssertAccepted(requestResult);
            var expected = ExpectedExpiry(issueInstant, skew);
            Assert.Equal(expected, recorder.ExpiryOf("LogoutResponse:" + logoutResponse.Id));
            Assert.Equal(expected, recorder.ExpiryOf("LogoutRequest:" + logoutRequest.Id));
        }

        [Fact]
        public async Task LoginResponse_ReplayAtWindowEnd_Rejected_Test()
        {
            using var context = ServiceFactory.Create();
            var requestId = NewRequestId();
            var issueInstant = context.Now;
            var fixture = LongLivedLogin(context, requestId, issueInstant);
            var saml = context.SignedBase64(fixture);

            var first = await SubmitLoginAsync(context, saml, requestId);
            context.Time.Advance(Timeout + Skew);
            var control = await SubmitLoginAsync(context, context.SignedBase64(LongLivedLogin(context, requestId, issueInstant)), requestId);
            var replay = await SubmitLoginAsync(context, saml, requestId);

            AssertAccepted(first);
            AssertAccepted(control);
            AssertRejectedWith(replay, SamlLoadValidationMessages.SamlReplayDetected);
        }

        [Fact]
        public async Task LogoutResponse_ReplayAtWindowEnd_Rejected_Test()
        {
            using var context = ServiceFactory.Create();
            var requestId = NewRequestId();
            var fixture = context.NewLogoutResponse(requestId);
            var saml = context.SignedBase64(fixture);

            var first = await SubmitLogoutResponseAsync(context, saml, requestId);
            context.Time.Advance(Timeout + Skew);
            var replay = await SubmitLogoutResponseAsync(context, saml, requestId);

            AssertAccepted(first);
            AssertRejectedWith(replay, SamlLoadValidationMessages.SamlReplayDetected);
        }

        [Fact]
        public async Task ReplayEntry_ActiveForMarginBeyondWindow_Test()
        {
            var recorder = new ExpiryRecordingReplayCache();
            using var context = ServiceFactory.Create(configureBefore: services => services.AddSingleton<ISamlReplayCache>(recorder));
            var requestId = NewRequestId();

            var result = await SubmitLoginAsync(context, context.SignedBase64(LongLivedLogin(context, requestId, context.Now)), requestId);

            AssertAccepted(result);
            var windowEnd = context.Now + Timeout + Skew;
            Assert.All(recorder.Calls, c => Assert.True(c.ExpiresAtUtc - windowEnd >= TimeSpan.FromMinutes(1),
                "replay entry expires " + (c.ExpiresAtUtc - windowEnd) + " after the acceptance window"));
        }

        private static DateTimeOffset ExpectedExpiry(DateTimeOffset issueInstant, TimeSpan skew)
            => issueInstant + Timeout + skew + (skew > TimeSpan.FromMinutes(1) ? skew : TimeSpan.FromMinutes(1));

        private static ResponseFixture LongLivedLogin(MPassTestContext context, string requestId, DateTimeOffset issueInstant)
        {
            var fixture = context.NewLoginResponse(requestId);
            fixture.IssueInstant = issueInstant;
            fixture.Assertions[0].ConditionsNotOnOrAfter = issueInstant.AddHours(1);
            fixture.Assertions[0].SubjectConfirmations[0].Data[0].NotOnOrAfter = issueInstant.AddHours(1);

            return fixture;
        }

        private const int Workers = 64;

        private static async Task<bool[]> RunConcurrently(int count, Func<int, Task<bool>> action)
        {
            using var gate = new ManualResetEventSlim(false);
            var tasks = Enumerable.Range(0, count)
                .Select(i => Task.Factory.StartNew(() =>
                {
                    gate.Wait();

                    return action(i).GetAwaiter().GetResult();
                }, CancellationToken.None, TaskCreationOptions.LongRunning, TaskScheduler.Default))
                .ToArray();
            gate.Set();

            return await Task.WhenAll(tasks);
        }

        [Fact]
        public async Task FullCacheNoneExpired_ConcurrentCallersFail_Test()
        {
            var time = TestClock.CreateFake();
            var cache = new InMemorySamlReplayCache(time, 100, 7);
            var expires = time.GetUtcNow().AddHours(1);
            for (var i = 0; i < 100; i++)
                Assert.True(await cache.TryAddAsync("fill-" + i, expires, Ct));

            var results = await RunConcurrently(Workers * 4, i => cache.TryAddAsync("new-" + i, expires, CancellationToken.None));

            Assert.All(results, Assert.False);
            Assert.False(await cache.TryAddAsync("fill-0", expires, Ct));
        }

        [Fact]
        public async Task SameKeyManyThreads_OneWins_RepeatedRounds_Test()
        {
            var time = TestClock.CreateFake();
            var cache = new InMemorySamlReplayCache(time, 10000, 3);
            var expires = time.GetUtcNow().AddHours(1);

            for (var round = 0; round < 50; round++)
            {
                var key = "round-" + round;
                var results = await RunConcurrently(Workers / 2, _ => cache.TryAddAsync(key, expires, CancellationToken.None));

                Assert.Equal(1, results.Count(r => r));
            }
        }

        [Fact]
        public async Task SameKeyLastSlot_OneWins_ThenCacheFull_Test()
        {
            var time = TestClock.CreateFake();
            var cache = new InMemorySamlReplayCache(time, 10, 1);
            var expires = time.GetUtcNow().AddHours(1);
            for (var i = 0; i < 9; i++)
                Assert.True(await cache.TryAddAsync("fill-" + i, expires, Ct));

            var results = await RunConcurrently(Workers, _ => cache.TryAddAsync("last", expires, CancellationToken.None));

            Assert.Equal(1, results.Count(r => r));
            Assert.False(await cache.TryAddAsync("another", expires, Ct));
        }

        [Fact]
        public async Task FullCacheExpired_ConcurrentAddsRespectCap_Test()
        {
            var time = TestClock.CreateFake();
            const int cap = 50;
            var cache = new InMemorySamlReplayCache(time, cap, 1000);
            for (var i = 0; i < cap; i++)
                Assert.True(await cache.TryAddAsync("old-" + i, time.GetUtcNow().AddMinutes(1), Ct));
            time.Advance(TimeSpan.FromMinutes(2));
            var expires = time.GetUtcNow().AddHours(1);

            var results = await RunConcurrently(Workers * 4, i => cache.TryAddAsync("new-" + i, expires, CancellationToken.None));

            var accepted = results.Select((r, i) => (r, i)).Where(x => x.r).Select(x => "new-" + x.i).ToList();
            Assert.InRange(accepted.Count, 1, cap);
            foreach (var id in accepted)
                Assert.False(await cache.TryAddAsync(id, expires, Ct), id + " accepted twice");

            var extra = new List<bool>();
            for (var i = 0; i < cap; i++)
                extra.Add(await cache.TryAddAsync("extra-" + i, expires, Ct));
            Assert.Equal(cap, accepted.Count + extra.Count(e => e));
        }

        [Fact]
        public async Task ExpiredKeyManyThreads_OneWins_Test()
        {
            var time = TestClock.CreateFake();
            var cache = new InMemorySamlReplayCache(time, 100, 1000);
            Assert.True(await cache.TryAddAsync("key", time.GetUtcNow().AddMinutes(1), Ct));
            time.Advance(TimeSpan.FromMinutes(2));
            var expires = time.GetUtcNow().AddHours(1);

            var results = await RunConcurrently(Workers, _ => cache.TryAddAsync("key", expires, CancellationToken.None));

            Assert.Equal(1, results.Count(r => r));
        }

        [Fact]
        public async Task MixedLoadWithPurges_NoDuplicateAccepted_Test()
        {
            var time = TestClock.CreateFake();
            var cache = new InMemorySamlReplayCache(time, 200, 5);
            var accepted = new ConcurrentDictionary<string, int>(StringComparer.Ordinal);

            var results = await RunConcurrently(Workers, async worker =>
            {
                for (var i = 0; i < 300; i++)
                {
                    var key = "k-" + (i % 120);
                    var expiresAt = time.GetUtcNow().AddSeconds(i % 3 == 0 ? -1 : 3600);
                    if (await cache.TryAddAsync(key, expiresAt, CancellationToken.None) && expiresAt > time.GetUtcNow())
                        accepted.AddOrUpdate(key, 1, (_, n) => n + 1);
                }

                return true;
            });

            Assert.All(results, Assert.True);
            Assert.All(accepted, pair => Assert.Equal(1, pair.Value));
        }

        public static TheoryData<string, bool> CandidateSets => new TheoryData<string, bool>
        {
            { "collection-wrong+single-idp", true },
            { "collection-null+single-idp", true },
            { "collection-empty+single-idp", true },
            { "collection-idp+single-idp", true },
            { "collection-wrong+single-wrong", false },
            { "collection-empty+single-null", false }
        };

        private static (X509Certificate2Collection Collection, X509Certificate2 Single) Candidates(string name)
        {
            var idp = TestCertificates.PublicOnly(TestCertificates.Idp);
            var wrong = TestCertificates.PublicOnly(TestCertificates.WrongKey);
            switch (name)
            {
                case "collection-wrong+single-idp": return (TestCertificates.Collection(TestCertificates.WrongKey), idp);
                case "collection-null+single-idp": return (null, idp);
                case "collection-empty+single-idp": return (new X509Certificate2Collection(), idp);
                case "collection-idp+single-idp": return (TestCertificates.Collection(TestCertificates.Idp), idp);
                case "collection-wrong+single-wrong": return (TestCertificates.Collection(TestCertificates.WrongKey), wrong);
                case "collection-empty+single-null": return (new X509Certificate2Collection(), null);
                default: throw new ArgumentOutOfRangeException(nameof(name));
            }
        }

        [Theory]
        [MemberData(nameof(CandidateSets))]
        public void Verifier_AllLoaders_SingleAndCollectionCerts_Test(string candidateSet, bool expectedAccepted)
        {
            var settings = new MPassTestSettings();
            var now = TestClock.Epoch;
            var requestId = NewRequestId();
            var (collection, single) = Candidates(candidateSet);
            var collectionCountBefore = collection?.Count ?? -1;

            var login = SamlMessageLoadAndVerifyHelper.LoadAndVerifyLoginResponse(new LoadAndVerifyLoginResponseRequest
            {
                SamlResponse = FixtureSigner.SignToBase64(SamlFixtureBuilder.Build(SamlFixtures.LoginResponse(settings, now, requestId))),
                IdpCertificate = single,
                IdpCertificates = collection,
                ExpectedDestination = settings.SamlServiceLoginDestination,
                ExpectedAudience = settings.SamlRequestIssuer,
                ExpectedIssuer = settings.IdentityProviderIssuer,
                ExpectedRequestId = requestId,
                TimeOut = Timeout,
                ClockSkew = Skew,
                CurrentUtc = now.UtcDateTime
            });
            var logoutResponse = SamlMessageLoadAndVerifyHelper.LoadAndVerifyLogoutResponse(new LoadAndVerifyLogoutResponseRequest
            {
                SamlResponse = FixtureSigner.SignToBase64(SamlFixtureBuilder.Build(SamlFixtures.LogoutResponse(settings, now, requestId))),
                IdpCertificate = single,
                IdpCertificates = collection,
                ExpectedDestination = settings.SamlServiceLogoutDestination,
                ExpectedIssuer = settings.IdentityProviderIssuer,
                ExpectedRequestId = requestId,
                TimeOut = Timeout,
                ClockSkew = Skew,
                CurrentUtc = now.UtcDateTime
            });
            var logoutRequest = SamlMessageLoadAndVerifyHelper.LoadAndVerifyLogoutRequest(new LoadAndVerifyLogoutRequestRequest
            {
                SamlRequest = FixtureSigner.SignToBase64(SamlFixtureBuilder.Build(SamlFixtures.LogoutRequest(settings, now))),
                IdpCertificate = single,
                IdpCertificates = collection,
                ExpectedDestination = settings.SamlServiceSingleLogoutDestination,
                ExpectedIssuer = settings.IdentityProviderIssuer,
                ExpectedNameId = SamlFixtures.DefaultNameId,
                ExpectedSessionIndex = DefaultLogoutSessionIndex,
                TimeOut = Timeout,
                ClockSkew = Skew,
                CurrentUtc = now.UtcDateTime
            });

            foreach (var result in new IResult[] { login, logoutResponse, logoutRequest })
            {
                if (expectedAccepted)
                    AssertAccepted(result);
                else
                    AssertRejected(result);
            }

            Assert.Equal(collectionCountBefore, collection?.Count ?? -1);
        }

        [Fact]
        public async Task LoginResponse_StatusMarkup_Stripped_Test()
        {
            using var context = ServiceFactory.Create();
            var requestId = NewRequestId();
            var fixture = context.NewLoginResponse(requestId);
            fixture.Assertions.Clear();
            fixture.StatusCode = "urn:test:<bad>&\"'code";
            fixture.StatusMessage = "a<b>c&d\"e'f\t\ng-marker";

            var result = await SubmitLoginAsync(context, context.SignedBase64(fixture), requestId);

            AssertRejectedWith(result, string.Format(SamlLoadValidationMessages.InvalidSamlResponseStatusCode, "urn:test:badcode", "abcdefg-marker"));
            AssertOnlyFixedMessages(result);
        }

        [Fact]
        public async Task LogoutResponse_StatusMarkup_StrippedCapped256_Test()
        {
            using var context = ServiceFactory.Create();
            var requestId = NewRequestId();
            var fixture = context.NewLogoutResponse(requestId);
            fixture.StatusCode = SamlNs.StatusResponder;
            var raw = string.Concat(Enumerable.Repeat("<i>x&amp;'\"</i>", 60)) + "TAIL-NOT-REACHED";
            fixture.StatusMessage = raw;

            var result = await SubmitLogoutResponseAsync(context, context.SignedBase64(fixture), requestId);

            AssertRejected(result);
            var filtered = new string(raw.Where(ch => "<>&\"'".IndexOf(ch) < 0 && !char.IsControl(ch)).ToArray());
            var expectedPart = filtered.Substring(0, 256);
            AssertRejectedWith(result, string.Format(SamlLoadValidationMessages.InvalidSamlResponseStatusCode, SamlNs.StatusResponder, expectedPart));
            Assert.DoesNotContain(MessageTexts(result), t => t.Contains("TAIL-NOT-REACHED", StringComparison.Ordinal));
        }
    }
}
