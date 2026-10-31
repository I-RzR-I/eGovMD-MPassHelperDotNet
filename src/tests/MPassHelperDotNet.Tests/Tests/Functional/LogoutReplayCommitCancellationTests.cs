using System;
using System.Threading;
using System.Threading.Tasks;
using Microsoft.Extensions.DependencyInjection;
using MPassHelperDotNet.Abstractions.Services.Replay;
using MPassHelperDotNet.Helpers;
using MPassHelperDotNet.Helpers.Messages;
using MPassHelperDotNet.Models.Dto.AuthService.LogoutResponse;
using MPassHelperDotNet.Models.Dto.RequestBuilder.LogOutResponse;
using MPassHelperDotNet.Tests.Helpers.Fakes;
using MPassHelperDotNet.Tests.Helpers.Hosting;
using MPassHelperDotNet.Tests.Helpers.Kits;
using MPassHelperDotNet.Tests.Helpers.Runtime;
using MPassHelperDotNet.Tests.Helpers.Saml;
using Xunit;

namespace MPassHelperDotNet.Tests.Tests.Functional
{
    [Trait(TestAreas.Trait, TestAreas.Functional)]
    public class LogoutReplayCommitCancellationTests
    {
        private const string SessionIndex = "_session-functional-commit";

        [Fact]
        public async Task ValidateLogout_CancelInCommit_Commits_Test()
        {
            using var cts = new CancellationTokenSource();
            var cache = new ConfigurableRecordingReplayCache { OnAdd = () => cts.Cancel() };
            using var context = ServiceFactory.Create(configureAfter: s => s.AddSingleton<ISamlReplayCache>(cache));
            var requestId = FunctionalTestKit.NewRequestId();
            var fixture = context.NewLogoutResponse(requestId);
            var dto = new ValidateLogoutResponseDto
            {
                SamlResponse = context.SignedBase64(fixture),
                LogOutRequestId = requestId
            };

            var result = await context.Auth.ValidateLogoutResponseAsync(dto, cts.Token);

            Assert.True(cts.IsCancellationRequested);
            FunctionalTestKit.AssertSuccess(result);
            Assert.Equal(new[] { DefaultStaticInfo.ReplayKeyLogoutResponse + fixture.Id }, cache.Keys);
            Assert.Single(cache.Tokens);
            Assert.All(cache.Tokens, token => Assert.False(token.CanBeCanceled));
        }

        [Fact]
        public async Task ValidateLogout_CancelInCommit_ReuseFails_Test()
        {
            using var cts = new CancellationTokenSource();
            var cache = new ConfigurableRecordingReplayCache { OnAdd = () => cts.Cancel() };
            using var context = ServiceFactory.Create(configureAfter: s => s.AddSingleton<ISamlReplayCache>(cache));
            var requestId = FunctionalTestKit.NewRequestId();
            var dto = new ValidateLogoutResponseDto
            {
                SamlResponse = context.SignedBase64(context.NewLogoutResponse(requestId)),
                LogOutRequestId = requestId
            };
            await context.Auth.ValidateLogoutResponseAsync(dto, cts.Token);
            cache.OnAdd = null;

            var replay = await context.Auth.ValidateLogoutResponseAsync(dto, TestContext.Current.CancellationToken);

            FunctionalTestKit.AssertFailureWith(replay, SamlLoadValidationMessages.SamlReplayDetected);
        }

        [Fact]
        public async Task ValidateLogout_CancelEarly_NoConsume_Test()
        {
            var cache = new ConfigurableRecordingReplayCache();
            var time = new ArmedTimeProvider(TestClock.Epoch);
            using var context = ServiceFactory.Create(time: time, configureAfter: s => s.AddSingleton<ISamlReplayCache>(cache));
            var requestId = FunctionalTestKit.NewRequestId();
            var fixture = context.NewLogoutResponse(requestId);
            var dto = new ValidateLogoutResponseDto
            {
                SamlResponse = context.SignedBase64(fixture),
                LogOutRequestId = requestId
            };
            var auth = context.Auth;
            using var cts = new CancellationTokenSource();
            time.Arm(() => cts.Cancel());

            await Assert.ThrowsAnyAsync<OperationCanceledException>(() => auth.ValidateLogoutResponseAsync(dto, cts.Token));

            Assert.True(time.Fired, "The clock hook did not run inside the call.");
            Assert.Empty(cache.Keys);
            Assert.Empty(cache.Tokens);
            
            var retry = await auth.ValidateLogoutResponseAsync(dto, TestContext.Current.CancellationToken);
            FunctionalTestKit.AssertSuccess(retry);
            Assert.Equal(new[] { DefaultStaticInfo.ReplayKeyLogoutResponse + fixture.Id }, cache.Keys);
        }

        [Fact]
        public async Task BuildLogoutResponse_CancelInCommit_Commits_Test()
        {
            using var cts = new CancellationTokenSource();
            var cache = new ConfigurableRecordingReplayCache { OnAdd = () => cts.Cancel() };
            using var context = ServiceFactory.Create(configureAfter: s => s.AddSingleton<ISamlReplayCache>(cache));
            var fixture = context.NewLogoutRequest(SamlFixtures.DefaultNameId, SessionIndex);
            var dto = NewBuildDto(context.SignedBase64(fixture));

            var result = await context.Builder.BuildLogOutResponseAsync(dto, cts.Token);

            Assert.True(cts.IsCancellationRequested);
            FunctionalTestKit.AssertSuccess(result);
            Assert.False(string.IsNullOrEmpty(result.Response.HtmlAuthDocument));
            Assert.Matches(FunctionalTestKit.RequestIdPattern, result.Response.LogoutResponseId);
            Assert.Equal(new[] { DefaultStaticInfo.ReplayKeyLogoutRequest + fixture.Id }, cache.Keys);
            Assert.Single(cache.Tokens);
            Assert.All(cache.Tokens, token => Assert.False(token.CanBeCanceled));
        }

        [Fact]
        public async Task BuildLogoutResponse_CancelInCommit_ReuseFails_Test()
        {
            using var cts = new CancellationTokenSource();
            var cache = new ConfigurableRecordingReplayCache { OnAdd = () => cts.Cancel() };
            using var context = ServiceFactory.Create(configureAfter: s => s.AddSingleton<ISamlReplayCache>(cache));
            var dto = NewBuildDto(context.SignedBase64(context.NewLogoutRequest(SamlFixtures.DefaultNameId, SessionIndex)));
            await context.Builder.BuildLogOutResponseAsync(dto, cts.Token);
            cache.OnAdd = null;

            var replay = await context.Builder.BuildLogOutResponseAsync(dto, TestContext.Current.CancellationToken);

            FunctionalTestKit.AssertFailureWith(replay, SamlLoadValidationMessages.SamlReplayDetected);
            Assert.Null(replay.Response);
        }

        [Fact]
        public async Task BuildLogoutResponse_CancelEarly_NoConsume_Test()
        {
            var cache = new ConfigurableRecordingReplayCache();
            var time = new ArmedTimeProvider(TestClock.Epoch);
            using var context = ServiceFactory.Create(time: time, configureAfter: s => s.AddSingleton<ISamlReplayCache>(cache));
            var fixture = context.NewLogoutRequest(SamlFixtures.DefaultNameId, SessionIndex);
            var dto = NewBuildDto(context.SignedBase64(fixture));
            var builder = context.Builder;
            using var cts = new CancellationTokenSource();
            time.Arm(() => cts.Cancel());

            await Assert.ThrowsAnyAsync<OperationCanceledException>(() => builder.BuildLogOutResponseAsync(dto, cts.Token));

            Assert.True(time.Fired, "The clock hook did not run inside the call.");
            Assert.Empty(cache.Keys);
            Assert.Empty(cache.Tokens);
            
            var retry = await builder.BuildLogOutResponseAsync(dto, TestContext.Current.CancellationToken);
            FunctionalTestKit.AssertSuccess(retry);
            Assert.Equal(new[] { DefaultStaticInfo.ReplayKeyLogoutRequest + fixture.Id }, cache.Keys);
        }

        private static BuildLogOutResponseDto NewBuildDto(string samlRequest) => new BuildLogOutResponseDto
        {
            SamlRequest = samlRequest,
            RelayState = "rs",
            UserIdentifierId = SamlFixtures.DefaultNameId,
            UserSessionIndexId = SessionIndex
        };
    }
}
