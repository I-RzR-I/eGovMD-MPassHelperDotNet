using System;
using System.Text.Json;
using System.Threading;
using System.Threading.Tasks;
using Microsoft.AspNetCore.Http;
using Microsoft.Extensions.Caching.Distributed;
using WebApplicationSample.Infrastructure;
using WebApplicationSample.Models;

namespace WebApplicationSample.Services
{
    public sealed class SamlSessionRegistry
    {
        private const string LogoutStateCookieName = "__Host-MPass.Slo";

        public static readonly TimeSpan SessionLifetime = TimeSpan.FromHours(8);

        private const string CacheKeyPrefix = "mpass:session:";

        private readonly IDistributedCache _cache;

        public SamlSessionRegistry(IDistributedCache cache)
        {
            _cache = cache;
        }

        public async Task<string> CreateAsync(HttpResponse response,
            SamlSession session, CancellationToken cancellationToken = default)
        {
            var sessionId = OpaqueKey.Create();
            await _cache.SetAsync(
                CacheKeyPrefix + sessionId,
                JsonSerializer.SerializeToUtf8Bytes(session),
                new DistributedCacheEntryOptions { AbsoluteExpirationRelativeToNow = SessionLifetime },
                cancellationToken);

            response.Cookies.Append(LogoutStateCookieName, sessionId, CrossSiteCookie.Create(SessionLifetime));

            return sessionId;
        }

        public async Task<SamlSession?> GetAsync(string? sessionId, CancellationToken cancellationToken = default)
        {
            if (!OpaqueKey.IsWellFormed(sessionId))
                return null;

            var payload = await _cache.GetAsync(CacheKeyPrefix + sessionId, cancellationToken);

            return payload is null ? null : JsonSerializer.Deserialize<SamlSession>(payload);
        }

        public async Task<bool> IsActiveAsync(string? sessionId, CancellationToken cancellationToken = default) =>
            await GetAsync(sessionId, cancellationToken) is not null;

        public string? GetLogoutStateSessionId(HttpRequest request) => request.Cookies[LogoutStateCookieName];

        public async Task EndAsync(HttpResponse response, string? sessionId, CancellationToken cancellationToken = default)
        {
            CrossSiteCookie.Delete(response, LogoutStateCookieName);
            if (OpaqueKey.IsWellFormed(sessionId))
                await _cache.RemoveAsync(CacheKeyPrefix + sessionId, cancellationToken);
        }
    }
}
