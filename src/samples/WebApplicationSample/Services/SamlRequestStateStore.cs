using System;
using System.Text.Json;
using System.Threading;
using System.Threading.Tasks;
using Microsoft.AspNetCore.Http;
using Microsoft.Extensions.Caching.Distributed;
using Microsoft.Extensions.Configuration;
using WebApplicationSample.Infrastructure;
using WebApplicationSample.Models;

namespace WebApplicationSample.Services
{
    public sealed class SamlRequestStateStore
    {
        private const string CacheKeyPrefix = "mpass:pending:";

        internal const string LifetimeSettingKey = "MPassSample:PendingRequestLifetime";

        private static readonly TimeSpan DefaultLifetime = TimeSpan.FromMinutes(30);

        private readonly IDistributedCache _cache;
        private readonly TimeSpan _lifetime;

        public SamlRequestStateStore(IDistributedCache cache, IConfiguration configuration)
        {
            _cache = cache;
            _lifetime = configuration.GetValue(LifetimeSettingKey, DefaultLifetime);
            if (_lifetime <= TimeSpan.Zero)
                throw new InvalidOperationException($"{LifetimeSettingKey} must be greater than 0.");
        }

        public async Task SaveAsync(HttpResponse response, SamlFlow flow,
            PendingSamlRequest request, CancellationToken cancellationToken = default)
        {
            var key = OpaqueKey.Create();
            await _cache.SetAsync(
                CacheKey(flow, key),
                JsonSerializer.SerializeToUtf8Bytes(request),
                new DistributedCacheEntryOptions { AbsoluteExpirationRelativeToNow = _lifetime },
                cancellationToken);

            response.Cookies.Append(CookieName(flow), key, CrossSiteCookie.Create(_lifetime));
        }

        public async Task<PendingSamlRequest?> TakeAsync(HttpContext context,
            SamlFlow flow, CancellationToken cancellationToken = default)
        {
            var cookieName = CookieName(flow);
            var key = context.Request.Cookies[cookieName];
            CrossSiteCookie.Delete(context.Response, cookieName);
            if (!OpaqueKey.IsWellFormed(key))
                return null;

            var cacheKey = CacheKey(flow, key!);
            var payload = await _cache.GetAsync(cacheKey, cancellationToken);
            if (payload is null)
                return null;

            await _cache.RemoveAsync(cacheKey, cancellationToken);

            return JsonSerializer.Deserialize<PendingSamlRequest>(payload);
        }

        private static string CookieName(SamlFlow flow) => flow switch
        {
            SamlFlow.Login => "__Host-MPass.Login",
            SamlFlow.Logout => "__Host-MPass.Logout",
            _ => throw new ArgumentOutOfRangeException(nameof(flow), flow, null)
        };

        private static string CacheKey(SamlFlow flow, string key) => CacheKeyPrefix + CookieName(flow) + ":" + key;
    }
}
