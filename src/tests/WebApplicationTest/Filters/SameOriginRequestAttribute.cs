using System;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Mvc.Filters;

namespace WebApplicationTest.Filters
{
    [AttributeUsage(AttributeTargets.Class | AttributeTargets.Method)]
    public sealed class SameOriginRequestAttribute : Attribute, IAuthorizationFilter
    {
        private const string SecFetchSiteHeader = "Sec-Fetch-Site";
        private const string SameOriginSite = "same-origin";
        private const string UserInitiatedSite = "none";

        public void OnAuthorization(AuthorizationFilterContext context)
        {
            if (!IsSameOrigin(context.HttpContext.Request))
                context.Result = new StatusCodeResult(StatusCodes.Status403Forbidden);
        }

        private static bool IsSameOrigin(HttpRequest request)
        {
            if (request.Headers.TryGetValue(SecFetchSiteHeader, out var fetchSite))
                return fetchSite.Count == 1
                       && (string.Equals(fetchSite[0], SameOriginSite, StringComparison.Ordinal)
                           || string.Equals(fetchSite[0], UserInitiatedSite, StringComparison.Ordinal));

            var origin = request.Headers.Origin;

            return origin.Count == 1
                   && string.Equals(origin[0], $"{request.Scheme}://{request.Host.Value}", StringComparison.OrdinalIgnoreCase);
        }
    }
}
