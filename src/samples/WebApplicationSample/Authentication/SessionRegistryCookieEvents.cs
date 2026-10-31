using System.Security.Claims;
using System.Threading.Tasks;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authentication.Cookies;
using WebApplicationSample.Services;

namespace WebApplicationSample.Authentication
{
    public sealed class SessionRegistryCookieEvents : CookieAuthenticationEvents
    {
        private readonly SamlSessionRegistry _sessionRegistry;

        public SessionRegistryCookieEvents(SamlSessionRegistry sessionRegistry)
        {
            _sessionRegistry = sessionRegistry;
        }

        public override async Task ValidatePrincipal(CookieValidatePrincipalContext context)
        {
            var sessionId = context.Principal?.FindFirstValue(ClaimTypes.Sid);
            if (await _sessionRegistry.IsActiveAsync(sessionId, context.HttpContext.RequestAborted))
                return;

            context.RejectPrincipal();
            await context.HttpContext.SignOutAsync(CookieAuthenticationDefaults.AuthenticationScheme);
        }
    }
}
