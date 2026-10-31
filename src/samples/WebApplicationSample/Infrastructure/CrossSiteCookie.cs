using System;
using Microsoft.AspNetCore.Http;

namespace WebApplicationSample.Infrastructure
{
    public static class CrossSiteCookie
    {
        public static CookieOptions Create(TimeSpan lifetime) => new CookieOptions
        {
            HttpOnly = true,
            Secure = true,
            SameSite = SameSiteMode.None,
            Path = "/",
            IsEssential = true,
            MaxAge = lifetime
        };

        public static void Delete(HttpResponse response, string name) =>
            response.Cookies.Delete(name, Create(TimeSpan.Zero));
    }
}
