using System.Text.Encodings.Web;
using Microsoft.AspNetCore.Antiforgery;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;

namespace WebApplicationSample.Controllers
{
    [Route("")]
    public sealed class HomeController : ControllerBase
    {
        private const string HtmlContentType = "text/html; charset=utf-8";

        private readonly IAntiforgery _antiforgery;

        public HomeController(IAntiforgery antiforgery)
        {
            _antiforgery = antiforgery;
        }

        [HttpGet("")]
        public ContentResult Index()
        {
            if (User.Identity?.IsAuthenticated != true)
                return Page("<p>You are not signed in.</p>"
                            + "<p><a href=\"/account/login?returnUrl=%2Fprotected\">Sign in with MPass</a></p>");

            var tokens = _antiforgery.GetAndStoreTokens(HttpContext);
            var encoder = HtmlEncoder.Default;

            return Page("<p>You are signed in with MPass.</p>"
                        + "<p><a href=\"/protected\">Protected page</a></p>"
                        + "<form method=\"post\" action=\"/account/logout\">"
                        + $"<input type=\"hidden\" name=\"{encoder.Encode(tokens.FormFieldName)}\" value=\"{encoder.Encode(tokens.RequestToken ?? string.Empty)}\">"
                        + "<button type=\"submit\">Sign out</button>"
                        + "</form>");
        }

        [HttpGet("protected")]
        [Authorize]
        public ContentResult Protected() =>
            Page("<p>This page is visible only after an MPass sign-in.</p><p><a href=\"/\">Home</a></p>");

        private ContentResult Page(string body) => Content(
            "<!DOCTYPE html><html lang=\"en\"><head><meta charset=\"utf-8\"><title>MPass sample</title></head>"
            + "<body><main>" + body + "</main></body></html>",
            HtmlContentType);
    }
}
