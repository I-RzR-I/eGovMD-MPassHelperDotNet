using System;
using System.Linq;
using System.Net.Mime;
using System.Security.Claims;
using System.Threading;
using System.Threading.Tasks;
using Microsoft.AspNetCore.Antiforgery;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authentication.Cookies;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Mvc;
using Microsoft.Extensions.Logging;
using MPassHelperDotNet.Abstractions.Services;
using MPassHelperDotNet.Models.Dto.AuthService.ExternalLogoutRequest;
using MPassHelperDotNet.Models.Dto.AuthService.LoginRequest;
using MPassHelperDotNet.Models.Dto.AuthService.LoginResponse;
using MPassHelperDotNet.Models.Dto.AuthService.LogoutRequest;
using MPassHelperDotNet.Models.Dto.AuthService.LogoutResponse;
using WebApplicationSample.Infrastructure;
using WebApplicationSample.Models;
using WebApplicationSample.Services;
using MPassResult = RzR.ResultMessage.Abstractions.IResult;

namespace WebApplicationSample.Controllers
{
    [Route("account")]
    public sealed class AccountController : ControllerBase
    {
        private const string HtmlContentType = "text/html; charset=utf-8";
        private const string HomeUrl = "/";

        private const string LoginRelayState = "login";
        private const string LogoutRelayState = "logout";

        private readonly IAuthMPassService _authMPassService;
        private readonly SamlRequestStateStore _requestStateStore;
        private readonly SamlSessionRegistry _sessionRegistry;
        private readonly IAntiforgery _antiforgery;
        private readonly ILogger<AccountController> _logger;

        public AccountController(IAuthMPassService authMPassService, SamlRequestStateStore requestStateStore,
            SamlSessionRegistry sessionRegistry, IAntiforgery antiforgery, ILogger<AccountController> logger)
        {
            _authMPassService = authMPassService;
            _requestStateStore = requestStateStore;
            _sessionRegistry = sessionRegistry;
            _antiforgery = antiforgery;
            _logger = logger;
        }

        [HttpGet("login")]
        public async Task<IActionResult> Login([FromQuery] string? returnUrl, CancellationToken cancellationToken)
        {
            var localReturnUrl = Url.IsLocalUrl(returnUrl) ? returnUrl! : HomeUrl;

            var authRequest = await _authMPassService.GenerateAuthRequestAsync(
                new GenerateAuthRequestDto { RelayState = LoginRelayState },
                cancellationToken);
            if (!authRequest.IsSuccess)
            {
                LogRejected("login request", authRequest);

                return Problem(statusCode: StatusCodes.Status500InternalServerError, detail: "MPass sign-in could not be started.");
            }

            await _requestStateStore.SaveAsync(
                Response,
                SamlFlow.Login,
                new PendingSamlRequest(authRequest.Response.AuthRequestId, localReturnUrl),
                cancellationToken);

            return SamlForm(authRequest.Response.HtmlDocument);
        }

        [HttpPost("acs")]
        [Consumes(MediaTypeNames.Application.FormUrlEncoded)]
        public async Task<IActionResult> AssertionConsumer(
            [FromForm(Name = "SAMLResponse")] string? samlResponse,
            [FromForm(Name = "RelayState")] string? relayState,
            CancellationToken cancellationToken)
        {
            var pending = await _requestStateStore.TakeAsync(HttpContext, SamlFlow.Login, cancellationToken);
            if (pending is null)
            {
                SampleLog.PendingRequestMissing(_logger, "login response");

                return Problem(statusCode: StatusCodes.Status400BadRequest, detail: "No MPass sign-in is pending for this browser.");
            }

            if (string.IsNullOrEmpty(samlResponse) || !string.Equals(relayState, LoginRelayState, StringComparison.Ordinal))
                return Problem(statusCode: StatusCodes.Status400BadRequest, detail: "The MPass response is incomplete.");

            var userData = await _authMPassService.GetUserDataFromAuthResponseAsync(
                new GetUserDataFromAuthResponseDto
                {
                    SamlResponse = samlResponse,
                    AuthRequestId = pending.RequestId
                },
                cancellationToken);

            var nameId = userData.Response?.UserInfo?.Idnp;
            var sessionIndex = userData.Response?.SessionIndexId;
            if (!userData.IsSuccess || string.IsNullOrEmpty(nameId) || string.IsNullOrEmpty(sessionIndex))
            {
                LogRejected("login response", userData);

                return Problem(statusCode: StatusCodes.Status401Unauthorized, detail: "MPass sign-in could not be verified.");
            }

            var sessionId = await _sessionRegistry.CreateAsync(Response, new SamlSession(nameId, sessionIndex), cancellationToken);

            var identity = new ClaimsIdentity(
                new[] { new Claim(ClaimTypes.Sid, sessionId) },
                CookieAuthenticationDefaults.AuthenticationScheme);
            await HttpContext.SignInAsync(CookieAuthenticationDefaults.AuthenticationScheme, new ClaimsPrincipal(identity));
            SampleLog.SignedIn(_logger);

            return LocalRedirect(pending.ReturnUrl);
        }

        [HttpPost("logout")]
        public async Task<IActionResult> Logout(CancellationToken cancellationToken)
        {
            if (!await _antiforgery.IsRequestValidAsync(HttpContext))
                return Problem(statusCode: StatusCodes.Status400BadRequest, detail: "The sign-out form has expired. Reload the page and try again.");

            var sessionId = User.FindFirstValue(ClaimTypes.Sid);
            var session = await _sessionRegistry.GetAsync(sessionId, cancellationToken);

            await _sessionRegistry.EndAsync(Response, sessionId, cancellationToken);
            await HttpContext.SignOutAsync(CookieAuthenticationDefaults.AuthenticationScheme);
            if (session is null)
                return LocalRedirect(HomeUrl);

            SampleLog.SessionEnded(_logger, "SP");
            var logoutRequest = await _authMPassService.GenerateLogoutRequestAsync(
                new GenerateLogOutRequestDto
                {
                    RelayState = LogoutRelayState,
                    UserIdentifierId = session.NameId,
                    SessionIndexId = session.SessionIndex
                },
                cancellationToken);
            if (!logoutRequest.IsSuccess)
            {
                LogRejected("logout request", logoutRequest);

                return LocalRedirect(HomeUrl);
            }

            await _requestStateStore.SaveAsync(
                Response,
                SamlFlow.Logout,
                new PendingSamlRequest(logoutRequest.Response.LogOutRequestId, HomeUrl),
                cancellationToken);

            return SamlForm(logoutRequest.Response.HtmlDocument);
        }

        [HttpPost("logout-callback")]
        [Consumes(MediaTypeNames.Application.FormUrlEncoded)]
        public async Task<IActionResult> LogoutCallback(
            [FromForm(Name = "SAMLResponse")] string? samlResponse,
            [FromForm(Name = "RelayState")] string? relayState,
            CancellationToken cancellationToken)
        {
            var pending = await _requestStateStore.TakeAsync(HttpContext, SamlFlow.Logout, cancellationToken);
            if (pending is null)
            {
                SampleLog.PendingRequestMissing(_logger, "logout response");

                return Problem(statusCode: StatusCodes.Status400BadRequest, detail: "No MPass logout is pending for this browser.");
            }

            if (string.IsNullOrEmpty(samlResponse) || !string.Equals(relayState, LogoutRelayState, StringComparison.Ordinal))
                return Problem(statusCode: StatusCodes.Status400BadRequest, detail: "The MPass response is incomplete.");

            var validation = await _authMPassService.ValidateLogoutResponseAsync(
                new ValidateLogoutResponseDto
                {
                    SamlResponse = samlResponse,
                    LogOutRequestId = pending.RequestId
                },
                cancellationToken);
            if (!validation.IsSuccess)
            {
                LogRejected("logout response", validation);

                return Problem(
                    statusCode: StatusCodes.Status400BadRequest,
                    detail: "You are signed out of this application, but the MPass logout response could not be verified.");
            }

            return LocalRedirect(pending.ReturnUrl);
        }

        [HttpPost("slo")]
        [Consumes(MediaTypeNames.Application.FormUrlEncoded)]
        public async Task<IActionResult> SingleLogout(
            [FromForm(Name = "SAMLRequest")] string? samlRequest,
            [FromForm(Name = "RelayState")] string? relayState,
            CancellationToken cancellationToken)
        {
            if (string.IsNullOrEmpty(samlRequest))
                return Problem(statusCode: StatusCodes.Status400BadRequest, detail: "The MPass request is incomplete.");

            var sessionId = _sessionRegistry.GetLogoutStateSessionId(Request);
            var session = await _sessionRegistry.GetAsync(sessionId, cancellationToken);
            if (session is null)
            {
                SampleLog.SingleLogoutSessionMissing(_logger);

                return Problem(statusCode: StatusCodes.Status400BadRequest, detail: "No active session was found for this MPass logout request.");
            }

            var logoutResponse = await _authMPassService.ProcessExternalLogoutRequestAsync(
                new ProcessExternalLogoutRequestDto
                {
                    SamlRequest = samlRequest,
                    RelayState = relayState,
                    UserIdentifierId = session.NameId,
                    SessionIndexId = session.SessionIndex
                },
                cancellationToken);
            if (!logoutResponse.IsSuccess)
            {
                LogRejected("single logout request", logoutResponse);

                return Problem(statusCode: StatusCodes.Status400BadRequest, detail: "The MPass logout request could not be verified.");
            }

            await _sessionRegistry.EndAsync(Response, sessionId, cancellationToken);
            SampleLog.SessionEnded(_logger, "IdP");

            return SamlForm(logoutResponse.Response.HtmlDocument);
        }

        private ContentResult SamlForm(string htmlDocument)
        {
            Response.Headers.CacheControl = "no-store";

            return Content(htmlDocument, HtmlContentType);
        }

        private void LogRejected(string operation, MPassResult result)
        {
            var reasons = result.Messages is null
                ? string.Empty
                : string.Join("; ", result.Messages.Select(message => message.Message));
            SampleLog.OperationRejected(_logger, operation, reasons);
        }
    }
}
