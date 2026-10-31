using System;
using System.Threading;
using System.Threading.Tasks;
using RzR.ResultMessage.Web;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Mvc;
using MPassHelperDotNet.Abstractions.Services;
using MPassHelperDotNet.Models.Dto.AuthService.ExternalLogoutRequest;
using MPassHelperDotNet.Models.Dto.AuthService.LoginRequest;
using MPassHelperDotNet.Models.Dto.AuthService.LoginResponse;
using MPassHelperDotNet.Models.Dto.AuthService.LogoutRequest;
using MPassHelperDotNet.Models.Dto.AuthService.LogoutResponse;
using WebApplicationTest.Filters;

namespace WebApplicationTest.Controllers
{
    [ApiController]
    [Route("api/[controller]/[action]")]
    [Produces("application/json")]
    public class AuthController : ResultBaseApiController
    {
        private const string FormContentType = "application/x-www-form-urlencoded";
        private const string HtmlContentType = "text/html";

        private const string LoginRelayState = "login";
        private const string LogoutRelayState = "logout";

        private const string AuthRequestIdSessionKey = "MPass.AuthRequestId";
        private const string LogOutRequestIdSessionKey = "MPass.LogOutRequestId";
        private const string NameIdSessionKey = "MPass.NameId";
        private const string SessionIndexSessionKey = "MPass.SessionIndex";

        private readonly IAuthMPassService _authMPassService;

        public AuthController(IAuthMPassService authMPassService)
        {
            _authMPassService = authMPassService;
        }

        [HttpGet]
        public async Task<IActionResult> PingService(CancellationToken cancellationToken = default)
        {
            var ping = await _authMPassService.PingAsync(cancellationToken);

            return Ok(new { isSuccess = ping.IsSuccess && ping.Response?.IsSuccess == true });
        }

        [HttpPost]
        [SameOriginRequest]
        [ProducesResponseType(typeof(string), StatusCodes.Status200OK, HtmlContentType)]
        [ProducesResponseType(StatusCodes.Status403Forbidden)]
        public async Task<IActionResult> GenerateAuthRequest(CancellationToken cancellationToken = default)
        {
            var authRequest = await _authMPassService.GenerateAuthRequestAsync(new GenerateAuthRequestDto
            {
                RelayState = LoginRelayState
            }, cancellationToken);
            if (!authRequest.IsSuccess)
                return JsonResult(authRequest);

            HttpContext.Session.SetString(AuthRequestIdSessionKey, authRequest.Response.AuthRequestId);

            return AutoPostForm(authRequest.Response.HtmlDocument);
        }

        [HttpPost]
        [Consumes(FormContentType)]
        public async Task<IActionResult> GetUserAuthInfo(
            [FromForm(Name = "SAMLResponse")] string samlResponse,
            [FromForm(Name = "RelayState")] string relayState,
            CancellationToken cancellationToken = default)
        {
            var authRequestId = TakeSessionValue(AuthRequestIdSessionKey);
            if (string.IsNullOrEmpty(authRequestId) || !string.Equals(relayState, LoginRelayState, StringComparison.Ordinal))
                return BadRequest(new { authenticated = false });

            var userData = await _authMPassService
                .GetUserDataFromAuthResponseAsync(new GetUserDataFromAuthResponseDto
                    {
                        AuthRequestId = authRequestId,
                        SamlResponse = samlResponse
                    },
                    cancellationToken);
            var nameId = userData.Response?.UserInfo?.Idnp;
            var sessionIndex = userData.Response?.SessionIndexId;
            if (!userData.IsSuccess || string.IsNullOrEmpty(nameId) || string.IsNullOrEmpty(sessionIndex))
                return StatusCode(StatusCodes.Status401Unauthorized, new { authenticated = false });

            HttpContext.Session.SetString(NameIdSessionKey, nameId);
            HttpContext.Session.SetString(SessionIndexSessionKey, sessionIndex);

            return Ok(new { authenticated = true });
        }

        [HttpPost]
        [SameOriginRequest]
        [ProducesResponseType(typeof(string), StatusCodes.Status200OK, HtmlContentType)]
        [ProducesResponseType(StatusCodes.Status403Forbidden)]
        public async Task<IActionResult> GenerateLogOutRequest(CancellationToken cancellationToken = default)
        {
            var nameId = HttpContext.Session.GetString(NameIdSessionKey);
            var sessionIndex = HttpContext.Session.GetString(SessionIndexSessionKey);
            if (string.IsNullOrEmpty(nameId) || string.IsNullOrEmpty(sessionIndex))
                return BadRequest(new { loggedOut = false });

            var logoutRequest = await _authMPassService
                .GenerateLogoutRequestAsync(new GenerateLogOutRequestDto
                    {
                        RelayState = LogoutRelayState,
                        UserIdentifierId = nameId,
                        SessionIndexId = sessionIndex
                    },
                    cancellationToken);
            if (!logoutRequest.IsSuccess)
                return JsonResult(logoutRequest);

            HttpContext.Session.SetString(LogOutRequestIdSessionKey, logoutRequest.Response.LogOutRequestId);

            return AutoPostForm(logoutRequest.Response.HtmlDocument);
        }

        [HttpPost]
        [Consumes(FormContentType)]
        public async Task<IActionResult> ValidateLogoutResponse(
            [FromForm(Name = "SAMLResponse")] string samlResponse,
            [FromForm(Name = "RelayState")] string relayState,
            CancellationToken cancellationToken = default)
        {
            var logOutRequestId = TakeSessionValue(LogOutRequestIdSessionKey);
            if (string.IsNullOrEmpty(logOutRequestId) || !string.Equals(relayState, LogoutRelayState, StringComparison.Ordinal))
                return BadRequest(new { loggedOut = false });

            var validation = await _authMPassService
                .ValidateLogoutResponseAsync(new ValidateLogoutResponseDto
                    {
                        SamlResponse = samlResponse,
                        LogOutRequestId = logOutRequestId
                    },
                    cancellationToken);
            if (!validation.IsSuccess)
                return BadRequest(new { loggedOut = false });

            HttpContext.Session.Clear();

            return Ok(new { loggedOut = true });
        }

        [HttpPost]
        [Consumes(FormContentType)]
        [ProducesResponseType(typeof(string), StatusCodes.Status200OK, HtmlContentType)]
        public async Task<IActionResult> ProcessExternalLogoutRequest(
            [FromForm(Name = "SAMLRequest")] string samlRequest,
            [FromForm(Name = "RelayState")] string relayState,
            CancellationToken cancellationToken = default)
        {
            var nameId = HttpContext.Session.GetString(NameIdSessionKey);
            var sessionIndex = HttpContext.Session.GetString(SessionIndexSessionKey);
            if (string.IsNullOrEmpty(nameId) || string.IsNullOrEmpty(sessionIndex))
                return BadRequest(new { loggedOut = false });

            var logoutResponse = await _authMPassService
                .ProcessExternalLogoutRequestAsync(new ProcessExternalLogoutRequestDto
                    {
                        UserIdentifierId = nameId,
                        RelayState = relayState,
                        SessionIndexId = sessionIndex,
                        SamlRequest = samlRequest
                    },
                    cancellationToken);
            if (!logoutResponse.IsSuccess)
                return BadRequest(new { loggedOut = false });

            HttpContext.Session.Clear();

            return AutoPostForm(logoutResponse.Response.HtmlDocument);
        }

        private ContentResult AutoPostForm(string htmlDocument)
        {
            Response.Headers.CacheControl = "no-store";

            return Content(htmlDocument, HtmlContentType);
        }

        private string TakeSessionValue(string key)
        {
            var value = HttpContext.Session.GetString(key);
            HttpContext.Session.Remove(key);

            return value;
        }
    }
}
