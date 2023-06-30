// ***********************************************************************
//  Assembly         : RzR.Shared.eGovMD.WebApplicationTest
//  Author           : RzR
//  Created On       : 2023-06-27 07:23
// 
//  Last Modified By : RzR
//  Last Modified On : 2023-06-30 14:07
// ***********************************************************************
//  <copyright file="AuthController.cs" company="">
//   Copyright (c) RzR. All rights reserved.
//  </copyright>
// 
//  <summary>
//  </summary>
// ***********************************************************************

#region U S A G E S

using System.Threading;
using System.Threading.Tasks;
using AggregatedGenericResultMessage.Web;
using Microsoft.AspNetCore.Mvc;
using MPassHelperDotNet.Abstractions.Services;
using MPassHelperDotNet.Models.Dto.AuthService.ExternalLogoutRequest;
using MPassHelperDotNet.Models.Dto.AuthService.LoginRequest;
using MPassHelperDotNet.Models.Dto.AuthService.LoginResponse;
using MPassHelperDotNet.Models.Dto.AuthService.LogoutRequest;
using MPassHelperDotNet.Models.Dto.AuthService.LogoutResponse;

#endregion

namespace WebApplicationTest.Controllers
{
    [ApiController]
    [Route("api/[controller]/[action]")]
    [Consumes("application/json")]
    [Produces("application/json")]
    public class AuthController : ResultBaseApiController
    {
        private readonly IAuthMPassService _authMPassService;

        public AuthController(IAuthMPassService authMPassService)
        {
            _authMPassService = authMPassService;
        }

        [HttpGet]
        public async Task<IActionResult> PingService(CancellationToken cancellationToken = default)
        {
            return JsonResult(await _authMPassService.PingAsync(cancellationToken));
        }

        [HttpPost]
        public async Task<IActionResult> GenerateAuthRequest(CancellationToken cancellationToken = default)
        {
            return JsonResult(
                await _authMPassService.GenerateAuthRequestAsync(new GenerateAuthRequestDto
                {
                    RelayState = "Temp ReplayState"
                }, cancellationToken));
        }

        [HttpPost]
        public async Task<IActionResult> GetUserAuthInfo(string samlResponse, string authRequestId,
            CancellationToken cancellationToken = default)
        {
            return JsonResult(await _authMPassService
                .GetUserDataFromAuthResponseAsync(new GetUserDataFromAuthResponseDto
                    {
                        AuthRequestId = authRequestId,
                        SamlResponse = samlResponse
                    },
                    cancellationToken));
        }

        [HttpPost]
        public async Task<IActionResult> GenerateLogOutRequest(CancellationToken cancellationToken = default)
        {
            return JsonResult(await _authMPassService
                .GenerateLogoutRequestAsync(new GenerateLogOutRequestDto
                    {
                        RelayState = "Temp ReplayState",
                        UserIdentifierId = "0000000000000",
                        SessionIndexId = "00000000-0000-0000-0000-000000000000"
                    },
                    cancellationToken));
        }

        [HttpPost]
        public async Task<IActionResult> ValidateLogoutResponse(string samlResponse, string logoutRequestId,
            CancellationToken cancellationToken = default)
        {
            return JsonResult(await _authMPassService
                .ValidateLogoutResponseAsync(new ValidateLogoutResponseDto
                    {
                        SamlResponse = samlResponse,
                        LogOutRequestId = logoutRequestId
                    },
                    cancellationToken));
        }

        [HttpPost]
        public async Task<IActionResult> ProcessExternalLogoutRequest(string samlRequest,
            CancellationToken cancellationToken = default)
        {
            return JsonResult(await _authMPassService
                .ProcessExternalLogoutRequestAsync(new ProcessExternalLogoutRequestDto
                    {
                        UserIdentifierId = "0000000000000",
                        RelayState = "Temp ReplayState",
                        SessionIndexId = "00000000-0000-0000-0000-000000000000",
                        SamlRequest = samlRequest
                    },
                    cancellationToken));
        }
    }
}