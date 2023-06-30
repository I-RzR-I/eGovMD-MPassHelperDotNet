// ***********************************************************************
//  Assembly         : RzR.Shared.eGovMD.MPassHelperDotNet
//  Author           : RzR
//  Created On       : 2023-06-21 23:43
// 
//  Last Modified By : RzR
//  Last Modified On : 2023-06-28 16:26
// ***********************************************************************
//  <copyright file="AuthMPassService.cs" company="">
//   Copyright (c) RzR. All rights reserved.
//  </copyright>
// 
//  <summary>
//  </summary>
// ***********************************************************************

#region U S A G E S

using System;
using System.Diagnostics;
using System.Net.Http;
using System.Threading;
using System.Threading.Tasks;
using AggregatedGenericResultMessage;
using AggregatedGenericResultMessage.Abstractions;
using AggregatedGenericResultMessage.Extensions.Result;
using AggregatedGenericResultMessage.Extensions.Result.Messages;
using DomainCommonExtensions.CommonExtensions;
using DomainCommonExtensions.DataTypeExtensions;
using MPassHelperDotNet.Abstractions.Services;
using MPassHelperDotNet.Helpers;
using MPassHelperDotNet.Helpers.SAML;
using MPassHelperDotNet.Models.Client;
using MPassHelperDotNet.Models.Dto.AuthService.ExternalLogoutRequest;
using MPassHelperDotNet.Models.Dto.AuthService.LoginRequest;
using MPassHelperDotNet.Models.Dto.AuthService.LoginResponse;
using MPassHelperDotNet.Models.Dto.AuthService.LogoutRequest;
using MPassHelperDotNet.Models.Dto.AuthService.LogoutResponse;
using MPassHelperDotNet.Models.Dto.RequestBuilder.LoginRequest;
using MPassHelperDotNet.Models.Dto.RequestBuilder.LogoutRequest;
using MPassHelperDotNet.Models.Dto.RequestBuilder.LogOutResponse;
using MPassHelperDotNet.Models.Internal.Request;

// ReSharper disable ConstantConditionalAccessQualifier

// ReSharper disable ClassNeverInstantiated.Global

#endregion

namespace MPassHelperDotNet.Services
{
    /// <inheritdoc />
    public class AuthMPassService : IAuthMPassService
    {
        /// <summary>
        ///     MPass builder service
        /// </summary>
        private readonly IMPassBuilderService _mPassBuilderService;

        /// <summary>
        ///     MPass SAML option
        /// </summary>
        private readonly MPassSamlOptions _mPassSamlOptions;

        /// <summary>
        ///     Initializes a new instance of the <see cref="MPassHelperDotNet.Services.AuthMPassService" /> class.
        /// </summary>
        /// <param name="mPassBuilderService">MPass communication string builder</param>
        /// <param name="mPassSamlOptions">MPass options</param>
        /// <remarks></remarks>
        public AuthMPassService(IMPassBuilderService mPassBuilderService, MPassSamlOptions mPassSamlOptions)
        {
            _mPassBuilderService = mPassBuilderService;
            _mPassSamlOptions = mPassSamlOptions;
        }

        /// <inheritdoc />
        public async Task<IResult<GenerateAuthRequestResultDto>> GenerateAuthRequestAsync(
            GenerateAuthRequestDto request,
            CancellationToken cancellationToken = default)
        {
            if (request.IsNull())
                return Result<GenerateAuthRequestResultDto>
                    .Failure(string.Format(DefaultMessages.ArgumentNullMessage, nameof(request)));

            if (request.RelayState.IsNullOrEmpty())
                return Result<GenerateAuthRequestResultDto>
                    .Failure(string.Format(DefaultMessages.ArgumentNullMessage, nameof(request.RelayState)));
            try
            {
                var requestBuild = await _mPassBuilderService
                    .BuildLogInRequestAsync(new BuildLogInRequestDto { RelayState = request.RelayState }, cancellationToken);

                if (!requestBuild.IsSuccess)
                    return Result<GenerateAuthRequestResultDto>
                        .Failure()
                        .JoinErrors(new[] { requestBuild.ToBase() });

                return Result<GenerateAuthRequestResultDto>
                    .Success(new GenerateAuthRequestResultDto
                    {
                        HtmlDocument = requestBuild.Response.HtmlAuthDocument,
                        AuthRequestId = requestBuild.Response.AuthRequestId
                    });
            }
            catch (Exception e)
            {
                return Result<GenerateAuthRequestResultDto>.Failure()
                    .AddException(e);
            }
        }

        /// <inheritdoc />
        public async Task<IResult<GetUserDataFromAuthResponseResultDto>>
            GetUserDataFromAuthResponseAsync(
                GetUserDataFromAuthResponseDto request,
                CancellationToken cancellationToken = default)
        {
            try
            {
                //  Validate login response from SAMLResponse
                var verifyLogInResponse = SamlMessageLoadAndVerifyHelper
                    .LoadAndVerifyLoginResponse(new LoadAndVerifyLoginResponseRequest
                    {
                        ExpectedRequestId = request.AuthRequestId,
                        SamlResponse = request.SamlResponse,
                        ExpectedDestination = _mPassSamlOptions.SamlServiceLoginDestination,
                        TimeOut = _mPassSamlOptions.SamlMessageTimeout,
                        ExpectedAudience = _mPassSamlOptions.SamlRequestIssuer,
                        IdpCertificate = _mPassSamlOptions.IdentityProviderCertificate
                    });

                if (!verifyLogInResponse.IsSuccess)
                    return Result<GetUserDataFromAuthResponseResultDto>
                        .Failure()
                        .JoinErrors(new[] { verifyLogInResponse.ToBase() });

                //  Get user info from SAML response
                var userData = SamlMessageParseHelper.GetAuthUserDetails(request.SamlResponse, false);
                if (!userData.IsSuccess)
                    return Result<GetUserDataFromAuthResponseResultDto>
                        .Failure()
                        .JoinErrors(new[] { userData.ToBase() });

                return await Task.FromResult(Result<GetUserDataFromAuthResponseResultDto>
                    .Success(new GetUserDataFromAuthResponseResultDto
                    {
                        UserInfo = userData.Response,
                        UserAttributes = verifyLogInResponse?.Response?.Attributes,
                        SessionIndexId = verifyLogInResponse?.Response?.SessionIndex
                    }));
            }
            catch (Exception e)
            {
                return Result<GetUserDataFromAuthResponseResultDto>
                    .Failure(DefaultMessages.AuthData.ErrorOnGenerateAuthUserData)
                    .WithError(e);
            }
        }

        /// <inheritdoc />
        public async Task<IResult<GenerateLogOutRequestResultDto>> GenerateLogoutRequestAsync(
            GenerateLogOutRequestDto request,
            CancellationToken cancellationToken = default)
        {
            if (request.IsNull())
                return Result<GenerateLogOutRequestResultDto>
                    .Failure(string.Format(DefaultMessages.ArgumentNullMessage, nameof(request)));

            if (request.RelayState.IsNullOrEmpty())
                return Result<GenerateLogOutRequestResultDto>
                    .Failure(string.Format(DefaultMessages.ArgumentNullMessage, nameof(request.RelayState)));

            if (request.SessionIndexId.IsNullOrEmpty())
                return Result<GenerateLogOutRequestResultDto>
                    .Failure(string.Format(DefaultMessages.ArgumentNullMessage, nameof(request.SessionIndexId)));

            if (request.UserIdentifierId.IsNullOrEmpty())
                return Result<GenerateLogOutRequestResultDto>
                    .Failure(string.Format(DefaultMessages.ArgumentNullMessage, nameof(request.UserIdentifierId)));

            try
            {
                var requestBuild = await _mPassBuilderService
                    .BuildLogOutRequestAsync(new BuildLogOutRequestDto
                    {
                        RelayState = request.RelayState,
                        UserSessionId = request.SessionIndexId,
                        UserIdentifierId = request.UserIdentifierId
                    },
                        cancellationToken);

                if (!requestBuild.IsSuccess)
                    return Result<GenerateLogOutRequestResultDto>
                        .Failure()
                        .JoinErrors(new[] { requestBuild.ToBase() });

                return Result<GenerateLogOutRequestResultDto>
                    .Success(new GenerateLogOutRequestResultDto
                    {
                        HtmlDocument = requestBuild.Response.HtmlAuthDocument,
                        LogOutRequestId = requestBuild.Response.LogoutRequestId
                    });
            }
            catch (Exception e)
            {
                return Result<GenerateLogOutRequestResultDto>
                    .Failure()
                    .AddException(e);
            }
        }

        /// <inheritdoc />
        public async Task<IResult> ValidateLogoutResponseAsync(
            ValidateLogoutResponseDto request,
            CancellationToken cancellationToken = default)
        {
            try
            {
                var validation = SamlMessageLoadAndVerifyHelper
                    .LoadAndVerifyLogoutResponse(new LoadAndVerifyLogoutResponseRequest
                    {
                        IdpCertificate = _mPassSamlOptions.IdentityProviderCertificate,
                        TimeOut = _mPassSamlOptions.SamlMessageTimeout,
                        ExpectedDestination = _mPassSamlOptions.SamlServiceLogoutDestination,
                        ExpectedRequestId = request.LogOutRequestId,
                        SamlResponse = request.SamlResponse
                    });

                if (!validation.IsSuccess)
                    return Result.Failure()
                        .JoinErrors(new[] { validation.ToBase() });

                return await Task.FromResult(Result.Success());
            }
            catch (Exception e)
            {
                return Result.Failure().AddException(e);
            }
        }

        /// <inheritdoc />
        public async Task<IResult<ProcessExternalLogoutRequestResultDto>> ProcessExternalLogoutRequestAsync(
            ProcessExternalLogoutRequestDto request,
            CancellationToken cancellationToken = default)
        {
            try
            {
                var requestValidation = await _mPassBuilderService
                    .BuildLogOutResponseAsync(
                        new BuildLogOutResponseDto
                        {
                            RelayState = request.RelayState,
                            SamlRequest = request.SamlRequest,
                            UserIdentifierId = request.UserIdentifierId,
                            UserSessionIndexId = request.SessionIndexId
                        }, cancellationToken);

                if (!requestValidation.IsSuccess)
                    return Result<ProcessExternalLogoutRequestResultDto>.Failure()
                        .JoinErrors(new[] { requestValidation.ToBase() });

                return Result<ProcessExternalLogoutRequestResultDto>
                    .Success(new ProcessExternalLogoutRequestResultDto
                    {
                        HtmlDocument = requestValidation.Response.HtmlAuthDocument,
                        LogoutResponseId = requestValidation.Response.LogoutResponseId
                    });
            }
            catch (Exception e)
            {
                return Result<ProcessExternalLogoutRequestResultDto>
                    .Failure().AddException(e);
            }
        }

        /// <inheritdoc />
        public async Task<IResult<PingResponse>> PingAsync(CancellationToken cancellationToken)
        {
            var stopwatch = new Stopwatch();
            var client = new HttpClient();

            try
            {
                stopwatch.Start();
                var checkingResponse = await client
                    .GetAsync(_mPassSamlOptions.SamlLoginDestination, cancellationToken);
                stopwatch.Stop();

                return !checkingResponse.IsSuccessStatusCode
                    ? Result<PingResponse>.Success(new PingResponse
                    {
                        Message = $"Communication problem. Server respond with code: {checkingResponse.StatusCode}",
                        Time = $"{stopwatch.Elapsed}",
                        IsSuccess = false
                    })
                    : Result<PingResponse>
                        .Success(new PingResponse { Message = "Server is available.", Time = $"{stopwatch.Elapsed}", IsSuccess = true });
            }
            catch (Exception e)
            {
                return Result<PingResponse>
                    .Success(new PingResponse { Message = "Communication problem: " + e.Message, Time = $"{stopwatch.Elapsed}", IsSuccess = false })
                    .AddException(e);
            }
        }
    }
}