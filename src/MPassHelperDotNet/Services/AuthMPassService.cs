// ***********************************************************************
//  Assembly         : RzR.Shared.eGovMD.MPassHelperDotNet
//  Author           : RzR
//  Created On       : 2023-06-21 23:43
// 
//  Last Modified By : RzR
//  Last Modified On : 2026-09-25 19:51
// ***********************************************************************
//  <copyright file="AuthMPassService.cs" company="">
//   Copyright (c) RzR. All rights reserved.
//  </copyright>
// 
//  <summary>
//  </summary>
// ***********************************************************************

#region U S I N G

using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;
using MPassHelperDotNet.Abstractions.Services;
using MPassHelperDotNet.Abstractions.Services.Replay;
using MPassHelperDotNet.Configurations.Certificate;
using MPassHelperDotNet.Extensions;
using MPassHelperDotNet.Helpers;
using MPassHelperDotNet.Helpers.Logging;
using MPassHelperDotNet.Helpers.Messages;
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
using RzR.Extensions.Domain.Primitives;
using RzR.Extensions.Domain.Text;
using RzR.ResultMessage;
using RzR.ResultMessage.Abstractions;
using System;
using System.Diagnostics;
using System.Net.Http;
using System.Threading;
using System.Threading.Tasks;

// ReSharper disable ConstantConditionalAccessQualifier
// ReSharper disable ClassNeverInstantiated.Global

#endregion

namespace MPassHelperDotNet.Services
{
    /// <inheritdoc />
    public class AuthMPassService : IAuthMPassService
    {
        /// <summary>
        ///     Shared HTTP client used by <see cref="PingAsync" /> (one instance for the process lifetime)
        /// </summary>
        private static readonly HttpClient PingHttpClient = new();

        /// <summary>
        ///     Logger
        /// </summary>
        private readonly ILogger<AuthMPassService> _logger;

        /// <summary>
        ///     MPass builder service
        /// </summary>
        private readonly IMPassBuilderService _mPassBuilderService;

        /// <summary>
        ///     MPass SAML option
        /// </summary>
        private readonly MPassSamlOptions _mPassSamlOptions;

        /// <summary>
        ///     SAML message replay cache
        /// </summary>
        private readonly ISamlReplayCache _replayCache;

        /// <summary>
        ///     Time provider
        /// </summary>
        private readonly TimeProvider _timeProvider;

        /// <summary>
        ///     Initializes a new instance of the <see cref="MPassHelperDotNet.Services.AuthMPassService" />
        ///     class.
        /// </summary>
        /// <param name="mPassBuilderService">MPass communication string builder.</param>
        /// <param name="mPassSamlOptions">MPass options.</param>
        /// <param name="replayCache">SAML message replay cache.</param>
        /// <param name="timeProvider">Time provider.</param>
        /// <param name="logger">Logger.</param>
        public AuthMPassService(IMPassBuilderService mPassBuilderService,
            IOptions<MPassSamlOptions> mPassSamlOptions, ISamlReplayCache replayCache,
            TimeProvider timeProvider, ILogger<AuthMPassService> logger)
        {
            _mPassBuilderService = mPassBuilderService;
            _mPassSamlOptions = mPassSamlOptions.Value;
            _replayCache = replayCache;
            _timeProvider = timeProvider;
            _logger = logger;
        }

        /// <inheritdoc />
        public async Task<IResult<GenerateAuthRequestResultDto>> GenerateAuthRequestAsync(
            GenerateAuthRequestDto request, CancellationToken cancellationToken = default)
        {
            cancellationToken.ThrowIfCancellationRequested();

            if (request.IsNull())
            {
                return Result<GenerateAuthRequestResultDto>
                    .Failure(string.Format(DefaultMessages.ArgumentNullMessage, nameof(request)));
            }

            if (request.RelayState.IsNullOrEmpty())
            {
                return Result<GenerateAuthRequestResultDto>
                    .Failure(string.Format(DefaultMessages.ArgumentNullMessage, nameof(request.RelayState)));
            }

            try
            {
                var requestBuild = await _mPassBuilderService
                    .BuildLogInRequestAsync(new BuildLogInRequestDto
                    {
                        RelayState = request.RelayState,
                        ForceAuthn = request.ForceAuthn,
                        IsPassive = request.IsPassive,
                        Language = request.Language
                    }, cancellationToken);

                if (requestBuild.IsFailure)
                {
                    return Result<GenerateAuthRequestResultDto>
                        .Failure()
                        .JoinErrors(new[] { requestBuild.ToBase() });
                }

                return Result<GenerateAuthRequestResultDto>
                    .Success(new GenerateAuthRequestResultDto
                    {
                        HtmlDocument = requestBuild.Response.HtmlAuthDocument,
                        AuthRequestId = requestBuild.Response.AuthRequestId
                    });
            }
            catch (Exception e) when (!ExceptionLogHelper.IsCallerCancellation(e, cancellationToken))
            {
                ExceptionLogHelper.LogCaughtException(_logger, e, nameof(GenerateAuthRequestAsync));

                return Result<GenerateAuthRequestResultDto>
                    .Failure(RequestBuilderMessages.ErrorBuildAuthRequest);
            }
        }

        /// <inheritdoc />
        public async Task<IResult<GetUserDataFromAuthResponseResultDto>> GetUserDataFromAuthResponseAsync(
                GetUserDataFromAuthResponseDto request, CancellationToken cancellationToken = default)
        {
            cancellationToken.ThrowIfCancellationRequested();

            if (request.IsNull())
            {
                return Result<GetUserDataFromAuthResponseResultDto>
                    .Failure(string.Format(DefaultMessages.ArgumentNullMessage, nameof(request)));
            }

            if (request.SamlResponse.IsNullOrEmpty())
            {
                return Result<GetUserDataFromAuthResponseResultDto>
                    .Failure(string.Format(DefaultMessages.ArgumentNullMessage, nameof(request.SamlResponse)));
            }

            if (request.AuthRequestId.IsMissing())
            {
                return Result<GetUserDataFromAuthResponseResultDto>
                    .Failure(DefaultMessages.ExpectedRequestIdRequired);
            }

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
                        IdpCertificate = _mPassSamlOptions.IdentityProviderCertificate,
                        IdpCertificates = CertificateLoader.IdentityProviderCertificates(_mPassSamlOptions),
                        ExpectedIssuer = _mPassSamlOptions.IdentityProviderIssuer,
                        ClockSkew = _mPassSamlOptions.SamlClockSkew,
                        CurrentUtc = _timeProvider.GetUtcNow().UtcDateTime,
                        AllowSha1Signatures = _mPassSamlOptions.AllowSha1Signatures,
                        MaxMessageLength = _mPassSamlOptions.SamlMessageMaxLength,
                        Logger = _logger
                    });

                if (verifyLogInResponse.IsFailure)
                {
                    return Result<GetUserDataFromAuthResponseResultDto>
                        .Failure()
                        .JoinErrors(new[] { verifyLogInResponse.ToBase() });
                }

                //  Get user info from SAML response
                var userData = SamlMessageParseHelper.GetAuthUserDetails(verifyLogInResponse.Response, _logger);
                if (userData.IsFailure)
                {
                    return Result<GetUserDataFromAuthResponseResultDto>
                        .Failure()
                        .JoinErrors(new[] { userData.ToBase() });
                }

                cancellationToken.ThrowIfCancellationRequested();

                if (!await TryCommitReplayAsync(DefaultStaticInfo.ReplayKeyResponse, verifyLogInResponse.Response.ResponseId,
                        verifyLogInResponse.Response.ReplayExpiresAtUtc, nameof(GetUserDataFromAuthResponseAsync), CancellationToken.None)
                    || !await TryCommitReplayAsync(DefaultStaticInfo.ReplayKeyAssertion, verifyLogInResponse.Response.AssertionId,
                        verifyLogInResponse.Response.ReplayExpiresAtUtc, nameof(GetUserDataFromAuthResponseAsync), CancellationToken.None))
                {
                    return Result<GetUserDataFromAuthResponseResultDto>
                        .Failure(SamlLoadValidationMessages.SamlReplayDetected);
                }

                return await Task.FromResult(Result<GetUserDataFromAuthResponseResultDto>
                    .Success(new GetUserDataFromAuthResponseResultDto
                    {
                        UserInfo = userData.Response,
                        UserAttributes = verifyLogInResponse?.Response?.Attributes,
                        SessionIndexId = verifyLogInResponse?.Response?.SessionIndex
                    }));
            }
            catch (Exception e) when (!ExceptionLogHelper.IsCallerCancellation(e, cancellationToken))
            {
                ExceptionLogHelper.LogCaughtException(_logger, e, nameof(GetUserDataFromAuthResponseAsync));

                return Result<GetUserDataFromAuthResponseResultDto>
                    .Failure(AuthDataMessages.ErrorOnGenerateAuthUserData);
            }
        }

        /// <inheritdoc />
        public async Task<IResult<GenerateLogOutRequestResultDto>> GenerateLogoutRequestAsync(
            GenerateLogOutRequestDto request, CancellationToken cancellationToken = default)
        {
            cancellationToken.ThrowIfCancellationRequested();

            if (request.IsNull())
            {
                return Result<GenerateLogOutRequestResultDto>
                    .Failure(string.Format(DefaultMessages.ArgumentNullMessage, nameof(request)));
            }

            if (request.RelayState.IsNullOrEmpty())
            {
                return Result<GenerateLogOutRequestResultDto>
                    .Failure(string.Format(DefaultMessages.ArgumentNullMessage, nameof(request.RelayState)));
            }

            if (request.SessionIndexId.IsNullOrEmpty())
            {
                return Result<GenerateLogOutRequestResultDto>
                    .Failure(string.Format(DefaultMessages.ArgumentNullMessage, nameof(request.SessionIndexId)));
            }

            if (request.UserIdentifierId.IsNullOrEmpty())
            {
                return Result<GenerateLogOutRequestResultDto>
                    .Failure(string.Format(DefaultMessages.ArgumentNullMessage, nameof(request.UserIdentifierId)));
            }

            try
            {
                var requestBuild = await _mPassBuilderService
                    .BuildLogOutRequestAsync(new BuildLogOutRequestDto
                    {
                        RelayState = request.RelayState,
                        UserSessionId = request.SessionIndexId,
                        UserIdentifierId = request.UserIdentifierId
                    }, cancellationToken);

                if (requestBuild.IsFailure)
                {
                    return Result<GenerateLogOutRequestResultDto>
                        .Failure()
                        .JoinErrors(new[] { requestBuild.ToBase() });
                }

                return Result<GenerateLogOutRequestResultDto>
                    .Success(new GenerateLogOutRequestResultDto
                    {
                        HtmlDocument = requestBuild.Response.HtmlAuthDocument,
                        LogOutRequestId = requestBuild.Response.LogoutRequestId
                    });
            }
            catch (Exception e) when (!ExceptionLogHelper.IsCallerCancellation(e, cancellationToken))
            {
                ExceptionLogHelper.LogCaughtException(_logger, e, nameof(GenerateLogoutRequestAsync));

                return Result<GenerateLogOutRequestResultDto>
                    .Failure(RequestBuilderMessages.ErrorBuildLogOutRequest);
            }
        }

        /// <inheritdoc />
        public async Task<IResult> ValidateLogoutResponseAsync(ValidateLogoutResponseDto request,
            CancellationToken cancellationToken = default)
        {
            cancellationToken.ThrowIfCancellationRequested();

            if (request.IsNull())
                return Result.Failure(string.Format(DefaultMessages.ArgumentNullMessage, nameof(request)));

            if (request.SamlResponse.IsNullOrEmpty())
                return Result.Failure(string.Format(DefaultMessages.ArgumentNullMessage, nameof(request.SamlResponse)));

            if (request.LogOutRequestId.IsMissing())
                return Result.Failure(DefaultMessages.ExpectedRequestIdRequired);

            try
            {
                var validation = SamlMessageLoadAndVerifyHelper
                    .LoadAndVerifyLogoutResponse(new LoadAndVerifyLogoutResponseRequest
                    {
                        IdpCertificate = _mPassSamlOptions.IdentityProviderCertificate,
                        TimeOut = _mPassSamlOptions.SamlMessageTimeout,
                        ExpectedDestination = _mPassSamlOptions.SamlServiceLogoutDestination,
                        ExpectedRequestId = request.LogOutRequestId,
                        SamlResponse = request.SamlResponse,
                        IdpCertificates = CertificateLoader.IdentityProviderCertificates(_mPassSamlOptions),
                        ExpectedIssuer = _mPassSamlOptions.IdentityProviderIssuer,
                        ClockSkew = _mPassSamlOptions.SamlClockSkew,
                        CurrentUtc = _timeProvider.GetUtcNow().UtcDateTime,
                        AllowSha1Signatures = _mPassSamlOptions.AllowSha1Signatures,
                        MaxMessageLength = _mPassSamlOptions.SamlMessageMaxLength,
                        Logger = _logger
                    });

                if (validation.IsFailure)
                {
                    return Result.Failure()
                        .JoinErrors(new[] { validation.ToBase() });
                }

                cancellationToken.ThrowIfCancellationRequested();
                
                if (!await TryCommitReplayAsync(DefaultStaticInfo.ReplayKeyLogoutResponse, validation.Response.ResponseId,
                        validation.Response.ReplayExpiresAtUtc, nameof(ValidateLogoutResponseAsync), CancellationToken.None))
                    return Result.Failure(SamlLoadValidationMessages.SamlReplayDetected);

                return await Task.FromResult(Result.Success());
            }
            catch (Exception e) when (!ExceptionLogHelper.IsCallerCancellation(e, cancellationToken))
            {
                ExceptionLogHelper.LogCaughtException(_logger, e, nameof(ValidateLogoutResponseAsync));

                return Result.Failure(SamlLoadValidationMessages.InvalidErrorOnLoadAndValidationLogoutResponseSaml);
            }
        }

        /// <inheritdoc />
        public async Task<IResult<ProcessExternalLogoutRequestResultDto>> ProcessExternalLogoutRequestAsync(
            ProcessExternalLogoutRequestDto request, CancellationToken cancellationToken = default)
        {
            cancellationToken.ThrowIfCancellationRequested();

            if (request.IsNull())
            {
                return Result<ProcessExternalLogoutRequestResultDto>
                    .Failure(string.Format(DefaultMessages.ArgumentNullMessage, nameof(request)));
            }

            if (request.SamlRequest.IsNullOrEmpty())
            {
                return Result<ProcessExternalLogoutRequestResultDto>
                    .Failure(string.Format(DefaultMessages.ArgumentNullMessage, nameof(request.SamlRequest)));
            }

            if (request.SessionIndexId.IsNullOrEmpty())
            {
                return Result<ProcessExternalLogoutRequestResultDto>
                    .Failure(string.Format(DefaultMessages.ArgumentNullMessage, nameof(request.SessionIndexId)));
            }

            if (request.UserIdentifierId.IsNullOrEmpty())
            {
                return Result<ProcessExternalLogoutRequestResultDto>
                    .Failure(string.Format(DefaultMessages.ArgumentNullMessage, nameof(request.UserIdentifierId)));
            }
            
            if (request.RelayState.IsRelayStateWithinLimit().IsFalse())
            {
                return Result<ProcessExternalLogoutRequestResultDto>
                    .Failure(RequestBuilderMessages.RelayStateTooLong);
            }

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

                if (requestValidation.IsFailure)
                {
                    return Result<ProcessExternalLogoutRequestResultDto>.Failure()
                        .JoinErrors(new[] { requestValidation.ToBase() });
                }

                return Result<ProcessExternalLogoutRequestResultDto>
                    .Success(new ProcessExternalLogoutRequestResultDto
                    {
                        HtmlDocument = requestValidation.Response.HtmlAuthDocument,
                        LogoutResponseId = requestValidation.Response.LogoutResponseId
                    });
            }
            catch (Exception e) when (!ExceptionLogHelper.IsCallerCancellation(e, cancellationToken))
            {
                ExceptionLogHelper.LogCaughtException(_logger, e, nameof(ProcessExternalLogoutRequestAsync));

                return Result<ProcessExternalLogoutRequestResultDto>
                    .Failure(RequestBuilderMessages.ErrorBuildLogOutResponse);
            }
        }

        /// <inheritdoc />
        public async Task<IResult<PingResponse>> PingAsync(CancellationToken cancellationToken)
        {
            cancellationToken.ThrowIfCancellationRequested();

            var stopwatch = new Stopwatch();

            try
            {
                stopwatch.Start();
                //  Only the status code is used, so the response body is not buffered
                using var checkingResponse = await PingHttpClient
                    .GetAsync(_mPassSamlOptions.SamlLoginDestination, HttpCompletionOption.ResponseHeadersRead, cancellationToken);
                stopwatch.Stop();

                return !checkingResponse.IsSuccessStatusCode
                    ? Result<PingResponse>.Success(new PingResponse
                    {
                        Message = $"Communication problem. Server respond with code: {checkingResponse.StatusCode}",
                        Time = $"{stopwatch.Elapsed}",
                        IsSuccess = false
                    })
                    : Result<PingResponse>
                        .Success(new PingResponse
                        {
                            Message = "Server is available.", 
                            Time = $"{stopwatch.Elapsed}", 
                            IsSuccess = true
                        });
            }
            catch (Exception e) when (!ExceptionLogHelper.IsCallerCancellation(e, cancellationToken))
            {
                ExceptionLogHelper.LogCaughtException(_logger, e, nameof(PingAsync));

                return Result<PingResponse>
                    .Success(new PingResponse
                    {
                        Message = DefaultMessages.PingCommunicationProblem, 
                        Time = $"{stopwatch.Elapsed}", 
                        IsSuccess = false
                    });
            }
        }

        /// <summary>
        ///     Commit a verified message ID to the replay cache (single use)
        /// </summary>
        /// <param name="keyPrefix">Message type prefix (<c>DefaultStaticInfo.ReplayKey*</c>)</param>
        /// <param name="messageId">Verified message ID.</param>
        /// <param name="expiresAtUtc">Time until which the ID must be remembered.</param>
        /// <param name="operation">Calling operation name, used for logging.</param>
        /// <param name="cancellationToken">Cancellation token.</param>
        /// <returns>
        ///     <see langword="true" /> when the ID was not seen before; <see langword="false" /> when it
        ///     is a replay, the ID is missing or the cache cannot accept new entries. 
        /// </returns>
        private async Task<bool> TryCommitReplayAsync(string keyPrefix, string messageId, DateTimeOffset expiresAtUtc,
            string operation, CancellationToken cancellationToken)
        {
            if (messageId.IsNullOrEmpty())
            {
                _logger.LogWarning("{Operation} rejected: the verified message has no {ReplayKind} ID", operation, keyPrefix);

                return false;
            }

            if (await _replayCache.TryAddAsync(keyPrefix + messageId, expiresAtUtc, cancellationToken))
                return true;

            _logger.LogWarning("{Operation} rejected: replay detected for {ReplayKind} {MessageId}", operation, keyPrefix, messageId);

            return false;
        }
    }
}