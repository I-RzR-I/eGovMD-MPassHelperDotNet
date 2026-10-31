// ***********************************************************************
//  Assembly         : RzR.Shared.eGovMD.MPassHelperDotNet
//  Author           : RzR
//  Created On       : 2023-06-19 19:10
// 
//  Last Modified By : RzR
//  Last Modified On : 2026-09-25 19:35
// ***********************************************************************
//  <copyright file="MPassBuilderService.cs" company="">
//   Copyright (c) RzR. All rights reserved.
//  </copyright>
// 
//  <summary>
//  </summary>
// ***********************************************************************

#region U S A G E S

using System;
using System.Net;
using System.Threading;
using System.Threading.Tasks;
using Microsoft.Extensions.Logging;
using RzR.ResultMessage;
using RzR.ResultMessage.Abstractions;
using RzR.Extensions.Domain.Primitives;
using RzR.Extensions.Domain.Text;
using Microsoft.Extensions.Options;
using MPassHelperDotNet.Abstractions.Services;
using MPassHelperDotNet.Abstractions.Services.Replay;
using MPassHelperDotNet.Configurations.Certificate;
using MPassHelperDotNet.Extensions;
using MPassHelperDotNet.Helpers;
using MPassHelperDotNet.Helpers.Logging;
using MPassHelperDotNet.Helpers.SAML;
using MPassHelperDotNet.Models.Client;
using MPassHelperDotNet.Models.Dto.RequestBuilder.LoginRequest;
using MPassHelperDotNet.Models.Dto.RequestBuilder.LogoutRequest;
using MPassHelperDotNet.Models.Dto.RequestBuilder.LogOutResponse;
using MPassHelperDotNet.Models.Internal.Request;
using LocalStringExtensions = MPassHelperDotNet.Extensions.StringExtensions;
using MPassHelperDotNet.Helpers.Messages;

// ReSharper disable ClassNeverInstantiated.Global

#endregion

namespace MPassHelperDotNet.Services
{
    /// <inheritdoc cref="IMPassBuilderService" />
    public class MPassBuilderService : IMPassBuilderService
    {
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
        ///     Logger
        /// </summary>
        private readonly ILogger<MPassBuilderService> _logger;

        /// <summary>
        ///     Initializes a new instance of the <see cref="MPassHelperDotNet.Services.MPassBuilderService" />
        ///     class.
        /// </summary>
        /// <param name="mPassSamlOptions">MPass SAML options.</param>
        /// <param name="replayCache">SAML message replay cache.</param>
        /// <param name="timeProvider">Time provider.</param>
        /// <param name="logger">Logger.</param>
        public MPassBuilderService(IOptions<MPassSamlOptions> mPassSamlOptions, ISamlReplayCache replayCache,
            TimeProvider timeProvider, ILogger<MPassBuilderService> logger)
        {
            _mPassSamlOptions = mPassSamlOptions.Value;
            _replayCache = replayCache;
            _timeProvider = timeProvider;
            _logger = logger;
        }

        /// <inheritdoc />
        public async Task<IResult<BuildLogInRequestResultDto>> BuildLogInRequestAsync(
            BuildLogInRequestDto request, CancellationToken cancellationToken = default)
        {
            cancellationToken.ThrowIfCancellationRequested();

            if (request.IsNull())
            {
                return Result<BuildLogInRequestResultDto>
                    .Failure(string.Format(DefaultMessages.ArgumentNullMessage, nameof(request)));
            }

            if (request.RelayState.IsRelayStateWithinLimit().IsFalse())
            {
                return Result<BuildLogInRequestResultDto>
                    .Failure(RequestBuilderMessages.RelayStateTooLong);
            }

            var language = request.Language.IsMissing() ? null : request.Language.Trim().ToLowerInvariant();
            if (language.IsPresent() && Array.IndexOf(DefaultStaticInfo.AllowedLanguages, language) < 0)
            {
                return Result<BuildLogInRequestResultDto>
                    .Failure(string.Format(RequestBuilderMessages.LanguageNotSupported, string.Join(", ", DefaultStaticInfo.AllowedLanguages)));
            }

            try
            {
                //  Generate auth request id
                var requestId = LocalStringExtensions.GenerateRequestId();

                //  The same URL is used for the signed Destination attribute and for the form action
                var loginDestination = BuildLoginDestination(_mPassSamlOptions.SamlLoginDestination, language);

                //  Build auth SAML request
                var authRequest = SamlMessageBuildHelper.BuildAuthStringRequest(requestId,
                    loginDestination, _mPassSamlOptions.SamlServiceLoginDestination,
                    _mPassSamlOptions.SamlRequestIssuer, _timeProvider.GetUtcNow().UtcDateTime,
                    request.ForceAuthn, request.IsPassive);

                if (authRequest.IsFailure)
                {
                    return new Result<BuildLogInRequestResultDto>
                    {
                        IsSuccess = false,
                        Response = null,
                        Messages = authRequest.Messages
                    };
                }

                //  Sign SAML auth request
                var signAuthRequest = SamlMessageSignatureHelper.SignSaml(authRequest.Response,
                    _mPassSamlOptions.ServiceCertificate, _logger);
                if (signAuthRequest.IsFailure)
                {
                    return new Result<BuildLogInRequestResultDto>
                    {
                        IsSuccess = false,
                        Response = null,
                        Messages = signAuthRequest.Messages
                    };
                }

                var samlMessage = signAuthRequest.Response.Base64Encode();

                //  Build HTML template
                var htmlAuthDocument = BuildPostHtml(loginDestination, "SAMLRequest", samlMessage, request.RelayState);

                return await Task.FromResult(Result<BuildLogInRequestResultDto>
                    .Success(new BuildLogInRequestResultDto
                    {
                        AuthRequestId = requestId,
                        HtmlAuthDocument = htmlAuthDocument,
                        SamlResponse = samlMessage
                    }));
            }
            catch (Exception e)
            {
                ExceptionLogHelper.LogCaughtException(_logger, e, nameof(BuildLogInRequestAsync));

                return Result<BuildLogInRequestResultDto>
                    .Failure(RequestBuilderMessages.ErrorBuildAuthRequest);
            }
        }

        /// <inheritdoc />
        public async Task<IResult<BuildLogOutRequestResultDto>> BuildLogOutRequestAsync(BuildLogOutRequestDto request,
            CancellationToken cancellationToken = default)
        {
            cancellationToken.ThrowIfCancellationRequested();

            if (request.IsNull())
            {
                return Result<BuildLogOutRequestResultDto>
                    .Failure(string.Format(DefaultMessages.ArgumentNullMessage, nameof(request)));
            }

            if (request.RelayState.IsRelayStateWithinLimit().IsFalse())
            {
                return Result<BuildLogOutRequestResultDto>
                    .Failure(RequestBuilderMessages.RelayStateTooLong);
            }

            try
            {
                //  Generate logout request id
                var requestId = LocalStringExtensions.GenerateRequestId();

                //  Build logout SAML request 
                var logoutRequest = SamlMessageBuildHelper.BuildLogoutStringRequest(requestId,
                        _mPassSamlOptions.SamlLogoutDestination, _mPassSamlOptions.SamlRequestIssuer,
                        request.UserIdentifierId, request.UserSessionId, _timeProvider.GetUtcNow().UtcDateTime);

                if (logoutRequest.IsFailure)
                {
                    return new Result<BuildLogOutRequestResultDto>
                    {
                        IsSuccess = false,
                        Response = null,
                        Messages = logoutRequest.Messages
                    };
                }

                //  Sign SAML logout request
                var signLogoutRequest = SamlMessageSignatureHelper.SignSaml(logoutRequest.Response,
                    _mPassSamlOptions.ServiceCertificate, _logger);
                if (signLogoutRequest.IsFailure)
                    return Result<BuildLogOutRequestResultDto>.Failure(RequestBuilderMessages.ErrorSignRequest);

                var samlMessage = signLogoutRequest.Response.Base64Encode();

                //  Build HTML template
                var htmlAuthDocument = BuildPostHtml(_mPassSamlOptions.SamlLogoutDestination, "SAMLRequest", samlMessage, request.RelayState);

                return await Task.FromResult(Result<BuildLogOutRequestResultDto>
                    .Success(new BuildLogOutRequestResultDto
                    {
                        LogoutRequestId = requestId,
                        HtmlAuthDocument = htmlAuthDocument,
                        SamlRequest = samlMessage
                    }));
            }
            catch (Exception e)
            {
                ExceptionLogHelper.LogCaughtException(_logger, e, nameof(BuildLogOutRequestAsync));

                return Result<BuildLogOutRequestResultDto>
                    .Failure(RequestBuilderMessages.ErrorBuildLogOutRequest);
            }
        }

        /// <inheritdoc />
        public async Task<IResult<BuildLogOutResponseResultDto>> BuildLogOutResponseAsync(BuildLogOutResponseDto request,
            CancellationToken cancellationToken = default)
        {
            cancellationToken.ThrowIfCancellationRequested();

            if (request.IsNull())
            {
                return Result<BuildLogOutResponseResultDto>
                    .Failure(string.Format(DefaultMessages.ArgumentNullMessage, nameof(request)));
            }

            if (request.RelayState.IsRelayStateWithinLimit().IsFalse())
            {
                return Result<BuildLogOutResponseResultDto>
                    .Failure(RequestBuilderMessages.RelayStateTooLong);
            }

            try
            {
                var utcNow = _timeProvider.GetUtcNow().UtcDateTime;

                //  Validate logout request
                var requestValidation = SamlMessageLoadAndVerifyHelper.LoadAndVerifyLogoutRequest(
                    new LoadAndVerifyLogoutRequestRequest
                    {
                        IdpCertificate = _mPassSamlOptions.IdentityProviderCertificate,
                        IdpCertificates = CertificateLoader.IdentityProviderCertificates(_mPassSamlOptions),
                        SamlRequest = request.SamlRequest,
                        TimeOut = _mPassSamlOptions.SamlMessageTimeout,
                        ExpectedSessionIndex = request.UserSessionIndexId,
                        ExpectedDestination = _mPassSamlOptions.SamlServiceSingleLogoutDestination,
                        ExpectedNameId = request.UserIdentifierId,
                        ExpectedIssuer = _mPassSamlOptions.IdentityProviderIssuer,
                        ClockSkew = _mPassSamlOptions.SamlClockSkew,
                        CurrentUtc = utcNow,
                        AllowSha1Signatures = _mPassSamlOptions.AllowSha1Signatures,
                        MaxMessageLength = _mPassSamlOptions.SamlMessageMaxLength,
                        Logger = _logger
                    });
                if (requestValidation.IsFailure)
                {
                    return new Result<BuildLogOutResponseResultDto>
                    {
                        IsSuccess = false, 
                        Response = null,
                        Messages = requestValidation.Messages
                    };
                }

                //  The logout request id is the replay key; the verifier guarantees it is not empty
                var logoutRequestId = requestValidation.Response.RequestId;

                //  Generate logout request id
                var requestId = LocalStringExtensions.GenerateRequestId();

                //  Build logout SAML response 
                var logoutResponse = SamlMessageBuildHelper.BuildLogoutStringResponse(requestId,
                    _mPassSamlOptions.SamlLogoutDestination, logoutRequestId, _mPassSamlOptions.SamlRequestIssuer,
                    utcNow);

                if (logoutResponse.IsFailure)
                {
                    return new Result<BuildLogOutResponseResultDto>
                    {
                        IsSuccess = false, 
                        Response = null, 
                        Messages = logoutResponse.Messages
                    };
                }

                //  Sign SAML logout response
                var signLogoutResponse = SamlMessageSignatureHelper.SignSaml(logoutResponse.Response, 
                    _mPassSamlOptions.ServiceCertificate, _logger);
                if (signLogoutResponse.IsFailure)
                    return Result<BuildLogOutResponseResultDto>.Failure(RequestBuilderMessages.ErrorSignRequest);
                
                var samlMessage = signLogoutResponse.Response.Base64Encode();

                //  Build HTML template
                var htmlAuthDocument = BuildPostHtml(_mPassSamlOptions.SamlLogoutDestination, "SAMLResponse", samlMessage, request.RelayState);

                cancellationToken.ThrowIfCancellationRequested();
                var isFirstUse = await _replayCache.TryAddAsync(DefaultStaticInfo.ReplayKeyLogoutRequest + logoutRequestId,
                    requestValidation.Response.ReplayExpiresAtUtc, CancellationToken.None);
                if (isFirstUse.IsFalse())
                {
                    _logger.LogWarning("{Operation}: logout request {MessageId} was already processed", nameof(BuildLogOutResponseAsync), logoutRequestId);

                    return Result<BuildLogOutResponseResultDto>
                        .Failure(SamlLoadValidationMessages.SamlReplayDetected);
                }

                return await Task.FromResult(Result<BuildLogOutResponseResultDto>
                    .Success(new BuildLogOutResponseResultDto
                    {
                        LogoutResponseId = requestId,
                        HtmlAuthDocument = htmlAuthDocument,
                        SamlResponse = samlMessage
                    }));
            }
            catch (Exception e) when (!ExceptionLogHelper.IsCallerCancellation(e, cancellationToken))
            {
                ExceptionLogHelper.LogCaughtException(_logger, e, nameof(BuildLogOutResponseAsync));

                return Result<BuildLogOutResponseResultDto>
                    .Failure(RequestBuilderMessages.ErrorBuildLogOutResponse);
            }
        }

        /// <summary>
        ///     Build the auto-submit HTML form (HTTP-POST binding) from <see cref="DefaultStaticInfo.DefaultRedirectHtml" />
        /// </summary>
        /// <param name="postUrl">Form action URL.</param>
        /// <param name="samlVariable">SAML form field name (SAMLRequest/SAMLResponse)</param>
        /// <param name="samlMessage">Base64 encoded SAML message.</param>
        /// <param name="relayState">RelayState value; null is rendered as an empty value.</param>
        /// <returns>
        ///     Return the HTML document.
        /// </returns>
        private static string BuildPostHtml(string postUrl, string samlVariable, string samlMessage, string relayState)
            => DefaultStaticInfo.DefaultRedirectHtml
                .Replace("{PostUrl}", WebUtility.HtmlEncode(postUrl))
                .Replace("{SAMLVariable}", WebUtility.HtmlEncode(samlVariable))
                .Replace("{SAMLMessage}", WebUtility.HtmlEncode(samlMessage))
                .Replace("{RelayState}", WebUtility.HtmlEncode(relayState.IfNullThenEmpty()));

        /// <summary>
        ///     Build the login URL (AuthnRequest Destination and form action) with the optional language
        ///     query parameter.
        /// </summary>
        /// <param name="destination">Configured login destination.</param>
        /// <param name="language">
        ///     Normalised and allowed language; null keeps the destination unchanged.
        /// </param>
        /// <returns>
        ///     Return the login URL.
        /// </returns>
        private static string BuildLoginDestination(string destination, string language)
        {
            if (language.IsNullOrEmpty() || destination.IsNullOrEmpty())
                return destination;

            var fragmentIndex = destination.IndexOf('#');
            var address = fragmentIndex < 0 ? destination : destination.Substring(0, fragmentIndex);
            var fragment = fragmentIndex < 0 ? string.Empty : destination.Substring(fragmentIndex);

            var queryIndex = address.IndexOf('?');
            if (queryIndex >= 0 && HasQueryParameter(address.Substring(queryIndex + 1), DefaultStaticInfo.LanguageQueryParameter))
                return destination;

            var separator = queryIndex < 0 ? "?" : "&";
            if (queryIndex >= 0 && (queryIndex == address.Length - 1 || address[address.Length - 1] == '&'))
                separator = string.Empty;

            return address + separator + DefaultStaticInfo.LanguageQueryParameter + "=" + Uri.EscapeDataString(language) + fragment;
        }

        /// <summary>
        ///     Check if a URL query contains a parameter with the given name.
        /// </summary>
        /// <param name="query">URL query, without the leading <c>?</c></param>
        /// <param name="name">Parameter name.</param>
        /// <returns>
        ///     Return <see langword="true" /> when a parameter with exactly this name (case-insensitive)
        ///     exists.
        /// </returns>
        private static bool HasQueryParameter(string query, string name)
        {
            foreach (var parameter in query.Split('&'))
            {
                var valueIndex = parameter.IndexOf('=');
                var parameterName = valueIndex < 0 ? parameter : parameter.Substring(0, valueIndex);
                if (string.Equals(parameterName, name, StringComparison.OrdinalIgnoreCase))
                    return true;
            }

            return false;
        }
    }
}