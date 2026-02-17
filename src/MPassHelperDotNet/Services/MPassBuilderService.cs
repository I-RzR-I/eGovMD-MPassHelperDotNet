// ***********************************************************************
//  Assembly         : RzR.Shared.eGovMD.MPassHelperDotNet
//  Author           : RzR
//  Created On       : 2023-06-19 19:10
// 
//  Last Modified By : RzR
//  Last Modified On : 2023-06-28 16:26
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
using System.Threading;
using System.Threading.Tasks;
using AggregatedGenericResultMessage;
using AggregatedGenericResultMessage.Abstractions;
using AggregatedGenericResultMessage.Extensions.Result;
using DomainCommonExtensions.CommonExtensions;
using DomainCommonExtensions.DataTypeExtensions;
using Microsoft.Extensions.Options;
using MPassHelperDotNet.Abstractions.Services;
using MPassHelperDotNet.Helpers;
using MPassHelperDotNet.Helpers.SAML;
using MPassHelperDotNet.Models.Client;
using MPassHelperDotNet.Models.Dto.RequestBuilder.LoginRequest;
using MPassHelperDotNet.Models.Dto.RequestBuilder.LogoutRequest;
using MPassHelperDotNet.Models.Dto.RequestBuilder.LogOutResponse;
using MPassHelperDotNet.Models.Internal.Request;
using LocalStringExtensions = MPassHelperDotNet.Extensions.StringExtensions;

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
        ///     Initializes a new instance of the <see cref="MPassHelperDotNet.Services.MPassBuilderService" /> class.
        /// </summary>
        /// <param name="mPassSamlOptions">MPass SAML options</param>
        /// <remarks></remarks>
        public MPassBuilderService(IOptions<MPassSamlOptions> mPassSamlOptions)
            => _mPassSamlOptions = mPassSamlOptions.Value;

        /// <inheritdoc />
        public async Task<IResult<BuildLogInRequestResultDto>> BuildLogInRequestAsync(
            BuildLogInRequestDto request,
            CancellationToken cancellationToken = default)
        {
            if (request.IsNull())
                return Result<BuildLogInRequestResultDto>
                    .Failure(string.Format(DefaultMessages.ArgumentNullMessage, nameof(request)));
            try
            {
                //  Generate auth request id
                var requestId = LocalStringExtensions.GenerateRequestId();

                //  Build auth SAML request 
                var authRequest = SamlMessageBuildHelper.BuildAuthStringRequest(requestId,
                    _mPassSamlOptions.SamlLoginDestination,
                    _mPassSamlOptions.SamlServiceLoginDestination,
                    _mPassSamlOptions.SamlRequestIssuer);

                if (!authRequest.IsSuccess)
                    return new Result<BuildLogInRequestResultDto> { IsSuccess = false, Response = null, Messages = authRequest.Messages };

                //  Sign SAML auth request
                var signAuthRequest = SamlMessageSignatureHelper.SignSaml(authRequest.Response, _mPassSamlOptions.ServiceCertificate);
                if (!signAuthRequest.IsSuccess)
                    return new Result<BuildLogInRequestResultDto> { IsSuccess = false, Response = null, Messages = signAuthRequest.Messages };
                var samlMessage = signAuthRequest.Response.Base64Encode();

                //  Build HTML template
                var htmlAuthDocument = DefaultStaticInfo.DefaultRedirectHtml
                    .Replace("{PostUrl}", _mPassSamlOptions.SamlLoginDestination)
                    .Replace("{SAMLVariable}", "SAMLRequest")
                    .Replace("{SAMLMessage}", samlMessage)
                    .Replace("{RelayState}", request.RelayState);

                return await Task.FromResult(Result<BuildLogInRequestResultDto>
                    .Success(new BuildLogInRequestResultDto { AuthRequestId = requestId, HtmlAuthDocument = htmlAuthDocument, SamlResponse = samlMessage }));
            }
            catch (Exception e)
            {
                return Result<BuildLogInRequestResultDto>
                    .Failure(DefaultMessages.RequestBuilder.ErrorBuildAuthRequest)
                    .WithError(e);
            }
        }

        /// <inheritdoc />
        public async Task<IResult<BuildLogOutRequestResultDto>> BuildLogOutRequestAsync(
            BuildLogOutRequestDto request,
            CancellationToken cancellationToken = default)
        {
            if (request.IsNull())
                return Result<BuildLogOutRequestResultDto>
                    .Failure(string.Format(DefaultMessages.ArgumentNullMessage, nameof(request)));
            try
            {
                //  Generate logout request id
                var requestId = LocalStringExtensions.GenerateRequestId();

                //  Build logout SAML request 
                var logoutRequest = SamlMessageBuildHelper
                    .BuildLogoutStringRequest(requestId,
                        _mPassSamlOptions.SamlLogoutDestination,
                        _mPassSamlOptions.SamlRequestIssuer,
                        request.UserIdentifierId,
                        request.UserSessionId);

                if (!logoutRequest.IsSuccess)
                    return new Result<BuildLogOutRequestResultDto> { IsSuccess = false, Response = null, Messages = logoutRequest.Messages };

                //  Sign SAML logout request
                var signLogoutRequest = SamlMessageSignatureHelper.SignSaml(logoutRequest.Response, _mPassSamlOptions.ServiceCertificate);
                var samlMessage = signLogoutRequest.Response.Base64Encode();

                //  Build HTML template
                var htmlAuthDocument = DefaultStaticInfo.DefaultRedirectHtml
                    .Replace("{PostUrl}", _mPassSamlOptions.SamlLogoutDestination)
                    .Replace("{SAMLVariable}", "SAMLRequest")
                    .Replace("{SAMLMessage}", samlMessage)
                    .Replace("{RelayState}", request.RelayState);

                return await Task.FromResult(Result<BuildLogOutRequestResultDto>
                    .Success(new BuildLogOutRequestResultDto { LogoutRequestId = requestId, HtmlAuthDocument = htmlAuthDocument, SamlRequest = samlMessage }));
            }
            catch (Exception e)
            {
                return Result<BuildLogOutRequestResultDto>
                    .Failure(DefaultMessages.RequestBuilder.ErrorBuildLogOutRequest)
                    .WithError(e);
            }
        }

        /// <inheritdoc />
        public async Task<IResult<BuildLogOutResponseResultDto>> BuildLogOutResponseAsync(
            BuildLogOutResponseDto request,
            CancellationToken cancellationToken = default)
        {
            if (request.IsNull())
                return Result<BuildLogOutResponseResultDto>
                    .Failure(string.Format(DefaultMessages.ArgumentNullMessage, nameof(request)));
            try
            {
                //  Validate logout request
                var requestValidation = SamlMessageLoadAndVerifyHelper.LoadAndVerifyLogoutRequest(new LoadAndVerifyLogoutRequestRequest
                {
                    IdpCertificate = _mPassSamlOptions.IdentityProviderCertificate,
                    SamlRequest = request.SamlRequest,
                    TimeOut = _mPassSamlOptions.SamlMessageTimeout,
                    ExpectedSessionIndex = request.UserSessionIndexId,
                    ExpectedDestination = _mPassSamlOptions.SamlServiceSingleLogoutDestination,
                    ExpectedNameId = request.UserIdentifierId
                });
                if (!requestValidation.IsSuccess)
                    return new Result<BuildLogOutResponseResultDto> { IsSuccess = false, Response = null, Messages = requestValidation.Messages };

                //  Generate logout request id
                var requestId = LocalStringExtensions.GenerateRequestId();

                //  Build logout SAML response 
                var logoutResponse = SamlMessageBuildHelper.BuildLogoutStringResponse(requestId,
                    _mPassSamlOptions.SamlLogoutDestination, requestValidation.Response.RequestId, _mPassSamlOptions.SamlRequestIssuer);

                if (!logoutResponse.IsSuccess)
                    return new Result<BuildLogOutResponseResultDto> { IsSuccess = false, Response = null, Messages = logoutResponse.Messages };

                //  Sign SAML logout response
                var signLogoutResponse = SamlMessageSignatureHelper.SignSaml(logoutResponse.Response, _mPassSamlOptions.ServiceCertificate);
                var samlMessage = signLogoutResponse.Response.Base64Encode();

                //  Build HTML template
                var htmlAuthDocument = DefaultStaticInfo.DefaultRedirectHtml
                    .Replace("{PostUrl}", _mPassSamlOptions.SamlLogoutDestination)
                    .Replace("{SAMLVariable}", "SAMLResponse")
                    .Replace("{SAMLMessage}", signLogoutResponse.Response.Base64Encode())
                    .Replace("{RelayState}", request.RelayState);

                return await Task.FromResult(Result<BuildLogOutResponseResultDto>
                    .Success(new BuildLogOutResponseResultDto
                    {
                        LogoutResponseId = requestId, 
                        HtmlAuthDocument = htmlAuthDocument, 
                        SamlResponse = samlMessage
                    }));
            }
            catch (Exception e)
            {
                return Result<BuildLogOutResponseResultDto>
                    .Failure(DefaultMessages.RequestBuilder.ErrorBuildLogOutResponse)
                    .WithError(e);
            }
        }
    }
}