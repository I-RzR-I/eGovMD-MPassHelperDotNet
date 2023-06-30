// ***********************************************************************
//  Assembly         : RzR.Shared.eGovMD.MPassHelperDotNet
//  Author           : RzR
//  Created On       : 2023-06-21 23:43
// 
//  Last Modified By : RzR
//  Last Modified On : 2023-06-28 16:26
// ***********************************************************************
//  <copyright file="IAuthMPassService.cs" company="">
//   Copyright (c) RzR. All rights reserved.
//  </copyright>
// 
//  <summary>
//  </summary>
// ***********************************************************************

#region U S A G E S

using System.Threading;
using System.Threading.Tasks;
using AggregatedGenericResultMessage.Abstractions;
using MPassHelperDotNet.Models.Client;
using MPassHelperDotNet.Models.Dto.AuthService.ExternalLogoutRequest;
using MPassHelperDotNet.Models.Dto.AuthService.LoginRequest;
using MPassHelperDotNet.Models.Dto.AuthService.LoginResponse;
using MPassHelperDotNet.Models.Dto.AuthService.LogoutRequest;
using MPassHelperDotNet.Models.Dto.AuthService.LogoutResponse;

#endregion

namespace MPassHelperDotNet.Abstractions.Services
{
    /// <summary>
    ///     Auth MPass service
    /// </summary>
    public interface IAuthMPassService
    {
        /// <summary>
        ///     Generate auth/login request data
        /// </summary>
        /// <param name="request">Required. Input data model.</param>
        /// <param name="cancellationToken">Optional. The default value is default.</param>
        /// <returns>Return a html document with details</returns>
        /// <remarks>SAMLRequest, when your system initiate login.</remarks>
        Task<IResult<GenerateAuthRequestResultDto>> GenerateAuthRequestAsync(
            GenerateAuthRequestDto request,
            CancellationToken cancellationToken = default);

        /// <summary>
        ///     Get/read user auth details from SAMLResponse variable
        /// </summary>
        /// <param name="request">Required. Input required information</param>
        /// <param name="cancellationToken">Optional. The default value is default.</param>
        /// <returns>Return available user profile data from SAMLResponse</returns>
        /// <remarks>SAMLResponse, when your system initiate login.</remarks>
        Task<IResult<GetUserDataFromAuthResponseResultDto>>
            GetUserDataFromAuthResponseAsync(
                GetUserDataFromAuthResponseDto request,
                CancellationToken cancellationToken = default);

        /// <summary>
        ///     Generate logout request
        /// </summary>
        /// <param name="request">Required. Input param necessary to generate logout request details</param>
        /// <param name="cancellationToken">Optional. The default value is default.</param>
        /// <returns>Return logout request HTML document with details</returns>
        /// <remarks>SAMLRequest, when your system initiate logout.</remarks>
        Task<IResult<GenerateLogOutRequestResultDto>> GenerateLogoutRequestAsync(
            GenerateLogOutRequestDto request,
            CancellationToken cancellationToken = default);

        /// <summary>
        ///     Validate logout response (SAMLResponse)
        /// </summary>
        /// <param name="request">Required. Input param necessary to validate logout response</param>
        /// <param name="cancellationToken">Optional. The default value is default.</param>
        /// <returns>Return validation of SAML logout response.</returns>
        /// <remarks>SAMLResponse, when your system initiate logout.</remarks>
        Task<IResult> ValidateLogoutResponseAsync(
            ValidateLogoutResponseDto request,
            CancellationToken cancellationToken = default);

        /// <summary>
        ///     Process external logout requests and responses with details which must be sent to the service provider.
        /// </summary>
        /// <param name="request">Required. Input param necessary to process logout request.</param>
        /// <param name="cancellationToken">Optional. The default value is default.</param>
        /// <returns>Return SAMLRequest validation and SAMLResponse which must be sent to the service provider.</returns>
        /// <remarks>Logout is initialized by auth service provider.</remarks>
        Task<IResult<ProcessExternalLogoutRequestResultDto>> ProcessExternalLogoutRequestAsync(
            ProcessExternalLogoutRequestDto request,
            CancellationToken cancellationToken = default);

        /// <summary>
        ///     Check if service is alive
        /// </summary>
        /// <param name="cancellationToken">Optional. The default value is default.</param>
        /// <returns>Return if authentication service is alive</returns>
        /// <remarks></remarks>
        Task<IResult<PingResponse>> PingAsync(CancellationToken cancellationToken);
    }
}