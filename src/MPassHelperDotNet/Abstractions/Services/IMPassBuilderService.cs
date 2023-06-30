// ***********************************************************************
//  Assembly         : RzR.Shared.eGovMD.MPassHelperDotNet
//  Author           : RzR
//  Created On       : 2023-06-19 19:10
// 
//  Last Modified By : RzR
//  Last Modified On : 2023-06-28 16:26
// ***********************************************************************
//  <copyright file="IMPassBuilderService.cs" company="">
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
using MPassHelperDotNet.Models.Dto.RequestBuilder.LoginRequest;
using MPassHelperDotNet.Models.Dto.RequestBuilder.LogoutRequest;
using MPassHelperDotNet.Models.Dto.RequestBuilder.LogOutResponse;

#endregion

namespace MPassHelperDotNet.Abstractions.Services
{
    /// <summary>
    ///     MPass request builder service
    /// </summary>
    public interface IMPassBuilderService
    {
        /// <summary>
        ///     Build/generate auth request
        /// </summary>
        /// <param name="request">Required. Input params used to build/generate auth request</param>
        /// <param name="cancellationToken">Optional. The default value is default.</param>
        /// <returns>Return result details necessary to create full auth request.</returns>
        /// <remarks>Auth request, when your service initialize auth.</remarks>
        Task<IResult<BuildLogInRequestResultDto>> BuildLogInRequestAsync(
            BuildLogInRequestDto request,
            CancellationToken cancellationToken = default);

        /// <summary>
        ///     Build/generate logout request
        /// </summary>
        /// <param name="request">Required. Input params used to build/generate logout request</param>
        /// <param name="cancellationToken">Optional. The default value is default.</param>
        /// <returns>Return result details necessary to create full logout request.</returns>
        /// <remarks>Logout request, when your system initialize logout.</remarks>
        Task<IResult<BuildLogOutRequestResultDto>> BuildLogOutRequestAsync(
            BuildLogOutRequestDto request,
            CancellationToken cancellationToken = default);

        /// <summary>
        ///     Build/generate logout response
        /// </summary>
        /// <param name="request">Required. Input params used to build/generate logout response</param>
        /// <param name="cancellationToken">Optional. The default value is default.</param>
        /// <returns>Return result details necessary to create full logout response.</returns>
        /// <remarks>Logout response, when someone out side of the system initialize logout.</remarks>
        Task<IResult<BuildLogOutResponseResultDto>> BuildLogOutResponseAsync(
            BuildLogOutResponseDto request,
            CancellationToken cancellationToken = default);
    }
}