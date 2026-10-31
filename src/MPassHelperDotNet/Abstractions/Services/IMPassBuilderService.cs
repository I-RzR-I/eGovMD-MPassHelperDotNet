// ***********************************************************************
//  Assembly         : RzR.Shared.eGovMD.MPassHelperDotNet
//  Author           : RzR
//  Created On       : 2023-06-19 19:10
// 
//  Last Modified By : RzR
//  Last Modified On : 2026-09-22 17:27
// ***********************************************************************
//  <copyright file="IMPassBuilderService.cs" company="">
//   Copyright (c) RzR. All rights reserved.
//  </copyright>
// 
//  <summary>
//  </summary>
// ***********************************************************************

#region U S I N G

using MPassHelperDotNet.Models.Dto.RequestBuilder.LoginRequest;
using MPassHelperDotNet.Models.Dto.RequestBuilder.LogoutRequest;
using MPassHelperDotNet.Models.Dto.RequestBuilder.LogOutResponse;
using RzR.ResultMessage.Abstractions;
using System.Threading;
using System.Threading.Tasks;

#endregion

namespace MPassHelperDotNet.Abstractions.Services
{
    /// <summary>
    ///     MPass request builder service.
    /// </summary>
    public interface IMPassBuilderService
    {
        /// <summary>
        ///     Build/generate auth request.
        /// </summary>
        /// <exception cref="System.OperationCanceledException">
        ///     The <paramref name="cancellationToken" /> was canceled.
        /// </exception>
        /// <param name="request">Required. Input params used to build/generate auth request.</param>
        /// <param name="cancellationToken">(Optional) Optional. The default value is default.</param>
        /// <returns>
        ///     Return result details necessary to create full auth request.
        /// </returns>
        Task<IResult<BuildLogInRequestResultDto>> BuildLogInRequestAsync(BuildLogInRequestDto request,
            CancellationToken cancellationToken = default);

        /// <summary>
        ///     Build/generate logout request.
        /// </summary>
        /// <exception cref="System.OperationCanceledException">
        ///     The <paramref name="cancellationToken" /> was canceled.
        /// </exception>
        /// <param name="request">Required. Input params used to build/generate logout request.</param>
        /// <param name="cancellationToken">(Optional) Optional. The default value is default.</param>
        /// <returns>
        ///     Return result details necessary to create full logout request.
        /// </returns>
        Task<IResult<BuildLogOutRequestResultDto>> BuildLogOutRequestAsync(BuildLogOutRequestDto request,
            CancellationToken cancellationToken = default);

        /// <summary>
        ///     Build/generate logout response.
        /// </summary>
        /// <exception cref="System.OperationCanceledException">
        ///     The <paramref name="cancellationToken" /> was canceled.
        /// </exception>
        /// <param name="request">Required. Input params used to build/generate logout response.</param>
        /// <param name="cancellationToken">(Optional) Optional. The default value is default.</param>
        /// <returns>
        ///     Return result details necessary to create full logout response.
        /// </returns>
        Task<IResult<BuildLogOutResponseResultDto>> BuildLogOutResponseAsync(BuildLogOutResponseDto request,
            CancellationToken cancellationToken = default);
    }
}