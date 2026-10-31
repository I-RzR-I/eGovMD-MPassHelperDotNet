// ***********************************************************************
//  Assembly         : RzR.Shared.eGovMD.MPassHelperDotNet
//  Author           : RzR
//  Created On       : 2023-06-23 16:31
// 
//  Last Modified By : RzR
//  Last Modified On : 2026-09-22 15:03
// ***********************************************************************
//  <copyright file="ValidateLogoutResponseDto.cs" company="">
//   Copyright (c) RzR. All rights reserved.
//  </copyright>
// 
//  <summary>
//  </summary>
// ***********************************************************************

// ReSharper disable ClassNeverInstantiated.Global
// ReSharper disable UnusedAutoPropertyAccessor.Global

namespace MPassHelperDotNet.Models.Dto.AuthService.LogoutResponse
{
    /// <summary>
    ///     Validation logout response
    /// </summary>
    public class ValidateLogoutResponseDto
    {
        /// <summary>
        ///     Logout request id, uniq id for identification
        /// </summary>
        /// <remarks>
        ///     Required. Take (read and remove) it from server-side storage (for example the user session) before the call,
        ///     whatever the outcome; never accept it from the POST body or the RelayState.
        /// </remarks>
        public string LogOutRequestId { get; set; }

        /// <summary>
        ///     SAMLResponse message received from auth service provider
        /// </summary>
        /// <remarks>Required.</remarks>
        public string SamlResponse { get; set; }
    }
}