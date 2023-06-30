// ***********************************************************************
//  Assembly         : RzR.Shared.eGovMD.MPassHelperDotNet
//  Author           : RzR
//  Created On       : 2023-06-23 16:31
// 
//  Last Modified By : RzR
//  Last Modified On : 2023-06-28 16:26
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
        public string LogOutRequestId { get; set; }

        /// <summary>
        ///     SAMLResponse message received from auth service provider
        /// </summary>
        public string SamlResponse { get; set; }
    }
}