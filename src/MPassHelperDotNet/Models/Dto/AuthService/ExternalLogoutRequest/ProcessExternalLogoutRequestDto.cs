// ***********************************************************************
//  Assembly         : RzR.Shared.eGovMD.MPassHelperDotNet
//  Author           : RzR
//  Created On       : 2023-06-23 18:28
// 
//  Last Modified By : RzR
//  Last Modified On : 2026-09-23 13:05
// ***********************************************************************
//  <copyright file="ProcessExternalLogoutRequestDto.cs" company="">
//   Copyright (c) RzR. All rights reserved.
//  </copyright>
// 
//  <summary>
//  </summary>
// ***********************************************************************

// ReSharper disable ClassNeverInstantiated.Global
// ReSharper disable UnusedAutoPropertyAccessor.Global

namespace MPassHelperDotNet.Models.Dto.AuthService.ExternalLogoutRequest
{
    /// <summary>
    ///     Process external logout request and generate logout response
    /// </summary>
    public class ProcessExternalLogoutRequestDto
    {
        /// <summary>
        ///     Logout SAMLRequest message received from external auth service provider
        /// </summary>
        /// <remarks>Required.</remarks>
        public string SamlRequest { get; set; }

        /// <summary>
        ///     Logout relay state
        /// </summary>
        /// <remarks>Optional. Limited to 80 bytes (UTF-8).</remarks>
        public string RelayState { get; set; }

        /// <summary>
        ///     User session id, stored after successfully login
        /// </summary>
        /// <remarks>Required. The LogoutRequest must contain this session index.</remarks>
        public string SessionIndexId { get; set; }

        /// <summary>
        ///     User identifier code
        /// </summary>
        /// <remarks>Required. The LogoutRequest NameID must match this value.</remarks>
        public string UserIdentifierId { get; set; }
    }
}