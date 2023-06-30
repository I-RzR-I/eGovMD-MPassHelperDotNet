// ***********************************************************************
//  Assembly         : RzR.Shared.eGovMD.MPassHelperDotNet
//  Author           : RzR
//  Created On       : 2023-06-23 18:28
// 
//  Last Modified By : RzR
//  Last Modified On : 2023-06-28 16:26
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
        public string SamlRequest { get; set; }

        /// <summary>
        ///     Logout relay state
        /// </summary>
        public string RelayState { get; set; }

        /// <summary>
        ///     User session id, stored after successfully login
        /// </summary>
        public string SessionIndexId { get; set; }

        /// <summary>
        ///     User identifier code
        /// </summary>
        public string UserIdentifierId { get; set; }
    }
}