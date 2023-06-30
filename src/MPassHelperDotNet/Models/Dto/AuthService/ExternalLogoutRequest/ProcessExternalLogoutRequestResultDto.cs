// ***********************************************************************
//  Assembly         : RzR.Shared.eGovMD.MPassHelperDotNet
//  Author           : RzR
//  Created On       : 2023-06-23 18:28
// 
//  Last Modified By : RzR
//  Last Modified On : 2023-06-28 16:26
// ***********************************************************************
//  <copyright file="ProcessExternalLogoutRequestResultDto.cs" company="">
//   Copyright (c) RzR. All rights reserved.
//  </copyright>
// 
//  <summary>
//  </summary>
// ***********************************************************************

// ReSharper disable UnusedAutoPropertyAccessor.Global

namespace MPassHelperDotNet.Models.Dto.AuthService.ExternalLogoutRequest
{
    /// <summary>
    ///     Process external logout request
    /// </summary>
    public class ProcessExternalLogoutRequestResultDto
    {
        /// <summary>
        ///     Logout response id, uniq id for identification
        /// </summary>
        public string LogoutResponseId { get; set; }

        /// <summary>
        ///     HTML template used to response to issuer
        /// </summary>
        public string HtmlDocument { get; set; }
    }
}