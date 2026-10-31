// ***********************************************************************
//  Assembly         : RzR.Shared.eGovMD.MPassHelperDotNet
//  Author           : RzR
//  Created On       : 2023-06-23 14:43
// 
//  Last Modified By : RzR
//  Last Modified On : 2023-06-28 16:26
// ***********************************************************************
//  <copyright file="GenerateLogOutRequestResultDto.cs" company="">
//   Copyright (c) RzR. All rights reserved.
//  </copyright>
// 
//  <summary>
//  </summary>
// ***********************************************************************

// ReSharper disable UnusedAutoPropertyAccessor.Global

namespace MPassHelperDotNet.Models.Dto.AuthService.LogoutRequest
{
    /// <summary>
    ///     Generate logout request
    /// </summary>
    public class GenerateLogOutRequestResultDto
    {
        /// <summary>
        ///     Logout request id, uniq id for identification.
        /// </summary>
        /// <remarks>
        ///     Store it per browser session in server-side storage (never in a client value); take (read
        ///     and remove) it before the logout SAMLResponse is validated, whatever the outcome, so it
        ///     is used only once.
        /// </remarks>
        /// <value>
        ///     The identifier of the log out request.
        /// </value>
        public string LogOutRequestId { get; set; }

        /// <summary>
        ///     HTML template send to service provider.
        /// </summary>
        /// <remarks>
        ///     Serve it with <c>Cache-Control: no-store</c>; it carries a single-use signed SAML message.
        /// </remarks>
        /// <value>
        ///     The HTML document.
        /// </value>
        public string HtmlDocument { get; set; }
    }
}