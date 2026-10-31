// ***********************************************************************
//  Assembly         : RzR.Shared.eGovMD.MPassHelperDotNet
//  Author           : RzR
//  Created On       : 2023-06-23 14:43
// 
//  Last Modified By : RzR
//  Last Modified On : 2023-06-28 16:26
// ***********************************************************************
//  <copyright file="GenerateAuthRequestResultDto.cs" company="">
//   Copyright (c) RzR. All rights reserved.
//  </copyright>
// 
//  <summary>
//  </summary>
// ***********************************************************************

// ReSharper disable UnusedAutoPropertyAccessor.Global

namespace MPassHelperDotNet.Models.Dto.AuthService.LoginRequest
{
    /// <summary>
    ///     Generate auth response result details
    /// </summary>
    public class GenerateAuthRequestResultDto
    {
        /// <summary>
        ///     Auth/login request id, uniq id for identification
        /// </summary>
        /// <remarks>
        ///     Store it per browser session in server-side storage (never in a client value); take (read and remove) it
        ///     before the SAMLResponse is validated, whatever the outcome, so it is used only once.
        /// </remarks>
        public string AuthRequestId { get; set; }

        /// <summary>
        ///     HTML template used to response to issuer
        /// </summary>
        /// <remarks>Serve it with <c>Cache-Control: no-store</c>; it carries a single-use signed SAML message.</remarks>
        public string HtmlDocument { get; set; }
    }
}