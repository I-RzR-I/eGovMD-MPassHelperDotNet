// ***********************************************************************
//  Assembly         : RzR.Shared.eGovMD.MPassHelperDotNet
//  Author           : RzR
//  Created On       : 2023-06-23 14:40
// 
//  Last Modified By : RzR
//  Last Modified On : 2026-09-22 15:51
// ***********************************************************************
//  <copyright file="BuildLogInRequestResultDto.cs" company="">
//   Copyright (c) RzR. All rights reserved.
//  </copyright>
// 
//  <summary>
//  </summary>
// ***********************************************************************

// ReSharper disable UnusedAutoPropertyAccessor.Global

namespace MPassHelperDotNet.Models.Dto.RequestBuilder.LoginRequest
{
    /// <summary>
    ///     Build login/auth request
    /// </summary>
    public class BuildLogInRequestResultDto
    {
        /// <summary>
        ///     Auth/login request id, uniq id for identification
        /// </summary>
        public string AuthRequestId { get; set; }

        /// <summary>
        ///     HTML template used to response to issuer
        /// </summary>
        /// <remarks>Serve it with <c>Cache-Control: no-store</c>; it carries a single-use signed SAML message.</remarks>
        public string HtmlAuthDocument { get; set; }

        /// <summary>
        ///     SAMLResponse message
        /// </summary>
        /// <remarks>
        ///     Despite its name, this property carries the signed SAML AuthnRequest (Base64), sent to the identity
        ///     provider as the <c>SAMLRequest</c> form value. The name is kept for backward compatibility.
        /// </remarks>
        public string SamlResponse { get; set; }
    }
}