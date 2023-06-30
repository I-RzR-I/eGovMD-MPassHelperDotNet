// ***********************************************************************
//  Assembly         : RzR.Shared.eGovMD.MPassHelperDotNet
//  Author           : RzR
//  Created On       : 2023-06-23 14:40
// 
//  Last Modified By : RzR
//  Last Modified On : 2023-06-28 16:26
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
        public string HtmlAuthDocument { get; set; }

        /// <summary>
        ///     SAMLResponse message
        /// </summary>
        public string SamlResponse { get; set; }
    }
}