// ***********************************************************************
//  Assembly         : RzR.Shared.eGovMD.MPassHelperDotNet
//  Author           : RzR
//  Created On       : 2023-06-23 14:41
// 
//  Last Modified By : RzR
//  Last Modified On : 2023-06-28 16:26
// ***********************************************************************
//  <copyright file="BuildLogOutResponseResultDto.cs" company="">
//   Copyright (c) RzR. All rights reserved.
//  </copyright>
// 
//  <summary>
//  </summary>
// ***********************************************************************

// ReSharper disable UnusedAutoPropertyAccessor.Global

namespace MPassHelperDotNet.Models.Dto.RequestBuilder.LogOutResponse
{
    /// <summary>
    ///     Build logout response
    /// </summary>
    public class BuildLogOutResponseResultDto
    {
        /// <summary>
        ///     Logout response id, uniq id for identification
        /// </summary>
        public string LogoutResponseId { get; set; }

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