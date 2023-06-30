// ***********************************************************************
//  Assembly         : RzR.Shared.eGovMD.MPassHelperDotNet
//  Author           : RzR
//  Created On       : 2023-06-23 14:41
// 
//  Last Modified By : RzR
//  Last Modified On : 2023-06-28 16:26
// ***********************************************************************
//  <copyright file="BuildLogOutRequestResultDto.cs" company="">
//   Copyright (c) RzR. All rights reserved.
//  </copyright>
// 
//  <summary>
//  </summary>
// ***********************************************************************

// ReSharper disable UnusedAutoPropertyAccessor.Global

namespace MPassHelperDotNet.Models.Dto.RequestBuilder.LogoutRequest
{
    /// <summary>
    ///     Build logout request
    /// </summary>
    public class BuildLogOutRequestResultDto
    {
        /// <summary>
        ///     Logout request id, uniq id for identification
        /// </summary>
        public string LogoutRequestId { get; set; }

        /// <summary>
        ///     HTML template used to response to issuer
        /// </summary>
        public string HtmlAuthDocument { get; set; }

        /// <summary>
        ///     SAMLRequest message
        /// </summary>
        public string SamlRequest { get; set; }
    }
}