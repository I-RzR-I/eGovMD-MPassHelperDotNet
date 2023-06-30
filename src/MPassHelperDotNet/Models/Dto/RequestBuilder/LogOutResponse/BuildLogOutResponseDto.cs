// ***********************************************************************
//  Assembly         : RzR.Shared.eGovMD.MPassHelperDotNet
//  Author           : RzR
//  Created On       : 2023-06-23 14:41
// 
//  Last Modified By : RzR
//  Last Modified On : 2023-06-28 16:26
// ***********************************************************************
//  <copyright file="BuildLogOutResponseDto.cs" company="">
//   Copyright (c) RzR. All rights reserved.
//  </copyright>
// 
//  <summary>
//  </summary>
// ***********************************************************************

// ReSharper disable ClassNeverInstantiated.Global
// ReSharper disable UnusedAutoPropertyAccessor.Global

namespace MPassHelperDotNet.Models.Dto.RequestBuilder.LogOutResponse
{
    /// <summary>
    ///     Build logout response input params
    /// </summary>
    public class BuildLogOutResponseDto
    {
        /// <summary>
        ///     SAML logout request
        /// </summary>
        public string SamlRequest { get; set; }

        /// <summary>
        ///     Gets or sets auth relay state.
        /// </summary>
        /// <value></value>
        /// <remarks></remarks>
        public string RelayState { get; set; } = "LogoutResponse Relay State";

        /// <summary>
        ///     User session id, stored after successfully login
        /// </summary>
        public string UserSessionIndexId { get; set; }

        /// <summary>
        ///     User identifier code
        /// </summary>
        public string UserIdentifierId { get; set; }
    }
}