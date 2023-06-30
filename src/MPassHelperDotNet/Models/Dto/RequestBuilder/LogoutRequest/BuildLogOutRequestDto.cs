// ***********************************************************************
//  Assembly         : RzR.Shared.eGovMD.MPassHelperDotNet
//  Author           : RzR
//  Created On       : 2023-06-23 14:41
// 
//  Last Modified By : RzR
//  Last Modified On : 2023-06-28 16:26
// ***********************************************************************
//  <copyright file="BuildLogOutRequestDto.cs" company="">
//   Copyright (c) RzR. All rights reserved.
//  </copyright>
// 
//  <summary>
//  </summary>
// ***********************************************************************

// ReSharper disable ClassNeverInstantiated.Global
// ReSharper disable UnusedAutoPropertyAccessor.Global

namespace MPassHelperDotNet.Models.Dto.RequestBuilder.LogoutRequest
{
    /// <summary>
    ///     Logout build request params
    /// </summary>
    public class BuildLogOutRequestDto
    {
        /// <summary>
        ///     Gets or sets auth relay state.
        /// </summary>
        /// <value></value>
        /// <remarks></remarks>
        public string RelayState { get; set; } = "LogoutRequest Relay State";

        /// <summary>
        ///     User identifier code/id. Currently is user IDNP
        /// </summary>
        public string UserIdentifierId { get; set; }

        /// <summary>
        ///     User current session index/id or key
        /// </summary>
        public string UserSessionId { get; set; }
    }
}