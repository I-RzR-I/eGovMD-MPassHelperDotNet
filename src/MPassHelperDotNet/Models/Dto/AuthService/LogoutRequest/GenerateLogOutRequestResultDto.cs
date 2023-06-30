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
        ///     Logout request id, uniq id for identification
        /// </summary>
        public string LogOutRequestId { get; set; }

        /// <summary>
        ///     HTML template send to service provider
        /// </summary>
        public string HtmlDocument { get; set; }
    }
}