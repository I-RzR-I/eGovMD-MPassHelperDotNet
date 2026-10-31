// ***********************************************************************
//  Assembly         : RzR.Shared.eGovMD.MPassHelperDotNet
//  Author           : RzR
//  Created On       : 2023-06-23 14:43
// 
//  Last Modified By : RzR
//  Last Modified On : 2026-09-22 12:12
// ***********************************************************************
//  <copyright file="GenerateLogOutRequestDto.cs" company="">
//   Copyright (c) RzR. All rights reserved.
//  </copyright>
// 
//  <summary>
//  </summary>
// ***********************************************************************

// ReSharper disable ClassNeverInstantiated.Global

namespace MPassHelperDotNet.Models.Dto.AuthService.LogoutRequest
{
    /// <summary>
    ///     Generate logout request
    /// </summary>
    public class GenerateLogOutRequestDto
    {
        /// <summary>
        ///     User session id, stored after successfully login
        /// </summary>
        public string SessionIndexId { get; set; }

        /// <summary>
        ///     Logout relay state
        /// </summary>
        /// <remarks>Required. Limited to 80 bytes (UTF-8).</remarks>
        public string RelayState { get; set; }

        /// <summary>
        ///     User identifier code id
        /// </summary>
        public string UserIdentifierId { get; set; }
    }
}