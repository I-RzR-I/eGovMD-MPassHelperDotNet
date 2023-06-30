// ***********************************************************************
//  Assembly         : RzR.Shared.eGovMD.MPassHelperDotNet
//  Author           : RzR
//  Created On       : 2023-06-23 14:40
// 
//  Last Modified By : RzR
//  Last Modified On : 2023-06-28 16:26
// ***********************************************************************
//  <copyright file="BuildLogInRequestDto.cs" company="">
//   Copyright (c) RzR. All rights reserved.
//  </copyright>
// 
//  <summary>
//  </summary>
// ***********************************************************************

// ReSharper disable ClassNeverInstantiated.Global

namespace MPassHelperDotNet.Models.Dto.RequestBuilder.LoginRequest
{
    /// <summary>
    ///     Build login request input data
    /// </summary>
    public class BuildLogInRequestDto
    {
        /// <summary>
        ///     Gets or sets auth relay state.
        /// </summary>
        /// <value></value>
        /// <remarks></remarks>
        public string RelayState { get; set; } = "LoginRequest Relay State";
    }
}