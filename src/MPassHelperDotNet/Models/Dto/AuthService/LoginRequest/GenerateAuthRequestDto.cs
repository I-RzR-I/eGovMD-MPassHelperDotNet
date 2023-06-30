// ***********************************************************************
//  Assembly         : RzR.Shared.eGovMD.MPassHelperDotNet
//  Author           : RzR
//  Created On       : 2023-06-23 14:43
// 
//  Last Modified By : RzR
//  Last Modified On : 2023-06-28 16:26
// ***********************************************************************
//  <copyright file="GenerateAuthRequestDto.cs" company="">
//   Copyright (c) RzR. All rights reserved.
//  </copyright>
// 
//  <summary>
//  </summary>
// ***********************************************************************

// ReSharper disable ClassNeverInstantiated.Global

namespace MPassHelperDotNet.Models.Dto.AuthService.LoginRequest
{
    /// <summary>
    ///     Generate SAML auth request
    /// </summary>
    public class GenerateAuthRequestDto
    {
        /// <summary>
        ///     Auth relay state
        /// </summary>
        public string RelayState { get; set; }
    }
}