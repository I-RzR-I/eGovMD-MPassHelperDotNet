// ***********************************************************************
//  Assembly         : RzR.Shared.eGovMD.MPassHelperDotNet
//  Author           : RzR
//  Created On       : 2023-06-23 14:43
// 
//  Last Modified By : RzR
//  Last Modified On : 2026-09-23 14:31
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
        /// <remarks>Required. Limited to 80 bytes (UTF-8).</remarks>
        public string RelayState { get; set; }

        /// <summary>
        ///     Ask the identity provider to authenticate the user again, 
        ///     even when a session already exists.
        /// </summary>
        public bool ForceAuthn { get; set; }

        /// <summary>
        ///     Ask the identity provider not to interact with the user (silent sign-in check)
        /// </summary>
        public bool IsPassive { get; set; }

        /// <summary>
        ///     Preferred language of the identity provider login page
        /// </summary>
        public string Language { get; set; }
    }
}