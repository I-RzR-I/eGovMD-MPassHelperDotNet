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

        /// <summary>
        ///     Gets or sets a value indicating whether the identity
        ///     provider is asked to authenticate the user again.
        /// </summary>
        public bool ForceAuthn { get; set; }

        /// <summary>
        ///     Gets or sets a value indicating whether the identity 
        ///     provider is asked not to interact with the user.
        /// </summary>
        public bool IsPassive { get; set; }

        /// <summary>
        ///     Gets or sets the preferred language of the identity provider login page.
        /// </summary>
        public string Language { get; set; }
    }
}