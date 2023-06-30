// ***********************************************************************
//  Assembly         : RzR.Shared.eGovMD.MPassHelperDotNet
//  Author           : RzR
//  Created On       : 2023-06-23 14:44
// 
//  Last Modified By : RzR
//  Last Modified On : 2023-06-28 16:26
// ***********************************************************************
//  <copyright file="GetUserDataFromAuthResponseResultDto.cs" company="">
//   Copyright (c) RzR. All rights reserved.
//  </copyright>
// 
//  <summary>
//  </summary>
// ***********************************************************************

#region U S A G E S

using System.Collections.Generic;

// ReSharper disable UnusedAutoPropertyAccessor.Global

#endregion

namespace MPassHelperDotNet.Models.Dto.AuthService.LoginResponse
{
    /// <summary>
    ///     Get user profile information
    /// </summary>
    public class GetUserDataFromAuthResponseResultDto
    {
        /// <summary>
        ///     User information details
        /// </summary>
        public AuthMPassUserInfo UserInfo { get; set; }

        /// <summary>
        ///     User information attributes received from SAMLResponse
        /// </summary>
        public Dictionary<string, IList<string>> UserAttributes { get; set; }

        /// <summary>
        ///     Authentication session id
        /// </summary>
        public string SessionIndexId { get; set; }
    }
}