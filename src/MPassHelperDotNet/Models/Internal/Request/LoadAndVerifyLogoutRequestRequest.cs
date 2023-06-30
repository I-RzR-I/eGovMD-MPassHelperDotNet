// ***********************************************************************
//  Assembly         : RzR.Shared.eGovMD.MPassHelperDotNet
//  Author           : RzR
//  Created On       : 2023-06-19 17:57
// 
//  Last Modified By : RzR
//  Last Modified On : 2023-06-28 16:26
// ***********************************************************************
//  <copyright file="LoadAndVerifyLogoutRequestRequest.cs" company="">
//   Copyright (c) RzR. All rights reserved.
//  </copyright>
// 
//  <summary>
//  </summary>
// ***********************************************************************

#region U S A G E S

using System;
using System.Security.Cryptography.X509Certificates;

#endregion

// ReSharper disable ClassNeverInstantiated.Global
// ReSharper disable UnusedAutoPropertyAccessor.Global

namespace MPassHelperDotNet.Models.Internal.Request
{
    /// <summary>
    ///     Load and verify LOGOUT request(request data)
    /// </summary>
    public class LoadAndVerifyLogoutRequestRequest
    {
        /// <summary>
        ///     SAML request
        /// </summary>
        public string SamlRequest { get; set; }

        /// <summary>
        ///     Identity provider certificate
        /// </summary>
        public X509Certificate2 IdpCertificate { get; set; }

        /// <summary>
        ///     Excepted destination URL
        /// </summary>
        public string ExpectedDestination { get; set; }

        /// <summary>
        ///     Timeout
        /// </summary>
        public TimeSpan TimeOut { get; set; }

        /// <summary>
        ///     Excepted user id (user identifier code/id)
        /// </summary>
        public string ExpectedNameId { get; set; }

        /// <summary>
        ///     Excepted user session id/index
        /// </summary>
        public string ExpectedSessionIndex { get; set; }
    }
}