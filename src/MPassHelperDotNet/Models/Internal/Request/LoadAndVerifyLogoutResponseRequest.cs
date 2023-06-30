// ***********************************************************************
//  Assembly         : RzR.Shared.eGovMD.MPassHelperDotNet
//  Author           : RzR
//  Created On       : 2023-06-19 10:00
// 
//  Last Modified By : RzR
//  Last Modified On : 2023-06-28 16:26
// ***********************************************************************
//  <copyright file="LoadAndVerifyLogoutResponseRequest.cs" company="">
//   Copyright (c) RzR. All rights reserved.
//  </copyright>
// 
//  <summary>
//  </summary>
// ***********************************************************************

#region U S A G E S

using System;
using System.Security.Cryptography.X509Certificates;

// ReSharper disable ClassNeverInstantiated.Global
// ReSharper disable UnusedAutoPropertyAccessor.Global

#endregion

namespace MPassHelperDotNet.Models.Internal.Request
{
    /// <summary>
    ///     Load and verify SAML response request model
    /// </summary>
    public class LoadAndVerifyLogoutResponseRequest
    {
        /// <summary>
        ///     SAML response
        /// </summary>
        public string SamlResponse { get; set; }

        /// <summary>
        ///     X509 IdP certificate
        /// </summary>
        public X509Certificate2 IdpCertificate { get; set; }

        /// <summary>
        ///     Excepted destination
        /// </summary>
        public string ExpectedDestination { get; set; }

        /// <summary>
        ///     Timeout
        /// </summary>
        public TimeSpan TimeOut { get; set; }

        /// <summary>
        ///     Excepted request id
        /// </summary>
        public string ExpectedRequestId { get; set; }
    }
}