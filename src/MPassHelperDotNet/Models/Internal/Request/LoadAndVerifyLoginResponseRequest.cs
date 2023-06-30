// ***********************************************************************
//  Assembly         : RzR.Shared.eGovMD.MPassHelperDotNet
//  Author           : RzR
//  Created On       : 2023-06-18 02:02
// 
//  Last Modified By : RzR
//  Last Modified On : 2023-06-28 16:26
// ***********************************************************************
//  <copyright file="LoadAndVerifyLoginResponseRequest.cs" company="">
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
    ///     Load and verify LogIn SAML response (request data)
    /// </summary>
    public class LoadAndVerifyLoginResponseRequest
    {
        /// <summary>
        ///     SAML response message
        /// </summary>
        public string SamlResponse { get; set; }

        /// <summary>
        ///     IDP certificate
        /// </summary>
        public X509Certificate2 IdpCertificate { get; set; }

        /// <summary>
        ///     Destination
        /// </summary>
        public string ExpectedDestination { get; set; }

        /// <summary>
        ///     Timeout
        /// </summary>
        public TimeSpan TimeOut { get; set; }

        /// <summary>
        ///     Auth request id
        /// </summary>
        public string ExpectedRequestId { get; set; }

        /// <summary>
        ///     Expected audience
        /// </summary>
        public string ExpectedAudience { get; set; }
    }
}