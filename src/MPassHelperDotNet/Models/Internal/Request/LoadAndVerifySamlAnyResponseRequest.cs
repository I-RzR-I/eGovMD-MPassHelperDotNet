// ***********************************************************************
//  Assembly         : RzR.Shared.eGovMD.MPassHelperDotNet
//  Author           : RzR
//  Created On       : 2023-06-17 21:43
// 
//  Last Modified By : RzR
//  Last Modified On : 2023-06-28 16:26
// ***********************************************************************
//  <copyright file="LoadAndVerifySamlAnyResponseRequest.cs" company="">
//   Copyright (c) RzR. All rights reserved.
//  </copyright>
// 
//  <summary>
//  </summary>
// ***********************************************************************

#region U S A G E S

using System;
using System.Collections.Generic;
using System.Security.Cryptography.X509Certificates;

// ReSharper disable UnusedAutoPropertyAccessor.Global
// ReSharper disable ClassNeverInstantiated.Global

#endregion


namespace MPassHelperDotNet.Models.Internal.Request
{
    /// <summary>
    ///     Load and verify SAML response request model
    /// </summary>
    internal class LoadAndVerifySamlAnyResponseRequest
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
        ///     Request id
        /// </summary>
        public string ExpectedRequestId { get; set; }

        /// <summary>
        ///     Status code to be validated
        /// </summary>
        public IEnumerable<string> ValidStatusCodes { get; set; }
    }
}