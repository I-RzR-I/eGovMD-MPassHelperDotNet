// ***********************************************************************
//  Assembly         : RzR.Shared.eGovMD.MPassHelperDotNet
//  Author           : RzR
//  Created On       : 2023-06-19 10:00
// 
//  Last Modified By : RzR
//  Last Modified On : 2026-09-23 09:58
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
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Logging.Abstractions;
using MPassHelperDotNet.Helpers;

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

        /// <summary>
        ///     Identity provider certificates trusted for the signature (primary and rotation certificates).
        /// </summary>
        internal X509Certificate2Collection IdpCertificates { get; set; }

        /// <summary>
        ///     Expected issuer (identity provider EntityID)
        /// </summary>
        internal string ExpectedIssuer { get; set; }

        /// <summary>
        ///     Allowed clock skew
        /// </summary>
        internal TimeSpan ClockSkew { get; set; }

        /// <summary>
        ///     Current UTC time used for every time validation
        /// </summary>
        internal DateTime CurrentUtc { get; set; }

        /// <summary>
        ///     Allow RSA-SHA1/SHA-1 signatures
        /// </summary>
        internal bool AllowSha1Signatures { get; set; }

        /// <summary>
        ///     Maximum accepted length (characters) of the Base64 SAML message
        /// </summary>
        internal int MaxMessageLength { get; set; } = DefaultStaticInfo.DefaultSamlMessageMaxLength;

        /// <summary>
        ///     Logger for caught exceptions (never for payloads). Defaults to <see cref="NullLogger.Instance" />.
        /// </summary>
        internal ILogger Logger { get; set; } = NullLogger.Instance;
    }
}