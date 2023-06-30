// ***********************************************************************
//  Assembly         : RzR.Shared.eGovMD.MPassHelperDotNet
//  Author           : RzR
//  Created On       : 2023-06-20 17:36
// 
//  Last Modified By : RzR
//  Last Modified On : 2023-06-28 16:26
// ***********************************************************************
//  <copyright file="MPassSamlOptions.cs" company="">
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

namespace MPassHelperDotNet.Models.Client
{
    /// <summary>
    ///     MPass options
    /// </summary>
    public class MPassSamlOptions
    {
        /// <summary>
        ///     SAML request issuer service
        /// </summary>
        public string SamlRequestIssuer { get; set; }

        /// <summary>
        ///     Service certificate path
        /// </summary>
        public string ServiceCertificatePath { get; set; }

        /// <summary>
        ///     Service certificate password
        /// </summary>
        public string ServiceCertificatePassword { get; set; }

        /// <summary>
        ///     Identity provider certificate path with certificate (*.CER)
        /// </summary>
        public string IdentityProviderCertificatePath { get; set; }

        /// <summary>
        ///     SAML message timeout.
        ///     Default value is 10 minutes.
        /// </summary>
        public TimeSpan SamlMessageTimeout { get; set; } = TimeSpan.FromMinutes(10);

        /// <summary>
        ///     SAML login destination URL
        /// </summary>
        public string SamlLoginDestination { get; set; }

        /// <summary>
        ///     SAML logout destination URL
        /// </summary>
        public string SamlLogoutDestination { get; set; }

        //  Additional fields

        /// <summary>
        ///     Service certificate (X509).
        /// </summary>
        public X509Certificate2 ServiceCertificate { get; set; }

        /// <summary>
        ///     Identity service certificate (X509).
        /// </summary>
        public X509Certificate2 IdentityProviderCertificate { get; set; }

        /// <summary>
        ///     Current service login destination (URL)
        /// </summary>
        public string SamlServiceLoginDestination { get; set; }

        /// <summary>
        ///     Current service logout destination (URL)
        /// </summary>
        public string SamlServiceLogoutDestination { get; set; }

        /// <summary>
        ///     Current service single logout destination (URL)
        /// </summary>
        public string SamlServiceSingleLogoutDestination { get; set; }
    }
}