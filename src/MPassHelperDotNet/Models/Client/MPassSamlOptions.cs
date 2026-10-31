// ***********************************************************************
//  Assembly         : RzR.Shared.eGovMD.MPassHelperDotNet
//  Author           : RzR
//  Created On       : 2023-06-20 17:36
// 
//  Last Modified By : RzR
//  Last Modified On : 2026-09-23 14:19
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
using MPassHelperDotNet.Helpers;

// ReSharper disable ClassNeverInstantiated.Global
// ReSharper disable UnusedAutoPropertyAccessor.Global

#endregion

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
        ///     Identity provider issuer (the MPass IdP metadata EntityID). Required.
        ///     Inbound messages and assertions must carry exactly this issuer.
        /// </summary>
        public string IdentityProviderIssuer { get; set; }

        /// <summary>
        ///     Optional additional identity provider certificate paths (*.CER/PEM), used during IdP certificate rotation.
        ///     A signature is accepted when it verifies with the primary or any additional certificate.
        /// </summary>
        public string[] IdentityProviderAdditionalCertificatePaths { get; set; }

        /// <summary>
        ///     Allowed clock skew between this service and the identity provider.
        ///     Default value is 2 minutes; the maximum accepted value is 5 minutes.
        /// </summary>
        public TimeSpan SamlClockSkew { get; set; } = TimeSpan.FromMinutes(2);

        /// <summary>
        ///     Allow inbound RSA-SHA1/SHA-1 signatures.
        ///     Default value is false; enable it only if the identity provider cannot sign with SHA-256 or stronger.
        /// </summary>
        public bool AllowSha1Signatures { get; set; }

        /// <summary>
        ///     Maximum accepted length (characters) of an inbound Base64 SAML message.
        ///     Default value is 262144.
        /// </summary>
        public int SamlMessageMaxLength { get; set; } = DefaultStaticInfo.DefaultSamlMessageMaxLength;

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
        ///     Identity provider certificates (X509) trusted for inbound signatures: the primary
        ///     <see cref="IdentityProviderCertificate" /> followed by the certificates from
        ///     <see cref="IdentityProviderAdditionalCertificatePaths" />. Populated on post configuration.
        /// </summary>
        public X509Certificate2Collection IdentityProviderCertificates { get; set; } = new X509Certificate2Collection();

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