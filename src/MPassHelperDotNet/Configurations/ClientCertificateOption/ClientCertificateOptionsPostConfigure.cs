// ***********************************************************************
//  Assembly         : RzR.Shared.eGovMD.MPassHelperDotNet
//  Author           : RzR
//  Created On       : 2023-06-13 20:41
// 
//  Last Modified By : RzR
//  Last Modified On : 2026-09-24 18:28
// ***********************************************************************
//  <copyright file="ClientCertificateOptionsPostConfigure.cs" company="">
//   Copyright (c) RzR. All rights reserved.
//  </copyright>
// 
//  <summary>
//  </summary>
// ***********************************************************************

#region U S A G E S

using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Security;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using RzR.Extensions.Domain.Primitives;
using RzR.Extensions.Domain.Text;
using Microsoft.Extensions.Options;
using MPassHelperDotNet.Configurations.Certificate;
using MPassHelperDotNet.Models.Client;

// ReSharper disable ClassNeverInstantiated.Global

#endregion

namespace MPassHelperDotNet.Configurations.ClientCertificateOption
{
    /// <summary>
    ///     Client certificate POST configuration options
    /// </summary>
    public class ClientCertificateOptionsPostConfigure : IPostConfigureOptions<MPassSamlOptions>
    {
        /// <summary>
        ///     POST configuration.
        /// </summary>
        /// <param name="name">Options name</param>
        /// <param name="options">Client certificate option</param>
        public void PostConfigure(string name, MPassSamlOptions options)
        {
            if (options.IsNull())
                return;

            // The loader returns null for a blank path; the password stays required so a password-less PFX is not accepted.
            if (!options.ServiceCertificatePassword.IsNullOrEmpty())
            {
                options.ServiceCertificate = TryLoad(() => CertificateLoader.Private(
                    options.ServiceCertificatePath,
                    options.ServiceCertificatePassword));
            }

            var idpCertificates = TryLoad(() => CertificateLoader.LoadAll(GetIdentityProviderCertificatePaths(options)))
                                  ?? new X509Certificate2Collection();

            options.IdentityProviderCertificates = idpCertificates;
            options.IdentityProviderCertificate = idpCertificates.Count.IsGreaterThanZero() ? idpCertificates[0] : null;

            options.ServiceCertificatePassword = null;
        }

        /// <summary>
        ///     Get the identity provider certificate paths: the primary path followed by the additional
        ///     rotation paths.
        /// </summary>
        /// <param name="options">MPass options.</param>
        /// <returns>
        ///     Return the configured paths in order, trimmed, without blank entries and without repeated
        ///     paths.
        /// </returns>
        internal static IList<string> GetIdentityProviderCertificatePaths(MPassSamlOptions options)
            => new[] { options.IdentityProviderCertificatePath }
                .Concat(options.IdentityProviderAdditionalCertificatePaths ?? Array.Empty<string>())
                .Where(path => !string.IsNullOrWhiteSpace(path))
                .Select(path => path.Trim())
                .Distinct(StringComparer.Ordinal)
                .ToList();

        /// <summary>
        ///     Run a certificate load and return null when the file is missing, unreadable or not a
        ///     valid certificate.
        /// </summary>
        /// <typeparam name="T">Loaded value type.</typeparam>
        /// <param name="load">Load function.</param>
        /// <returns>
        ///     Return the loaded value or null.
        /// </returns>
        private static T TryLoad<T>(Func<T> load) where T : class
        {
            try
            {
                return load();
            }
            catch (Exception e) when (e is CryptographicException or IOException or UnauthorizedAccessException
                                          or SecurityException or FormatException or ArgumentException or NotSupportedException)
            {
                return null;
            }
        }
    }
}