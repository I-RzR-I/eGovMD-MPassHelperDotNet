// ***********************************************************************
//  Assembly         : RzR.Shared.eGovMD.MPassHelperDotNet
//  Author           : RzR
//  Created On       : 2023-06-13 20:41
// 
//  Last Modified By : RzR
//  Last Modified On : 2026-09-24 08:58
// ***********************************************************************
//  <copyright file="CertificateLoader.cs" company="">
//   Copyright (c) RzR. All rights reserved.
//  </copyright>
// 
//  <summary>
//  </summary>
// ***********************************************************************

#region U S I N G

using MPassHelperDotNet.Extensions;
using MPassHelperDotNet.Models.Client;
using RzR.Extensions.Domain.Primitives;
using System;
using System.Collections.Generic;
using System.IO;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;

#if  NETSTANDARD2_0

using RzR.Extensions.Domain.Text;

#endif

#if NETSTANDARD2_1_OR_GREATER || NET

using System.Runtime.CompilerServices;

#endif

#endregion

// ReSharper disable IdentifierTypo
// ReSharper disable ExpressionIsAlwaysNull
// ReSharper disable JoinDeclarationAndInitializer

namespace MPassHelperDotNet.Configurations.Certificate
{
    /// <summary>
    ///     Certificate loader.
    /// </summary>
    internal static class CertificateLoader
    {
        /// <summary>
        ///     (Immutable)
        ///     X509KeyStorageFlags.EphemeralKeySet (value 32); not part of the netstandard2.0 API
        ///     surface.
        /// </summary>
        private const X509KeyStorageFlags EphemeralKeySet = (X509KeyStorageFlags)32;

        /// <summary>
        ///     Load public certificate.
        /// </summary>
        /// <param name="certificatePath">Certificate path.</param>
        /// <returns>
        ///     An X509Certificate2.
        /// </returns>
        internal static X509Certificate2 Public(string certificatePath)
        {
            if (string.IsNullOrWhiteSpace(certificatePath))
                return null;

            var certificate = LoadPublicCertificateFromChain(certificatePath);
            return !certificate.IsNull()
                ? certificate
                : File.Exists(certificatePath)
                    ? new X509Certificate2(certificatePath)
                    : !Directory.Exists(certificatePath)
                        ? null
                        : LoadPublicCertificateFromChain(Path.Combine(certificatePath, "tls.crt"));
        }

        /// <summary>
        ///     Load all public certificates (primary and rotation identity provider certificates)
        /// </summary>
        /// <param name="paths">Certificate paths; null, empty and not found entries are skipped.</param>
        /// <returns>
        ///     Return the loaded certificates, in the order of the paths, without duplicates (same
        ///     thumbprint)
        /// </returns>
        internal static X509Certificate2Collection LoadAll(IEnumerable<string> paths)
        {
            var certificates = new X509Certificate2Collection();
            if (paths.IsNull())
                return certificates;

            try
            {
                foreach (var path in paths)
                {
                    var certificate = Public(path);
                    if (certificate.IsNull())
                        continue;

                    if (ContainsThumbprint(certificates, certificate.Thumbprint))
                        certificate.Dispose();
                    else
                        certificates.Add(certificate);
                }
            }
            catch
            {
                DisposeAll(certificates);
                throw;
            }

            return certificates;
        }

        /// <summary>
        ///     Get the identity provider certificates trusted for the inbound signature.
        /// </summary>
        /// <param name="options">MPass options.</param>
        /// <returns>
        ///     Return the configured <see cref="MPassSamlOptions.IdentityProviderCertificates" />, plus
        ///     <see cref="MPassSamlOptions.IdentityProviderCertificate" /> when it is set and not
        ///     already listed (same thumbprint).
        /// </returns>
        internal static X509Certificate2Collection IdentityProviderCertificates(MPassSamlOptions options)
        {
            var certificates = new X509Certificate2Collection();
            if (options.IsNull())
                return certificates;

            if (!options.IdentityProviderCertificates.IsNull())
                certificates.AddRange(options.IdentityProviderCertificates);

            var primaryCertificate = options.IdentityProviderCertificate;
            if (!primaryCertificate.IsNull() && !ContainsThumbprint(certificates, primaryCertificate.Thumbprint))
                certificates.Add(primaryCertificate);

            return certificates;
        }

        /// <summary>
        ///     Check whether the collection already contains a certificate with the given thumbprint.
        /// </summary>
        /// <param name="certificates">Certificate collection.</param>
        /// <param name="thumbprint">Certificate thumbprint.</param>
        /// <returns>
        ///     Return true if a certificate with the same thumbprint exists; otherwise false.
        /// </returns>
        internal static bool ContainsThumbprint(X509Certificate2Collection certificates, string thumbprint)
        {
            foreach (var certificate in certificates)
            {
                if (string.Equals(certificate.Thumbprint, thumbprint, StringComparison.OrdinalIgnoreCase))
                    return true;
            }

            return false;
        }

        /// <summary>
        ///     Load private certificate.
        /// </summary>
        /// <param name="certificatePath">Required. Certificate path.</param>
        /// <param name="certificatePassword">
        ///     (Optional) Optional. Certificate password. The default value is null.
        /// </param>
        /// <returns>
        ///     An X509Certificate2.
        /// </returns>
        internal static X509Certificate2 Private(string certificatePath, string certificatePassword = null)
        {
            X509Certificate2 result;
            if (string.IsNullOrWhiteSpace(certificatePath))
                return null;

#if NETSTANDARD2_1_OR_GREATER || NET
            if (File.Exists(certificatePath) && !string.IsNullOrWhiteSpace(certificatePassword))
            {
                var x509Certificate2Collection = new X509Certificate2Collection();
                x509Certificate2Collection.Import(certificatePath, certificatePassword, X509KeyStorageFlags.DefaultKeySet);
                var x509Certificate2Collection2 = x509Certificate2Collection;
                var index = x509Certificate2Collection2.Count - 1;

                return x509Certificate2Collection2[index];
            }

            if (!Directory.Exists(certificatePath)) return null;

            var certificateFile = Path.Combine(certificatePath, "tls.crt");
            var path = Path.Combine(certificatePath, "tls.key");

            if (!File.Exists(path)) return null;

            using var x509Certificate = CertificateLoader.LoadPublicCertificateFromChain(certificateFile);
            if (x509Certificate == null)
            {
                result = null;
            }
            else
            {
                var array = File.ReadAllLines(path);
                if (array.Length < 3)
                {
                    result = null;
                }
                else
                {
                    var array2 =
 Convert.FromBase64String(string.Concat(RuntimeHelpers.GetSubArray<string>(array, new Range(1, new Index(1, true)))));
                    if (array[0].Contains("EC PRIVATE KEY", StringComparison.OrdinalIgnoreCase))
                    {
                        using var ecdsa = ECDsa.Create();
                        if (!ecdsa.IsNull())
                        {
                            ecdsa?.ImportECPrivateKey(array2, out _);

                            return new X509Certificate2(x509Certificate.CopyWithPrivateKey(ecdsa)
                                .Export(X509ContentType.Pfx));
                        }
                    }
                    if (array[0].Contains("RSA PRIVATE KEY", StringComparison.OrdinalIgnoreCase))
                    {
                        using var rsa = RSA.Create();
                        rsa.ImportRSAPrivateKey(array2, out _);

                        return new X509Certificate2(x509Certificate.CopyWithPrivateKey(rsa).Export(X509ContentType.Pfx));
                    }
                    if (array[0].Contains("DSA PRIVATE KEY", StringComparison.OrdinalIgnoreCase))
                    {
                        using var dsa = DSA.Create();
                        dsa.ImportPkcs8PrivateKey(array2, out _);

                        return new X509Certificate2(x509Certificate.CopyWithPrivateKey(dsa).Export(X509ContentType.Pfx));
                    }
                    result = null;
                }
            }

#else
            try
            {
                result = new X509Certificate2(certificatePath, certificatePassword, EphemeralKeySet);
            }
            catch (Exception e) when (e is PlatformNotSupportedException || e is CryptographicException || e is ArgumentException)
            {
                result = new X509Certificate2(certificatePath, certificatePassword, X509KeyStorageFlags.UserKeySet);
            }
#endif

            return result;
        }

        /// <summary>
        ///     Load public certificate from chain.
        /// </summary>
        /// <param name="certificateFile">Certificate file path.</param>
        /// <returns>
        ///     The public certificate from chain.
        /// </returns>
        private static X509Certificate2 LoadPublicCertificateFromChain(string certificateFile)
        {
            if (!File.Exists(certificateFile))
                return null;

            var x509Certificate2Collection = LoadPublicCertificatesChain(certificateFile);
            if (x509Certificate2Collection.Count.IsZero())
                return null;

            for (var i = 1; i < x509Certificate2Collection.Count; i++)
                x509Certificate2Collection[i].Dispose();

            return x509Certificate2Collection[0];
        }

        /// <summary>
        ///     Load public certificate from chain.
        /// </summary>
        /// <param name="certificateFile">Certificate file path.</param>
        /// <returns>
        ///     The public certificates chain.
        /// </returns>
        private static X509Certificate2Collection LoadPublicCertificatesChain(string certificateFile)
        {
            var x509Certificate2Collection = new X509Certificate2Collection();
            var array = File.ReadAllLines(certificateFile);
            var num = -1;
            try
            {
                for (var i = 0; i < array.Length; i++)
                {
                    if (num.IsLessZero())
                    {
                        if (array[i].Contains("BEGIN CERTIFICATE", StringComparison.OrdinalIgnoreCase)) num = i + 1;
                    }
                    else if (array[i].Contains("END CERTIFICATE", StringComparison.OrdinalIgnoreCase))
                    {
                        x509Certificate2Collection.Add(
                            new X509Certificate2(Convert.FromBase64String(string.Concat(array.SubArray(num, i - num)))));
                        num = -1;
                    }
                }
            }
            catch
            {
                DisposeAll(x509Certificate2Collection);
                throw;
            }

            return x509Certificate2Collection;
        }

        /// <summary>
        ///     Dispose every certificate in the collection.
        /// </summary>
        /// <param name="certificates">Certificate collection.</param>
        private static void DisposeAll(X509Certificate2Collection certificates)
        {
            foreach (var certificate in certificates)
                certificate.Dispose();
        }
    }
}