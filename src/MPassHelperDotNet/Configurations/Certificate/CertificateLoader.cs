// ***********************************************************************
//  Assembly         : RzR.Shared.eGovMD.MPassHelperDotNet
//  Author           : RzR
//  Created On       : 2023-06-13 20:41
// 
//  Last Modified By : RzR
//  Last Modified On : 2023-06-28 16:26
// ***********************************************************************
//  <copyright file="CertificateLoader.cs" company="">
//   Copyright (c) RzR. All rights reserved.
//  </copyright>
// 
//  <summary>
//  </summary>
// ***********************************************************************

#region U S A G E S

using System;
using System.IO;
using System.Security.Cryptography.X509Certificates;
using DomainCommonExtensions.CommonExtensions;
using DomainCommonExtensions.DataTypeExtensions;
using MPassHelperDotNet.Extensions;

#endregion


// ReSharper disable IdentifierTypo
// ReSharper disable ExpressionIsAlwaysNull
// ReSharper disable JoinDeclarationAndInitializer

namespace MPassHelperDotNet.Configurations.Certificate
{
    /// <summary>
    ///     Certificate loader
    /// </summary>
    /// <remarks></remarks>
    internal static class CertificateLoader
    {
        /// <summary>
        ///     Load public certificate
        /// </summary>
        /// <param name="certificatePath">Certificate path</param>
        /// <returns></returns>
        /// <remarks></remarks>
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
        ///     Load private certificate
        /// </summary>
        /// <param name="certificatePath">Required. Certificate path</param>
        /// <param name="certificatePassword">Optional. Certificate password. The default value is null.</param>
        /// <returns></returns>
        /// <remarks></remarks>
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
                if (x509Certificate2Collection.Count > 1)
                {
                    CertificateLoader.StoreIntermediateCertificates(x509Certificate2Collection, 0, x509Certificate2Collection.Count - 1);
                }
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
            result = new X509Certificate2(certificatePath, certificatePassword);
#endif

            return result;
        }

        /// <summary>
        ///     Load public certificate from chain
        /// </summary>
        /// <param name="certificateFile">Certificate file path</param>
        /// <returns></returns>
        /// <remarks></remarks>
        private static X509Certificate2 LoadPublicCertificateFromChain(string certificateFile)
        {
            if (!File.Exists(certificateFile))
                return null;

            var x509Certificate2Collection = LoadPublicCertificatesChain(certificateFile);
            if (x509Certificate2Collection.Count.IsZero())
                return null;

            if (x509Certificate2Collection.Count > 1)
                StoreIntermediateCertificates(x509Certificate2Collection, 1, x509Certificate2Collection.Count);

            return x509Certificate2Collection[0];
        }

        /// <summary>
        ///     Load public certificate from chain
        /// </summary>
        /// <param name="certificateFile">Certificate file path</param>
        /// <returns></returns>
        /// <remarks></remarks>
        private static X509Certificate2Collection LoadPublicCertificatesChain(string certificateFile)
        {
            var x509Certificate2Collection = new X509Certificate2Collection();
            var array = File.ReadAllLines(certificateFile);
            var num = -1;
            for (var i = 0; i < array.Length; i++)
                if (num.IsLessZero())
                {
                    if (array[i].Contains("BEGIN CERTIFICATE", StringComparison.OrdinalIgnoreCase)) num = i + 1;
                }
                else if (array[i].Contains("END CERTIFICATE", StringComparison.OrdinalIgnoreCase))
                {
                    x509Certificate2Collection.Add(
                        new X509Certificate2(Convert.FromBase64String(string.Concat(array.SubArray(num, i - 1)))));
                    num = -1;
                }

            return x509Certificate2Collection;
        }

        /// <summary>
        ///     Load certificate from store
        /// </summary>
        /// <param name="certificates">Certificate collection</param>
        /// <param name="start">Start index</param>
        /// <param name="end">End index</param>
        /// <remarks></remarks>
        private static void StoreIntermediateCertificates(X509Certificate2Collection certificates, int start, int end)
        {
            if (start >= end)
                return;

            var x509Store = new X509Store(StoreName.CertificateAuthority, StoreLocation.CurrentUser);
            x509Store.Open(OpenFlags.ReadWrite);
            for (var i = start; i < end; i++)
            {
                var certificate = certificates[i];
                if (certificate.Issuer != certificate.Subject && !x509Store.Certificates.Contains(certificate))
                    x509Store.Add(certificate);
            }

            x509Store.Close();
        }
    }
}