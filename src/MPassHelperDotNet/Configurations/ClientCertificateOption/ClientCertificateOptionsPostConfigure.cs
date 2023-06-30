// ***********************************************************************
//  Assembly         : RzR.Shared.eGovMD.MPassHelperDotNet
//  Author           : RzR
//  Created On       : 2023-06-13 20:41
// 
//  Last Modified By : RzR
//  Last Modified On : 2023-06-28 16:26
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
using System.Security.Cryptography.X509Certificates;
using DomainCommonExtensions.CommonExtensions;
using DomainCommonExtensions.DataTypeExtensions;
using Microsoft.Extensions.Options;
using MPassHelperDotNet.Configurations.Certificate;
using MPassHelperDotNet.Helpers;
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
        ///     POST configuration
        /// </summary>
        /// <param name="name"></param>
        /// <param name="options">Client certificate option</param>
        public void PostConfigure(string name, MPassSamlOptions options)
        {
            if (options.ServiceCertificatePath.IsNullOrEmpty())
                throw new ArgumentException(string.Format(DefaultMessages.ArgumentNullMessage, nameof(options.ServiceCertificatePath)));

            if (options.ServiceCertificatePassword.IsNullOrEmpty())
                throw new ArgumentException(string.Format(DefaultMessages.ArgumentNullMessage, nameof(options.ServiceCertificatePassword)));

            if (options.IdentityProviderCertificatePath.IsNullOrEmpty())
                throw new ArgumentException(string.Format(DefaultMessages.ArgumentNullMessage, nameof(options.IdentityProviderCertificatePath)));

            if (options.SamlLoginDestination.IsNullOrEmpty())
                throw new ArgumentException(string.Format(DefaultMessages.ArgumentNullMessage, nameof(options.SamlLoginDestination)));

            if (options.SamlLogoutDestination.IsNullOrEmpty())
                throw new ArgumentException(string.Format(DefaultMessages.ArgumentNullMessage, nameof(options.SamlLogoutDestination)));

            if (options.SamlServiceLoginDestination.IsNullOrEmpty())
                throw new ArgumentException(string.Format(DefaultMessages.ArgumentNullMessage, nameof(options.SamlServiceLoginDestination)));

            if (options.SamlServiceLogoutDestination.IsNullOrEmpty())
                throw new ArgumentException(string.Format(DefaultMessages.ArgumentNullMessage, nameof(options.SamlServiceLogoutDestination)));

            if (options.SamlServiceSingleLogoutDestination.IsNullOrEmpty())
                throw new ArgumentException(string.Format(DefaultMessages.ArgumentNullMessage, nameof(options.SamlServiceSingleLogoutDestination)));

            // ReSharper disable once CollectionNeverUpdated.Local
            var certificate = new X509Certificate2Collection(CertificateLoader.Private(
                options.ServiceCertificatePath,
                options.ServiceCertificatePassword));

            if (certificate.Count.IsZero())
                throw new ApplicationException(DefaultMessages.InvalidCertificatePathOrPassword);

            if (certificate.Count.IsGreaterThanZero())
                options.ServiceCertificate = certificate[0];

            var idpCertificate = CertificateLoader.Public(options.IdentityProviderCertificatePath);
            options.IdentityProviderCertificate = idpCertificate.IsNull()
                ? throw new ArgumentException(string.Format(DefaultMessages.ArgumentNullMessage, nameof(options.IdentityProviderCertificatePath)))
                : idpCertificate;
        }
    }
}