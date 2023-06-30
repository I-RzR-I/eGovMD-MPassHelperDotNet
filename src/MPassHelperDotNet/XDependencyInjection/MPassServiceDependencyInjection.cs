// ***********************************************************************
//  Assembly         : RzR.Shared.eGovMD.MPassHelperDotNet
//  Author           : RzR
//  Created On       : 2023-06-22 00:21
// 
//  Last Modified By : RzR
//  Last Modified On : 2023-06-28 16:26
// ***********************************************************************
//  <copyright file="MPassServiceDependencyInjection.cs" company="">
//   Copyright (c) RzR. All rights reserved.
//  </copyright>
// 
//  <summary>
//  </summary>
// ***********************************************************************

#if NETSTANDARD2_0_OR_GREATER || NET || NETCOREAPP3_1_OR_GREATER

#region U S A G E S

using DomainCommonExtensions.DataTypeExtensions;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Options;
using MPassHelperDotNet.Abstractions.Services;
using MPassHelperDotNet.Configurations.Certificate;
using MPassHelperDotNet.Configurations.ClientCertificateOption;
using MPassHelperDotNet.Models.Client;
using MPassHelperDotNet.Services;
using UniqueServiceCollection;

#endregion

namespace MPassHelperDotNet.XDependencyInjection
{
    /// <summary>
    ///     MPass service DI
    /// </summary>
    /// <remarks></remarks>
    public static partial class DependencyInjection
    {
        /// <summary>
        ///     Add MPass service
        /// </summary>
        /// <param name="services">Service collection</param>
        /// <param name="configuration">App configuration</param>
        /// <returns></returns>
        /// <remarks></remarks>
        public static IServiceCollection AddMPassService(this IServiceCollection services, IConfiguration configuration)
        {
            var mPassSamlOptions = configuration.GetSection(nameof(MPassSamlOptions)).Get<MPassSamlOptions>();
            services.AddOptions<MPassSamlOptions>();
            mPassSamlOptions.ServiceCertificate = CertificateLoader.Private(mPassSamlOptions.ServiceCertificatePath, mPassSamlOptions.ServiceCertificatePassword);
            mPassSamlOptions.IdentityProviderCertificate = CertificateLoader.Public(mPassSamlOptions.IdentityProviderCertificatePath);

            services.Configure<MPassSamlOptions>(options =>
            {
                options.ServiceCertificate = mPassSamlOptions.ServiceCertificate;
                options.ServiceCertificatePath = mPassSamlOptions.ServiceCertificatePath;
                options.ServiceCertificatePassword = mPassSamlOptions.ServiceCertificatePassword;

                options.IdentityProviderCertificatePath = mPassSamlOptions.IdentityProviderCertificatePath;
                if (!mPassSamlOptions.IdentityProviderCertificatePath.IsNullOrEmpty())
                    options.IdentityProviderCertificate = mPassSamlOptions.IdentityProviderCertificate;

                options.SamlLogoutDestination = mPassSamlOptions.SamlLogoutDestination;
                options.SamlLoginDestination = mPassSamlOptions.SamlLoginDestination;
                options.SamlMessageTimeout = mPassSamlOptions.SamlMessageTimeout;
                options.SamlRequestIssuer = mPassSamlOptions.SamlRequestIssuer;

                options.SamlServiceLoginDestination = mPassSamlOptions.SamlServiceLoginDestination;
                options.SamlServiceLogoutDestination = mPassSamlOptions.SamlServiceLogoutDestination;
                options.SamlServiceSingleLogoutDestination = mPassSamlOptions.SamlServiceSingleLogoutDestination;
            });

            services.PostConfigure<MPassSamlOptions>(options =>
            {
                options.ServiceCertificate = mPassSamlOptions.ServiceCertificate;
                options.ServiceCertificatePath = mPassSamlOptions.ServiceCertificatePath;
                options.ServiceCertificatePassword = mPassSamlOptions.ServiceCertificatePassword;

                options.IdentityProviderCertificatePath = mPassSamlOptions.IdentityProviderCertificatePath;
                if (!mPassSamlOptions.IdentityProviderCertificatePath.IsNullOrEmpty())
                    options.IdentityProviderCertificate = mPassSamlOptions.IdentityProviderCertificate;

                options.SamlLogoutDestination = mPassSamlOptions.SamlLogoutDestination;
                options.SamlLoginDestination = mPassSamlOptions.SamlLoginDestination;
                options.SamlMessageTimeout = mPassSamlOptions.SamlMessageTimeout;
                options.SamlRequestIssuer = mPassSamlOptions.SamlRequestIssuer;

                options.SamlServiceLoginDestination = mPassSamlOptions.SamlServiceLoginDestination;
                options.SamlServiceLogoutDestination = mPassSamlOptions.SamlServiceLogoutDestination;
                options.SamlServiceSingleLogoutDestination = mPassSamlOptions.SamlServiceSingleLogoutDestination;
            });

            services.AddUnique(mPassSamlOptions);
            services.AddUnique<IPostConfigureOptions<MPassSamlOptions>, ClientCertificateOptionsPostConfigure>();

            services.AddUnique<IMPassBuilderService, MPassBuilderService>(ServiceLifetime.Scoped);
            services.AddUnique<IAuthMPassService, AuthMPassService>(ServiceLifetime.Scoped);

            return services;
        }
    }
}
#endif