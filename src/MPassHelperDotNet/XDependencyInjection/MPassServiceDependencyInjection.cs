// ***********************************************************************
//  Assembly         : RzR.Shared.eGovMD.MPassHelperDotNet
//  Author           : RzR
//  Created On       : 2023-06-22 00:21
// 
//  Last Modified By : RzR
//  Last Modified On : 2026-09-25 20:36
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

using Microsoft.Extensions.Configuration;
using System;
using System.Linq;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.DependencyInjection.Extensions;
using Microsoft.Extensions.Options;
using MPassHelperDotNet.Abstractions.Services;
using MPassHelperDotNet.Abstractions.Services.Replay;
using MPassHelperDotNet.Configurations.ClientCertificateOption;
using MPassHelperDotNet.Models.Client;
using MPassHelperDotNet.Services;
using MPassHelperDotNet.Services.Replay;
using RzR.Extensions.Domain.Primitives;
using RzR.Extensions.UniqueServiceCollection.ServiceCollectionExtensions;

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
        ///     Add MPass service. Binds <see cref="MPassSamlOptions" /> from the configuration section
        ///     with the same name, loads the certificates once on post configuration and validates the
        ///     options when the host starts.
        /// </summary>
        /// <remarks>
        ///     Invalid options are reported by <see cref="MPassSamlOptionsValidation" /> as one
        ///     <see cref="OptionsValidationException" /> that lists every problem, thrown on host start.
        ///     Calling it more than once registers nothing twice; when the options are already bound
        ///     from configuration, they are not bound again.
        /// </remarks>
        /// <exception cref="ArgumentNullException">
        ///     When <paramref name="services" /> or <paramref name="configuration" /> is null.
        /// </exception>
        /// <param name="services">Service collection.</param>
        /// <param name="configuration">App configuration.</param>
        /// <returns>
        ///     Return the same service collection.
        /// </returns>
        public static IServiceCollection AddMPassService(this IServiceCollection services, IConfiguration configuration)
        {
            if (services.IsNull())
                throw new ArgumentNullException(nameof(services));

            if (configuration.IsNull())
                throw new ArgumentNullException(nameof(configuration));

            var isAlreadyBound = services.Any(descriptor =>
                descriptor.ServiceType == typeof(IConfigureOptions<MPassSamlOptions>)
                && descriptor.ImplementationInstance is NamedConfigureFromConfigurationOptions<MPassSamlOptions>);
            var optionsBuilder = services.AddOptions<MPassSamlOptions>();

            if (isAlreadyBound.IsFalse())
                optionsBuilder.Bind(configuration.GetSection(nameof(MPassSamlOptions)));

            optionsBuilder.ValidateOnStart();

            services.TryAddEnumerable(ServiceDescriptor
                .Singleton<IPostConfigureOptions<MPassSamlOptions>, ClientCertificateOptionsPostConfigure>());
            services.TryAddEnumerable(ServiceDescriptor
                .Singleton<IValidateOptions<MPassSamlOptions>, MPassSamlOptionsValidation>());

            services.TryAddSingleton<IOptions<MPassSamlOptions>>(serviceProvider =>
                new OptionsWrapper<MPassSamlOptions>(serviceProvider.GetRequiredService<IOptionsMonitor<MPassSamlOptions>>().CurrentValue));
            services.TryAddSingleton(serviceProvider => serviceProvider.GetRequiredService<IOptions<MPassSamlOptions>>().Value);

            services.AddLogging();
            services.TryAddSingleton(TimeProvider.System);
            services.TryAddSingleton<ISamlReplayCache, InMemorySamlReplayCache>();

            services.AddUnique<IMPassBuilderService, MPassBuilderService>(ServiceLifetime.Scoped);
            services.AddUnique<IAuthMPassService, AuthMPassService>(ServiceLifetime.Scoped);

            return services;
        }
    }
}
#endif