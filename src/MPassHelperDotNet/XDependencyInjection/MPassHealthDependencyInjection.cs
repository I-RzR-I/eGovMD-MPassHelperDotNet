// ***********************************************************************
//  Assembly         : RzR.Shared.eGovMD.MPassHelperDotNet
//  Author           : RzR
//  Created On       : 2023-06-22 00:23
// 
//  Last Modified By : RzR
//  Last Modified On : 2026-09-22 09:03
// ***********************************************************************
//  <copyright file="MPassHealthDependencyInjection.cs" company="">
//   Copyright (c) RzR. All rights reserved.
//  </copyright>
// 
//  <summary>
//  </summary>
// ***********************************************************************

#region U S A G E S

using System;
using System.Collections.Generic;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.DependencyInjection.Extensions;
using Microsoft.Extensions.Diagnostics.HealthChecks;
using MPassHelperDotNet.Helpers.Messages;
using MPassHelperDotNet.Services;

#endregion

#if NETSTANDARD2_0_OR_GREATER || NET || NETCOREAPP3_1_OR_GREATER

namespace MPassHelperDotNet.XDependencyInjection
{
    /// <summary>
    ///     MPass health certificate check service DI
    /// </summary>
    /// <remarks></remarks>
    public static partial class DependencyInjection
    {
        /// <summary>
        ///     Add MPass certificate health check.
        /// </summary>
        /// <param name="builder">Required. Health check builder.</param>
        /// <param name="failureStatus">(Optional) Optional. The default value is default.</param>
        /// <param name="tags">(Optional) Optional. The default value is default.</param>
        /// <returns>
        ///     An IHealthChecksBuilder.
        /// </returns>
        public static IHealthChecksBuilder AddMPassCertificateHealthCheck(this IHealthChecksBuilder builder,
            HealthStatus? failureStatus = null, IEnumerable<string> tags = null)
            => builder.AddMPassCertificateHealthCheck("MPass", failureStatus, tags);

        /// <summary>
        ///     Add MPass certificate health check.
        /// </summary>
        /// <exception cref="ArgumentException">
        ///     Thrown when one or more arguments have unsupported or illegal values.
        /// </exception>
        /// <param name="builder">Required.  Health check builder.</param>
        /// <param name="name">Required. Configuration name.</param>
        /// <param name="failureStatus">(Optional) Optional. The default value is default.</param>
        /// <param name="tags">(Optional) Optional. The default value is default.</param>
        /// <returns>
        ///     An IHealthChecksBuilder.
        /// </returns>
        public static IHealthChecksBuilder AddMPassCertificateHealthCheck(this IHealthChecksBuilder builder,
            string name, HealthStatus? failureStatus = null, IEnumerable<string> tags = null)
        {
            if (string.IsNullOrWhiteSpace(name))
            {
                throw new ArgumentException(string.Format(DefaultMessages.ArgumentNullMessage + ". Please provide a configuration name, MPass!",
                    nameof(name)), nameof(name));
            }

            builder.Services.TryAddSingleton(TimeProvider.System);
            builder.Services.TryAddSingleton<MPassSamlHealthCheck>();

            // ReSharper disable once AssignNullToNotNullAttribute
            return builder.AddCheck<MPassSamlHealthCheck>(name, failureStatus, tags);
        }
    }
}
#endif