// ***********************************************************************
//  Assembly         : RzR.Shared.eGovMD.MPassHelperDotNet
//  Author           : RzR
//  Created On       : 2023-06-21 23:54
// 
//  Last Modified By : RzR
//  Last Modified On : 2023-06-28 16:26
// ***********************************************************************
//  <copyright file="MPassSamlHealthCheck.cs" company="">
//   Copyright (c) RzR. All rights reserved.
//  </copyright>
// 
//  <summary>
//  </summary>
// ***********************************************************************

#region U S A G E S

using System;
using System.Threading;
using System.Threading.Tasks;
using Microsoft.Extensions.Diagnostics.HealthChecks;
using Microsoft.Extensions.Options;
using MPassHelperDotNet.Models.Client;

#endregion

namespace MPassHelperDotNet.Services
{
    /// <summary>
    ///     MPass health certificate check
    /// </summary>
    public class MPassSamlHealthCheck : IHealthCheck
    {
        /// <summary>
        ///     Monitoring options
        /// </summary>
        private readonly IOptionsMonitor<MPassSamlOptions> _optionsMonitor;

        /// <summary>
        ///     Initializes a new instance of the <see cref="MPassHelperDotNet.Services.MPassSamlHealthCheck" /> class.
        /// </summary>
        /// <param name="optionsMonitor">Monitoring options</param>
        /// <remarks></remarks>
        public MPassSamlHealthCheck(IOptionsMonitor<MPassSamlOptions> optionsMonitor)
            => _optionsMonitor = optionsMonitor;

        /// <inheritdoc />
        public async Task<HealthCheckResult> CheckHealthAsync(
            HealthCheckContext context,
            CancellationToken cancellationToken = default)
        {
            var options = _optionsMonitor.CurrentValue;

            if (options.IdentityProviderCertificate == null)
                return await Task.FromResult(HealthCheckResult.Unhealthy("No identity provider certificate specified"));

            if (options.IdentityProviderCertificate.NotAfter < DateTime.Now)
                return await Task.FromResult(new HealthCheckResult(context.Registration.FailureStatus, "Identity provider certificate is expired"));

            if (options.IdentityProviderCertificate.NotAfter < DateTime.Now.AddDays(30))
                return await Task.FromResult(HealthCheckResult.Degraded("Identity provider certificate expires in less than 30 days"));

            if (options.ServiceCertificate == null)
                return await Task.FromResult(HealthCheckResult.Unhealthy("No service certificate specified"));

            if (!options.ServiceCertificate.HasPrivateKey)
                return await Task.FromResult(HealthCheckResult.Unhealthy("Service certificate does not contain private key"));

            if (options.ServiceCertificate.NotAfter < DateTime.Now)
                return await Task.FromResult(new HealthCheckResult(context.Registration.FailureStatus, "Service certificate is expired"));

            if (options.ServiceCertificate.NotAfter < DateTime.Now.AddDays(30))
                return await Task.FromResult(HealthCheckResult.Degraded("Service certificate expires in less than 30 days"));
            
            return await Task.FromResult(HealthCheckResult.Healthy());
        }
    }
}