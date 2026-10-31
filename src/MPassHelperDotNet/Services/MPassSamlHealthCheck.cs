// ***********************************************************************
//  Assembly         : RzR.Shared.eGovMD.MPassHelperDotNet
//  Author           : RzR
//  Created On       : 2023-06-21 23:54
// 
//  Last Modified By : RzR
//  Last Modified On : 2026-09-22 12:06
// ***********************************************************************
//  <copyright file="MPassSamlHealthCheck.cs" company="">
//   Copyright (c) RzR. All rights reserved.
//  </copyright>
// 
//  <summary>
//  </summary>
// ***********************************************************************

#region U S I N G

using Microsoft.Extensions.Diagnostics.HealthChecks;
using Microsoft.Extensions.Options;
using MPassHelperDotNet.Configurations.Certificate;
using MPassHelperDotNet.Models.Client;
using RzR.Extensions.Domain.Primitives;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Security.Cryptography.X509Certificates;
using System.Threading;
using System.Threading.Tasks;

#endregion

namespace MPassHelperDotNet.Services
{
    /// <summary>
    ///     MPass health certificate check
    /// </summary>
    public class MPassSamlHealthCheck : IHealthCheck
    {
        /// <summary>
        ///     (Immutable)
        ///     A certificate that expires within this period reports <see cref="HealthStatus.Degraded" />
        /// 
        /// </summary>
        private static readonly TimeSpan ExpiryWarningPeriod = TimeSpan.FromDays(30);

        /// <summary>
        ///     (Immutable)
        ///     Monitoring options.
        /// </summary>
        private readonly IOptionsMonitor<MPassSamlOptions> _optionsMonitor;

        /// <summary>
        ///     (Immutable)
        ///     Time provider.
        /// </summary>
        private readonly TimeProvider _timeProvider;

        /// <summary>
        ///     Initializes a new instance of the <see cref="MPassHelperDotNet.Services.MPassSamlHealthCheck" />
        ///     class.
        /// </summary>
        /// <exception cref="ArgumentNullException">When a parameter is null.</exception>
        /// <param name="optionsMonitor">Monitoring options.</param>
        /// <param name="timeProvider">Time provider used to evaluate the certificate validity.</param>
        public MPassSamlHealthCheck(IOptionsMonitor<MPassSamlOptions> optionsMonitor, TimeProvider timeProvider)
        {
            _optionsMonitor = optionsMonitor ?? throw new ArgumentNullException(nameof(optionsMonitor));
            _timeProvider = timeProvider ?? throw new ArgumentNullException(nameof(timeProvider));
        }

        /// <summary>
        ///     Check the service certificate and every identity provider certificate (primary and
        ///     rotation). Every check is evaluated and the worst status is returned; an unhealthy result
        ///     uses the registration failure status.
        /// </summary>
        /// <param name="context">Health check context.</param>
        /// <param name="cancellationToken">(Optional) Cancellation token.</param>
        /// <returns>
        ///     Return the health check result with every problem in the description.
        /// </returns>
        public Task<HealthCheckResult> CheckHealthAsync(HealthCheckContext context,
            CancellationToken cancellationToken = default)
        {
            var options = _optionsMonitor.CurrentValue;
            var nowUtc = _timeProvider.GetUtcNow().UtcDateTime;
            var problems = new List<(HealthStatus Status, string Message)>();

            var idpCertificates = CertificateLoader.IdentityProviderCertificates(options);
            if (idpCertificates.Count.IsZero())
                problems.Add((HealthStatus.Unhealthy, "No identity provider certificate specified"));

            foreach (var idpCertificate in idpCertificates)
                CheckExpiry(problems, idpCertificate, nowUtc, "Identity provider certificate", idpCertificate.Thumbprint);

            if (options.ServiceCertificate.IsNull())
                problems.Add((HealthStatus.Unhealthy, "No service certificate specified"));
            else
            {
                if (!options.ServiceCertificate.HasPrivateKey)
                    problems.Add((HealthStatus.Unhealthy, "Service certificate does not contain private key"));

                CheckExpiry(problems, options.ServiceCertificate, nowUtc, "Service certificate", null);
            }

            if (problems.Count.IsZero())
                return Task.FromResult(HealthCheckResult.Healthy());

            var description = string.Join("; ", problems.Select(problem => problem.Message));
            var result = problems.Any(problem => problem.Status == HealthStatus.Unhealthy)
                ? new HealthCheckResult(context?.Registration?.FailureStatus ?? HealthStatus.Unhealthy, description)
                : HealthCheckResult.Degraded(description);

            return Task.FromResult(result);
        }

        /// <summary>
        ///     Add an unhealthy problem when the certificate is expired, or a degraded one when it
        ///     expires within the warning period.
        /// </summary>
        /// <param name="problems">Problem list.</param>
        /// <param name="certificate">Certificate.</param>
        /// <param name="nowUtc">Current UTC time.</param>
        /// <param name="certificateName">Certificate name used in the message.</param>
        /// <param name="thumbprint">
        ///     Optional. Thumbprint added to the message to identify one of several certificates.
        /// </param>
        private static void CheckExpiry(ICollection<(HealthStatus Status, string Message)> problems,
            X509Certificate2 certificate, DateTime nowUtc, string certificateName, string thumbprint)
        {
            var notAfterUtc = certificate.NotAfter.ToUniversalTime();
            var expired = notAfterUtc < nowUtc;
            if (!expired && notAfterUtc >= nowUtc.Add(ExpiryWarningPeriod))
                return;

            var name = thumbprint.IsNull() ? certificateName : $"{certificateName} ({thumbprint})";
            problems.Add(expired
                ? (HealthStatus.Unhealthy, $"{name} is expired")
                : (HealthStatus.Degraded, $"{name} expires in less than {ExpiryWarningPeriod.TotalDays} days"));
        }
    }
}