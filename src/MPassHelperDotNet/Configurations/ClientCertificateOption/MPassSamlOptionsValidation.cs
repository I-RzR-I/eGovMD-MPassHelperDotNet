// ***********************************************************************
//  Assembly         : RzR.Shared.eGovMD.MPassHelperDotNet
//  Author           : RzR
//  Created On       : 2026-09-24 13:01
// 
//  Last Modified By : RzR
//  Last Modified On : 2026-09-24 17:13
// ***********************************************************************
//  <copyright file="MPassSamlOptionsValidation.cs" company="">
//   Copyright (c) RzR. All rights reserved.
//  </copyright>
// 
//  <summary>
//  </summary>
// ***********************************************************************

#region U S A G E S

using System;
using System.Collections.Generic;
using System.Security.Cryptography.X509Certificates;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Logging.Abstractions;
using Microsoft.Extensions.Options;
using MPassHelperDotNet.Helpers;
using MPassHelperDotNet.Helpers.Messages;
using MPassHelperDotNet.Models.Client;
using RzR.Extensions.Domain.Primitives;

#endregion

namespace MPassHelperDotNet.Configurations.ClientCertificateOption
{
    /// <summary>
    ///     MPass options validation.
    ///     Collects every configuration problem so the host start fails once with the complete list.
    /// </summary>
    public sealed class MPassSamlOptionsValidation : IValidateOptions<MPassSamlOptions>
    {
        /// <summary>
        ///     Setting name prefix used in the failure messages
        /// </summary>
        private const string SettingPrefix = nameof(MPassSamlOptions) + ".";

        /// <summary>
        ///     Minimum accepted RSA key size (bits)
        /// </summary>
        private const int MinRsaKeySize = 2048;

        /// <summary>
        ///     Prefix of a placeholder value that was never replaced (e.g. "__SET_IdentityProviderIssuer__")
        /// </summary>
        private const string PlaceholderPrefix = "__SET_";

        /// <summary>
        ///     Documented placeholder of <see cref="MPassSamlOptions.IdentityProviderIssuer" />
        /// </summary>
        private const string IdentityProviderIssuerPlaceholder = "<MPass IdP metadata EntityID>";

        /// <summary>
        ///     Logger
        /// </summary>
        private readonly ILogger<MPassSamlOptionsValidation> _logger;

        /// <summary>
        ///     Initializes a new instance of the <see cref="MPassSamlOptionsValidation" /> class.
        /// </summary>
        /// <param name="logger">
        ///     (Optional) Optional. Logger used for the non-loopback http destination warning. The
        ///     default value is null (no logging).
        /// </param>
        public MPassSamlOptionsValidation(ILogger<MPassSamlOptionsValidation> logger = null)
            => _logger = logger ?? NullLogger<MPassSamlOptionsValidation>.Instance;

        /// <summary>
        ///     Validate MPass options.
        /// </summary>
        /// <param name="name">Options name.</param>
        /// <param name="options">MPass options.</param>
        /// <returns>
        ///     Return success, or a failure that lists every problem found.
        /// </returns>
        public ValidateOptionsResult Validate(string name, MPassSamlOptions options)
        {
            if (options.IsNull())
                return ValidateOptionsResult.Fail(string.Format(DefaultMessages.ArgumentNullMessage, nameof(MPassSamlOptions)));

            var failures = new List<string>();

            ValidateRequired(failures, nameof(options.SamlRequestIssuer), options.SamlRequestIssuer);
            var hasServiceCertificatePath = ValidateRequired(failures, nameof(options.ServiceCertificatePath), options.ServiceCertificatePath);
            ValidateRequired(failures, nameof(options.IdentityProviderCertificatePath), options.IdentityProviderCertificatePath);
            ValidateRequired(failures, nameof(options.IdentityProviderIssuer), options.IdentityProviderIssuer);
            if (string.Equals(options.IdentityProviderIssuer, IdentityProviderIssuerPlaceholder, StringComparison.Ordinal))
                failures.Add(PlaceholderMessage(nameof(options.IdentityProviderIssuer)));

            ValidateDestination(failures, nameof(options.SamlLoginDestination), options.SamlLoginDestination);
            ValidateDestination(failures, nameof(options.SamlLogoutDestination), options.SamlLogoutDestination);
            ValidateDestination(failures, nameof(options.SamlServiceLoginDestination), options.SamlServiceLoginDestination);
            ValidateDestination(failures, nameof(options.SamlServiceLogoutDestination), options.SamlServiceLogoutDestination);
            ValidateDestination(failures, nameof(options.SamlServiceSingleLogoutDestination), options.SamlServiceSingleLogoutDestination);

            if (options.SamlMessageTimeout <= TimeSpan.Zero || options.SamlMessageTimeout > DefaultStaticInfo.MaxSamlMessageTimeout)
            {
                failures.Add(string.Format(OptionsValidationMessages.MessageTimeoutOutOfRange,
                    $"{SettingPrefix}{nameof(options.SamlMessageTimeout)}", DefaultStaticInfo.MaxSamlMessageTimeout));
            }

            if (options.SamlClockSkew < TimeSpan.Zero || options.SamlClockSkew > DefaultStaticInfo.MaxSamlClockSkew)
            {
                failures.Add(string.Format(OptionsValidationMessages.ClockSkewOutOfRange,
                    $"{SettingPrefix}{nameof(options.SamlClockSkew)}", DefaultStaticInfo.MaxSamlClockSkew));
            }

            if (options.SamlMessageMaxLength <= 0)
                failures.Add(string.Format(OptionsValidationMessages.MessageMaxLengthInvalid, $"{SettingPrefix}{nameof(options.SamlMessageMaxLength)}"));

            ValidateServiceCertificate(failures, options, hasServiceCertificatePath);
            ValidateIdentityProviderCertificates(failures, options);

            return failures.Count.IsZero()
                ? ValidateOptionsResult.Success
                : ValidateOptionsResult.Fail(failures);
        }

        /// <summary>
        ///     Validate a required setting: not empty, without leading or trailing whitespace and not a
        ///     placeholder.
        /// </summary>
        /// <param name="failures">Failure list.</param>
        /// <param name="settingName">Setting name.</param>
        /// <param name="value">Setting value.</param>
        /// <returns>
        ///     Return true when the value is set.
        /// </returns>
        private static bool ValidateRequired(ICollection<string> failures, string settingName, string value)
        {
            if (string.IsNullOrWhiteSpace(value))
            {
                failures.Add(string.Format(DefaultMessages.ArgumentNullMessage, $"{SettingPrefix}{settingName}"));

                return false;
            }

            if (!string.Equals(value, value.Trim(), StringComparison.Ordinal))
            {
                failures.Add(string.Format(OptionsValidationMessages.SettingHasSurroundingWhitespace, $"{SettingPrefix}{settingName}"));

                return false;
            }

            if (value.StartsWith(PlaceholderPrefix, StringComparison.OrdinalIgnoreCase))
            {
                failures.Add(PlaceholderMessage(settingName));

                return false;
            }

            return true;
        }

        /// <summary>
        ///     Validate a destination: required, absolute http or https URI. Logs a warning for http
        ///     with a non-loopback host.
        /// </summary>
        /// <param name="failures">Failure list.</param>
        /// <param name="settingName">Setting name.</param>
        /// <param name="value">Setting value.</param>
        private void ValidateDestination(ICollection<string> failures, string settingName, string value)
        {
            if (!ValidateRequired(failures, settingName, value))
                return;

            if (!Uri.TryCreate(value, UriKind.Absolute, out var uri)
                || (uri.Scheme != Uri.UriSchemeHttps && uri.Scheme != Uri.UriSchemeHttp))
            {
                failures.Add(string.Format(OptionsValidationMessages.DestinationInvalid, $"{SettingPrefix}{settingName}"));

                return;
            }

            if (uri.Scheme == Uri.UriSchemeHttp && !uri.IsLoopback)
                _logger.LogWarning(
                    "MPass setting {SettingName} uses http with a non-loopback host; SAML messages are sent unencrypted. Use https in production.",
                    $"{SettingPrefix}{settingName}");
        }

        /// <summary>
        ///     Validate the service (SP) certificate: loaded, with a private key, RSA key of at least
        ///     2048 bits.
        /// </summary>
        /// <param name="failures">Failure list.</param>
        /// <param name="options">MPass options.</param>
        /// <param name="hasServiceCertificatePath">
        ///     Whether the service certificate path passed the required-setting check.
        /// </param>
        private static void ValidateServiceCertificate(ICollection<string> failures, MPassSamlOptions options, bool hasServiceCertificatePath)
        {
            var certificate = options.ServiceCertificate;
            if (certificate.IsNull())
            {
                if (hasServiceCertificatePath)
                {
                    failures.Add(string.Format(OptionsValidationMessages.ServiceCertificateNotLoaded,
                        $"{SettingPrefix}{nameof(options.ServiceCertificatePath)}", $"{SettingPrefix}{nameof(options.ServiceCertificatePassword)}"));
                }

                return;
            }

            if (!certificate.HasPrivateKey)
                failures.Add(string.Format(OptionsValidationMessages.ServiceCertificateWithoutPrivateKey, $"{SettingPrefix}{nameof(options.ServiceCertificate)}"));

            ValidateRsaKeySize(failures, certificate, $"{SettingPrefix}{nameof(options.ServiceCertificate)}");
        }

        /// <summary>
        ///     Validate the identity provider certificates: primary and every additional path loaded, at
        ///     least one certificate, each an RSA key of at least 2048 bits without a private key.
        /// 
        /// </summary>
        /// <param name="failures">Failure list.</param>
        /// <param name="options">MPass options.</param>
        private static void ValidateIdentityProviderCertificates(ICollection<string> failures, MPassSamlOptions options)
        {
            var certificates = options.IdentityProviderCertificates ?? new X509Certificate2Collection();

            var expectedCount = ClientCertificateOptionsPostConfigure.GetIdentityProviderCertificatePaths(options).Count;
            if (certificates.Count < expectedCount)
            {
                failures.Add(string.Format(OptionsValidationMessages.IdentityProviderCertificatePathInvalid,
                    $"{SettingPrefix}{nameof(options.IdentityProviderCertificatePath)}", $"{SettingPrefix}{nameof(options.IdentityProviderAdditionalCertificatePaths)}"));
            }
            else if (certificates.Count.IsZero())
                failures.Add(string.Format(OptionsValidationMessages.IdentityProviderCertificateRequired, $"{SettingPrefix}{nameof(options.IdentityProviderCertificatePath)}"));

            foreach (var certificate in certificates)
            {
                var settingName = $"{SettingPrefix}{nameof(options.IdentityProviderCertificates)} ({certificate.Thumbprint})";
                if (certificate.HasPrivateKey)
                    failures.Add(string.Format(OptionsValidationMessages.IdentityProviderCertificateWithPrivateKey, settingName));

                ValidateRsaKeySize(failures, certificate, settingName);
            }
        }

        /// <summary>
        ///     Validate that the certificate has an RSA key of at least 2048 bits.
        /// </summary>
        /// <param name="failures">Failure list.</param>
        /// <param name="certificate">Certificate.</param>
        /// <param name="settingName">Setting name used in the failure message.</param>
        private static void ValidateRsaKeySize(ICollection<string> failures, X509Certificate2 certificate, string settingName)
        {
            using var rsa = certificate.GetRSAPublicKey();
            if (rsa.IsNull())
                failures.Add(string.Format(OptionsValidationMessages.CertificateNotRsa, settingName));
            else if (rsa.KeySize < MinRsaKeySize)
                failures.Add(string.Format(OptionsValidationMessages.CertificateRsaKeyTooSmall, settingName, MinRsaKeySize));
        }

        /// <summary>
        ///     Build the placeholder failure message.
        /// </summary>
        /// <param name="settingName">Setting name.</param>
        /// <returns>
        ///     Return the failure message.
        /// </returns>
        private static string PlaceholderMessage(string settingName)
            => string.Format(OptionsValidationMessages.SettingIsPlaceholder, $"{SettingPrefix}{settingName}");
    }
}