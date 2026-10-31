// ***********************************************************************
//  Assembly         : RzR.Shared.eGovMD.MPassHelperDotNet
//  Author           : RzR
//  Created On       : 2026-09-24 11:51
// 
//  Last Modified By : RzR
//  Last Modified On : 2026-09-24 11:51
// ***********************************************************************
//  <copyright file="OptionsValidationMessages.cs" company="">
//   Copyright (c) RzR. All rights reserved.
//  </copyright>
// 
//  <summary>
//  </summary>
// ***********************************************************************

namespace MPassHelperDotNet.Helpers.Messages
{
    /// <summary>
    ///     MPass options validation messages ({0} is the setting name)
    /// </summary>
    internal static class OptionsValidationMessages
    {
        internal const string SettingHasSurroundingWhitespace = "{0} must not start or end with whitespace.";
        internal const string SettingIsPlaceholder = "{0} still contains a placeholder value; set the real value.";
        internal const string DestinationInvalid = "{0} must be an absolute http or https URL.";
        internal const string MessageTimeoutOutOfRange = "{0} must be greater than 0 and at most {1}.";
        internal const string ClockSkewOutOfRange = "{0} must be between 0 and {1}.";
        internal const string MessageMaxLengthInvalid = "{0} must be greater than 0.";
        internal const string ServiceCertificateNotLoaded = DefaultMessages.InvalidCertificatePathOrPassword + " ({0}, {1})";
        internal const string ServiceCertificateWithoutPrivateKey = "{0} does not contain a private key.";
        internal const string IdentityProviderCertificatePathInvalid = "{0} or {1} contains a path that does not point to a valid certificate, or repeats a certificate configured under another path.";
        internal const string IdentityProviderCertificateRequired = "At least one identity provider certificate is required ({0}).";
        internal const string IdentityProviderCertificateWithPrivateKey = "{0} must not contain a private key.";
        internal const string CertificateNotRsa = "{0} must use an RSA key.";
        internal const string CertificateRsaKeyTooSmall = "{0} must use an RSA key of at least {1} bits.";
    }
}
