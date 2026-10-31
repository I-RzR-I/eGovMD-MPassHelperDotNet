// ***********************************************************************
//  Assembly         : RzR.Shared.eGovMD.MPassHelperDotNet
//  Author           : RzR
//  Created On       : 2023-06-17 21:16
// 
//  Last Modified By : RzR
//  Last Modified On : 2026-09-23 12:50
// ***********************************************************************
//  <copyright file="DefaultStaticInfo.cs" company="">
//   Copyright (c) RzR. All rights reserved.
//  </copyright>
// 
//  <summary>
//  </summary>
// ***********************************************************************

#region U S A G E S

using System;
using System.Security.Cryptography.Xml;

#endregion

namespace MPassHelperDotNet.Helpers
{
    /// <summary>
    ///     Internal information used to help generate data
    /// </summary>
    internal static class DefaultStaticInfo
    {
        internal const string SamlUrnStatusSuccess = "urn:oasis:names:tc:SAML:2.0:status:Success";
        internal const string SamlUrnStatusPartialLogout = "urn:oasis:names:tc:SAML:2.0:status:PartialLogout";
        internal const string UrnSaml2Protocol = "urn:oasis:names:tc:SAML:2.0:protocol";
        internal const string UrnSaml2Assertion = "urn:oasis:names:tc:SAML:2.0:assertion";
        internal const string SamlUrnStatusAuthnFailed = "urn:oasis:names:tc:SAML:2.0:status:AuthnFailed";
        internal const string SamlUrnStatusUnknownPrincipal = "urn:oasis:names:tc:SAML:2.0:status:UnknownPrincipal";
        internal const string SamlUrnStatusNoPassive = "urn:oasis:names:tc:SAML:2.0:status:NoPassive";
        internal const string SamlBearerMethod = "urn:oasis:names:tc:SAML:2.0:cm:bearer";

        /// <summary>
        ///     Maximum RelayState size in bytes (UTF-8), according to [SAMLBind, 3.5.3]
        /// </summary>
        internal const int RelayStateMaxBytes = 80;

        /// <summary>
        ///     Default maximum length (characters) of an inbound Base64 SAML message
        /// </summary>
        internal const int DefaultSamlMessageMaxLength = 262144;

        /// <summary>
        ///     Maximum length (characters) of an IdP StatusMessage copied into a result message
        /// </summary>
        internal const int StatusMessageMaxLength = 256;

        internal const string ReplayKeyResponse = "Response:";
        internal const string ReplayKeyAssertion = "Assertion:";
        internal const string ReplayKeyLogoutRequest = "LogoutRequest:";
        internal const string ReplayKeyLogoutResponse = "LogoutResponse:";

        /// <summary>
        ///     Login URL query parameter that carries the preferred identity provider page language
        /// </summary>
        internal const string LanguageQueryParameter = "lang";

        /// <summary>
        ///     Languages accepted for the login page language hint (normalised: trimmed, lower case)
        /// </summary>
        internal static readonly string[] AllowedLanguages = { "ro", "ru", "en" };

        /// <summary>
        ///     Upper bound accepted for the SAML message timeout option
        /// </summary>
        internal static readonly TimeSpan MaxSamlMessageTimeout = TimeSpan.FromMinutes(30);

        /// <summary>
        ///     Upper bound accepted for the SAML clock skew option
        /// </summary>
        internal static readonly TimeSpan MaxSamlClockSkew = TimeSpan.FromMinutes(5);

        /// <summary>
        ///     Minimum extra time a replay cache entry is kept after the acceptance window closes
        ///     (covers the delay between the verification and the replay commit)
        /// </summary>
        internal static readonly TimeSpan MinReplayCommitMargin = TimeSpan.FromMinutes(1);

        /// <summary>
        ///     Public key algorithm OID of an RSA key (rsaEncryption)
        /// </summary>
        internal const string RsaPublicKeyOid = "1.2.840.113549.1.1.1";

        /// <summary>
        ///     Allowed inbound signature methods (RSA with SHA-256/384/512)
        /// </summary>
        internal static readonly string[] AllowedSignatureMethods =
        {
            SignedXml.XmlDsigRSASHA256Url,
            SignedXml.XmlDsigRSASHA384Url,
            SignedXml.XmlDsigRSASHA512Url
        };

        /// <summary>
        ///     Allowed inbound digest methods (SHA-256/384/512)
        /// </summary>
        internal static readonly string[] AllowedDigestMethods =
        {
            SignedXml.XmlDsigSHA256Url,
            SignedXml.XmlDsigSHA384Url,
            SignedXml.XmlDsigSHA512Url
        };

        /// <summary>
        ///     SHA-1 signature methods, allowed only when the SHA-1 option is enabled
        /// </summary>
        internal static readonly string[] Sha1SignatureMethods = { SignedXml.XmlDsigRSASHA1Url };

        /// <summary>
        ///     SHA-1 digest methods, allowed only when the SHA-1 option is enabled
        /// </summary>
        internal static readonly string[] Sha1DigestMethods = { SignedXml.XmlDsigSHA1Url };

        /// <summary>
        ///     Template MPass redirect HTML
        /// </summary>
        internal const string DefaultRedirectHtml = @"
                        <!DOCTYPE html>
                        
                        <html lang=""en"" xmlns=""http://www.w3.org/1999/xhtml"">
                        <head>
                            <meta charset=""utf-8"" />
                            <title>redirecting...</title>
                        </head>
                        <body onload=""document.forms[0].submit();"">
                            <div>Redirecting to MPass...</div>
                            <form method=""POST"" action=""{PostUrl}"">
                                <input type=""hidden"" name=""{SAMLVariable}"" value=""{SAMLMessage}"" />
                                <input type=""hidden"" name=""RelayState"" value=""{RelayState}"" />
                        
                                <noscript>
                                    <p>
                                        <strong>Note:</strong>
                                        Since your browser does not support Javascript, please click the Continue button once to proceed.
                                    </p>
                                    <div>
                                        <input type=""submit"" value=""Continue"" />
                                    </div>
                                </noscript>
                            </form>
                        </body>
                        </html>
                        ";
    }
}