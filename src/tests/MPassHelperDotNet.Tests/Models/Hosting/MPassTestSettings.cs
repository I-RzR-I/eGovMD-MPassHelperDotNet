using System;
using System.Collections.Generic;
using System.Globalization;
using System.Security.Cryptography.X509Certificates;
using MPassHelperDotNet.Tests.Helpers.Certificates;
using MPassHelperDotNet.Tests.Models.Certificates;

namespace MPassHelperDotNet.Tests.Models.Hosting
{
    internal sealed class MPassTestSettings
    {
        internal const string SectionName = "MPassSamlOptions";

        internal const string DefaultSpIssuer = "https://sp.test.local/metadata";
        internal const string DefaultIdpIssuer = "https://idp.test.local/metadata";
        internal const string DefaultIdpLoginUrl = "https://idp.test.local/saml/login";
        internal const string DefaultIdpLogoutUrl = "https://idp.test.local/saml/logout";
        internal const string DefaultSpAcsUrl = "https://sp.test.local/saml/acs";
        internal const string DefaultSpLogoutResponseUrl = "https://sp.test.local/saml/logout-response";
        internal const string DefaultSpSingleLogoutUrl = "https://sp.test.local/saml/slo";

        internal const string DefaultPfxPassword = "unit-test-only-pfx";

        public string SamlRequestIssuer { get; set; } = DefaultSpIssuer;

        public string IdentityProviderIssuer { get; set; } = DefaultIdpIssuer;

        public string SamlLoginDestination { get; set; } = DefaultIdpLoginUrl;

        public string SamlLogoutDestination { get; set; } = DefaultIdpLogoutUrl;

        public string SamlServiceLoginDestination { get; set; } = DefaultSpAcsUrl;

        public string SamlServiceLogoutDestination { get; set; } = DefaultSpLogoutResponseUrl;

        public string SamlServiceSingleLogoutDestination { get; set; } = DefaultSpSingleLogoutUrl;

        public TimeSpan? SamlMessageTimeout { get; set; } = TimeSpan.FromMinutes(10);

        public TimeSpan? SamlClockSkew { get; set; } = TimeSpan.FromMinutes(2);

        public bool? AllowSha1Signatures { get; set; }

        public int? SamlMessageMaxLength { get; set; }

        public X509Certificate2 ServiceCertificate { get; set; } = TestCertificates.Sp;

        public string ServiceCertificatePassword { get; set; } = DefaultPfxPassword;

        public string ServiceCertificatePath { get; set; }

        public X509Certificate2 IdentityProviderCertificate { get; set; } = TestCertificates.Idp;

        public CertificateFileFormat IdentityProviderCertificateFormat { get; set; } = CertificateFileFormat.Der;

        public string IdentityProviderCertificatePath { get; set; }

        public List<X509Certificate2> IdentityProviderAdditionalCertificates { get; } = new List<X509Certificate2>();

        public Dictionary<string, string> AdditionalConfiguration { get; } = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);

        public bool OmitSection { get; set; }

        internal Dictionary<string, string> ToConfiguration(TestCertificateFiles files)
        {
            var values = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);
            if (OmitSection)
                return values;

            void Put(string key, string value)
            {
                if (value != null)
                    values[SectionName + ":" + key] = value;
            }

            Put("SamlRequestIssuer", SamlRequestIssuer);
            Put("IdentityProviderIssuer", IdentityProviderIssuer);
            Put("SamlLoginDestination", SamlLoginDestination);
            Put("SamlLogoutDestination", SamlLogoutDestination);
            Put("SamlServiceLoginDestination", SamlServiceLoginDestination);
            Put("SamlServiceLogoutDestination", SamlServiceLogoutDestination);
            Put("SamlServiceSingleLogoutDestination", SamlServiceSingleLogoutDestination);
            Put("SamlMessageTimeout", SamlMessageTimeout?.ToString("c", CultureInfo.InvariantCulture));
            Put("SamlClockSkew", SamlClockSkew?.ToString("c", CultureInfo.InvariantCulture));
            Put("AllowSha1Signatures", AllowSha1Signatures.HasValue ? (AllowSha1Signatures.Value ? "true" : "false") : null);
            Put("SamlMessageMaxLength", SamlMessageMaxLength?.ToString(CultureInfo.InvariantCulture));

            Put("ServiceCertificatePassword", ServiceCertificatePassword);
            Put("ServiceCertificatePath", ServiceCertificatePath
                                          ?? (ServiceCertificate != null ? files.WritePfx(ServiceCertificate, ServiceCertificatePassword) : null));

            Put("IdentityProviderCertificatePath", IdentityProviderCertificatePath
                                                   ?? (IdentityProviderCertificate != null
                                                       ? files.WritePublic(IdentityProviderCertificate, IdentityProviderCertificateFormat)
                                                       : null));

            for (var i = 0; i < IdentityProviderAdditionalCertificates.Count; i++)
                Put("IdentityProviderAdditionalCertificatePaths:" + i.ToString(CultureInfo.InvariantCulture),
                    files.WritePublic(IdentityProviderAdditionalCertificates[i], IdentityProviderCertificateFormat));

            foreach (var pair in AdditionalConfiguration)
            {
                var key = SectionName + ":" + pair.Key;
                if (pair.Value == null)
                    values.Remove(key);
                else
                    values[key] = pair.Value;
            }

            return values;
        }
    }
}
