using System.Collections.Generic;
using System.Security.Cryptography.X509Certificates;
using System.Security.Cryptography.Xml;
using MPassHelperDotNet.Tests.Helpers.Certificates;

namespace MPassHelperDotNet.Tests.Models.Signing
{
    internal sealed class FixtureSigningOptions
    {
        public X509Certificate2 Certificate { get; set; } = TestCertificates.Idp;

        public X509Certificate2 KeyInfoCertificate { get; set; }

        public bool IncludeKeyInfo { get; set; } = true;

        public SignaturePlacement Placement { get; set; } = SignaturePlacement.Root;

        public string ReferenceUri { get; set; }

        public string ExtraReferenceUri { get; set; }

        public IList<string> TransformUris { get; set; } = new List<string>
        {
            SignedXml.XmlDsigEnvelopedSignatureTransformUrl,
            SignedXml.XmlDsigExcC14NTransformUrl
        };

        public string CanonicalizationMethod { get; set; } = SignedXml.XmlDsigExcC14NTransformUrl;

        public string SignatureMethod { get; set; } = SignedXml.XmlDsigRSASHA256Url;

        public string DigestMethod { get; set; } = SignedXml.XmlDsigSHA256Url;

        public byte[] HmacKey { get; set; }

        public bool DuplicateSignature { get; set; }

        public string ObjectIdAttributeName { get; set; }

        internal static FixtureSigningOptions Sha1() => new FixtureSigningOptions
        {
            SignatureMethod = SignedXml.XmlDsigRSASHA1Url,
            DigestMethod = SignedXml.XmlDsigSHA1Url
        };

        internal static FixtureSigningOptions EnvelopedOnly() => new FixtureSigningOptions
        {
            TransformUris = new List<string> { SignedXml.XmlDsigEnvelopedSignatureTransformUrl }
        };

        internal FixtureSigningOptions ForSecondarySignature() => new FixtureSigningOptions
        {
            Certificate = Certificate,
            KeyInfoCertificate = KeyInfoCertificate,
            IncludeKeyInfo = IncludeKeyInfo,
            Placement = Placement,
            TransformUris = new List<string>(TransformUris),
            CanonicalizationMethod = CanonicalizationMethod,
            SignatureMethod = SignatureMethod,
            DigestMethod = DigestMethod,
            HmacKey = HmacKey
        };
    }
}
