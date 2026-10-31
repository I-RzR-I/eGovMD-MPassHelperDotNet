using System;
using System.Collections.Generic;
using System.Linq;
using System.Xml;
using MPassHelperDotNet.Helpers.SAML;
using MPassHelperDotNet.Tests.Helpers.Certificates;
using MPassHelperDotNet.Tests.Helpers.Saml;
using MPassHelperDotNet.Tests.Helpers.Signing;
using Xunit;

namespace MPassHelperDotNet.Tests.Helpers.Kits
{
    internal static class AuthnRequestTestKit
    {
        internal const string AuthnRequestRoot = "AuthnRequest";

        internal static readonly string[] BaseRootAttributes =
        {
            "ID", "Version", "IssueInstant", "Destination", "AssertionConsumerServiceURL"
        };

        internal static string RequestXml(string html)
        {
            var xml = HtmlFormReader.GetSamlXml(html, "SAMLRequest");
            Assert.False(string.IsNullOrEmpty(xml));

            return xml;
        }

        internal static bool VerifiesWith(string xml, System.Security.Cryptography.X509Certificates.X509Certificate2 certificate)
        {
            var load = SamlXmlLoadHelper.LoadFromBase64(FixtureEncoding.ToBase64(xml), 0);
            if (!load.IsSuccess)
                return false;

            var verified = SamlMessageLoadAndVerifyHelper.VerifySignature(load.Response, TestCertificates.Collection(certificate), AuthnRequestRoot, false);

            return verified.IsSuccess && verified.Response;
        }

        internal static void AssertSignedBySp(string xml)
        {
            Assert.True(VerifiesWith(xml, TestCertificates.Sp), "AuthnRequest signature not verified with the SP certificate");
            Assert.False(VerifiesWith(xml, TestCertificates.Idp), "AuthnRequest signature verified with an unrelated certificate");

            var document = FixtureEncoding.LoadXml(xml);
            var root = document.DocumentElement;
            var ns = SamlNs.CreateNamespaceManager(document);
            var signature = Assert.Single(FixtureSigner.DirectSignatures(root));
            var reference = Assert.Single(signature.SelectNodes("ds:SignedInfo/ds:Reference", ns).Cast<XmlElement>());
            Assert.Equal("#" + root.GetAttribute("ID"), reference.GetAttribute("URI"));
        }

        internal static IReadOnlyList<string> RootAttributeNames(XmlElement root)
            => root.Attributes.Cast<XmlAttribute>()
                .Where(a => a.Prefix != "xmlns" && a.Name != "xmlns")
                .Select(a => a.Name)
                .OrderBy(n => n, StringComparer.Ordinal)
                .ToList();

        internal static string ReplaceText(string xml, string original, string replacement)
        {
            var index = xml.IndexOf(original, StringComparison.Ordinal);
            Assert.True(index >= 0, "Fragment not found: " + original);
            Assert.Equal(index, xml.LastIndexOf(original, StringComparison.Ordinal));

            return xml.Substring(0, index) + replacement + xml.Substring(index + original.Length);
        }
    }
}
