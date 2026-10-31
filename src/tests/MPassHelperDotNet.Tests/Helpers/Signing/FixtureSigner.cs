using System;
using System.Collections.Generic;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Security.Cryptography.Xml;
using System.Xml;
using MPassHelperDotNet.Tests.Helpers.Certificates;
using MPassHelperDotNet.Tests.Helpers.Saml;
using MPassHelperDotNet.Tests.Models.Signing;

namespace MPassHelperDotNet.Tests.Helpers.Signing
{
    internal static class FixtureSigner
    {
        internal static XmlDocument Sign(XmlDocument document) => Sign(document, new FixtureSigningOptions());

        internal static XmlDocument Sign(XmlDocument document, FixtureSigningOptions options)
        {
            if (document?.DocumentElement == null)
                throw new ArgumentException("The fixture document has no root element.", nameof(document));
            if (options == null)
                throw new ArgumentNullException(nameof(options));

            var working = FixtureEncoding.Reparse(document);
            switch (options.Placement)
            {
                case SignaturePlacement.Root:
                    SignElement(working, working.DocumentElement, options);
                    break;

                case SignaturePlacement.Assertion:
                    SignElement(working, FindAssertion(working), options);
                    break;

                case SignaturePlacement.RootAndAssertion:
                    SignElement(working, FindAssertion(working), options.ForSecondarySignature());
                    working = FixtureEncoding.Reparse(working);
                    SignElement(working, working.DocumentElement, options);
                    break;

                default:
                    throw new ArgumentOutOfRangeException(nameof(options), options.Placement, "Unknown signature placement.");
            }

            return FixtureEncoding.Reparse(working);
        }

        internal static string SignToBase64(XmlDocument document, FixtureSigningOptions options = null)
            => FixtureEncoding.ToBase64(Sign(document, options ?? new FixtureSigningOptions()));

        internal static IReadOnlyList<XmlElement> DirectSignatures(XmlElement element)
        {
            var signatures = new List<XmlElement>();
            foreach (XmlNode child in element.ChildNodes)
            {
                if (child is XmlElement childElement &&
                    childElement.LocalName == "Signature" &&
                    childElement.NamespaceURI == SamlNs.XmlDsig)
                    signatures.Add(childElement);
            }

            return signatures;
        }

        internal static XmlElement FindAssertion(XmlDocument document)
        {
            foreach (XmlNode child in document.DocumentElement.ChildNodes)
            {
                if (child is XmlElement element && element.LocalName == "Assertion" && element.NamespaceURI == SamlNs.Assertion)
                    return element;
            }

            throw new InvalidOperationException("The fixture has no saml2:Assertion child to sign.");
        }

        private static void SignElement(XmlDocument document, XmlElement target, FixtureSigningOptions options)
        {
            var targetId = target.GetAttribute("ID");
            var signedXml = new FixtureSignedXml(document, target, targetId);
            signedXml.SignedInfo.CanonicalizationMethod = options.CanonicalizationMethod;

            signedXml.AddReference(CreateReference(options.ReferenceUri ?? "#" + targetId, options));
            if (options.ExtraReferenceUri != null)
                signedXml.AddReference(CreateReference(options.ExtraReferenceUri, options));

            if (options.IncludeKeyInfo)
            {
                var keyInfo = new KeyInfo();
                keyInfo.AddClause(new KeyInfoX509Data(TestCertificates.PublicOnly(options.KeyInfoCertificate ?? options.Certificate)));
                signedXml.KeyInfo = keyInfo;
            }

            if (options.HmacKey != null)
            {
                using (var hmac = new HMACSHA256(options.HmacKey))
                {
                    signedXml.ComputeSignature(hmac);
                }
            }
            else
            {
                signedXml.SigningKey = options.Certificate.GetRSAPrivateKey()
                                       ?? throw new InvalidOperationException("The signing certificate has no RSA private key.");
                signedXml.SignedInfo.SignatureMethod = options.SignatureMethod;
                signedXml.ComputeSignature();
            }

            var signatureElement = signedXml.GetXml();
            if (!string.IsNullOrEmpty(options.ObjectIdAttributeName))
            {
                var objectElement = document.CreateElement("Object", SamlNs.XmlDsig);
                var data = document.CreateElement("t", "Data", SamlNs.TestMarker);
                data.SetAttribute(options.ObjectIdAttributeName, document.DocumentElement.GetAttribute("ID"));
                objectElement.AppendChild(data);
                signatureElement.AppendChild(objectElement);
            }

            var issuer = FindIssuer(target);
            if (issuer != null)
                target.InsertAfter(signatureElement, issuer);
            else
                target.PrependChild(signatureElement);

            if (options.DuplicateSignature)
                target.InsertAfter(signatureElement.CloneNode(true), signatureElement);
        }

        private static Reference CreateReference(string uri, FixtureSigningOptions options)
        {
            var reference = new Reference(uri) { DigestMethod = options.DigestMethod };
            foreach (var transformUri in options.TransformUris)
                reference.AddTransform(CreateTransform(transformUri));

            return reference;
        }

        private static Transform CreateTransform(string uri)
        {
            switch (uri)
            {
                case SignedXml.XmlDsigEnvelopedSignatureTransformUrl:
                    return new XmlDsigEnvelopedSignatureTransform();
                case SignedXml.XmlDsigExcC14NTransformUrl:
                    return new XmlDsigExcC14NTransform();
                case SignedXml.XmlDsigExcC14NWithCommentsTransformUrl:
                    return new XmlDsigExcC14NWithCommentsTransform();
                case SignedXml.XmlDsigC14NTransformUrl:
                    return new XmlDsigC14NTransform();
                case SignedXml.XmlDsigC14NWithCommentsTransformUrl:
                    return new XmlDsigC14NWithCommentsTransform();
                default:
                    throw new ArgumentException("Unsupported fixture transform URI: " + uri, nameof(uri));
            }
        }

        private static XmlElement FindIssuer(XmlElement element)
        {
            foreach (XmlNode child in element.ChildNodes)
            {
                if (child is XmlElement childElement && childElement.LocalName == "Issuer" && childElement.NamespaceURI == SamlNs.Assertion)
                    return childElement;
            }

            return null;
        }
    }
}
