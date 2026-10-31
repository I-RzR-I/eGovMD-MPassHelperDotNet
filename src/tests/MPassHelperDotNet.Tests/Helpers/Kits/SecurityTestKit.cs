using System;
using System.Collections.Generic;
using System.Linq;
using System.Reflection;
using System.Security.Cryptography.Xml;
using System.Text.RegularExpressions;
using System.Threading;
using System.Threading.Tasks;
using System.Xml;
using MPassHelperDotNet.Helpers.Messages;
using MPassHelperDotNet.Models.Dto.AuthService.ExternalLogoutRequest;
using MPassHelperDotNet.Models.Dto.AuthService.LoginResponse;
using MPassHelperDotNet.Models.Dto.AuthService.LogoutResponse;
using MPassHelperDotNet.Tests.Helpers.Certificates;
using MPassHelperDotNet.Tests.Helpers.Hosting;
using MPassHelperDotNet.Tests.Helpers.Saml;
using MPassHelperDotNet.Tests.Helpers.Signing;
using MPassHelperDotNet.Tests.Models.Signing;
using RzR.ResultMessage.Abstractions;
using RzR.ResultMessage.Enums;
using Xunit;

namespace MPassHelperDotNet.Tests.Helpers.Kits
{
    internal static class SecurityTestKit
    {
        internal const string DefaultLogoutSessionIndex = "_session-default";

        internal static CancellationToken Ct => TestContext.Current.CancellationToken;

        internal static string NewRequestId() => SamlIds.New("_req");

        internal static Task<IResult<GetUserDataFromAuthResponseResultDto>> SubmitLoginAsync(MPassTestContext context, string samlResponse,
            string authRequestId)
            => context.Auth.GetUserDataFromAuthResponseAsync(
                new GetUserDataFromAuthResponseDto { SamlResponse = samlResponse, AuthRequestId = authRequestId }, Ct);

        internal static Task<IResult> SubmitLogoutResponseAsync(MPassTestContext context, string samlResponse, string logOutRequestId)
            => context.Auth.ValidateLogoutResponseAsync(
                new ValidateLogoutResponseDto { SamlResponse = samlResponse, LogOutRequestId = logOutRequestId }, Ct);

        internal static Task<IResult<ProcessExternalLogoutRequestResultDto>> SubmitLogoutRequestAsync(MPassTestContext context, string samlRequest,
            string nameId = SamlFixtures.DefaultNameId, string sessionIndex = DefaultLogoutSessionIndex, string relayState = null)
            => context.Auth.ProcessExternalLogoutRequestAsync(
                new ProcessExternalLogoutRequestDto
                {
                    SamlRequest = samlRequest,
                    SessionIndexId = sessionIndex,
                    UserIdentifierId = nameId,
                    RelayState = relayState
                }, Ct);

        internal static IReadOnlyList<string> MessageTexts(IResult result)
        {
            var texts = new List<string>();
            if (result?.Messages == null)
                return texts;

            foreach (var message in result.Messages)
            {
                if (message?.Message == null)
                    continue;

                if (!string.IsNullOrEmpty(message.Message.Info))
                    texts.Add(message.Message.Info);
                if (message.Message.Details != null)
                    texts.AddRange(message.Message.Details.Where(d => !string.IsNullOrEmpty(d)));
            }

            return texts;
        }

        internal static string Describe(IResult result) => string.Join(" || ", MessageTexts(result));

        internal static void AssertRejected(IResult result)
        {
            Assert.NotNull(result);
            Assert.False(result.IsSuccess, "Expected a Failure, got Success. Messages: " + Describe(result));
            AssertNoExceptionDetails(result);
        }

        internal static void AssertRejectedWith(IResult result, string expectedMessage)
        {
            AssertRejected(result);
            Assert.True(MessageTexts(result).Any(t => string.Equals(t, expectedMessage, StringComparison.Ordinal)),
                "Expected message '" + expectedMessage + "'. Actual: " + Describe(result));
        }

        internal static void AssertAccepted(IResult result)
        {
            Assert.NotNull(result);
            Assert.True(result.IsSuccess, "Expected Success. Messages: " + Describe(result));
        }

        internal static void AssertNoExceptionDetails(IResult result)
        {
            if (result?.Messages == null)
                return;

            foreach (var message in result.Messages)
                Assert.NotEqual(MessageType.Exception, message.MessageType);

            foreach (var text in MessageTexts(result))
            {
                Assert.DoesNotContain("Exception", text, StringComparison.Ordinal);
                Assert.DoesNotContain("   at ", text, StringComparison.Ordinal);
                Assert.DoesNotContain("<saml", text, StringComparison.Ordinal);
                Assert.DoesNotContain("<?xml", text, StringComparison.Ordinal);
            }
        }

        internal static void AssertOnlyFixedMessages(IResult result)
        {
            foreach (var text in MessageTexts(result))
                Assert.True(FixedMessagePatterns.Value.Any(p => p.IsMatch(text)), "Not a fixed message text: '" + text + "'");
        }

        private static readonly Type[] FixedMessageTypes =
        {
            typeof(DefaultMessages),
            typeof(SamlLoadValidationMessages),
            typeof(RequestBuilderMessages),
            typeof(AuthDataMessages),
            typeof(OptionsValidationMessages)
        };

        private static readonly Lazy<IReadOnlyList<Regex>> FixedMessagePatterns = new Lazy<IReadOnlyList<Regex>>(() =>
        {
            var uncovered = typeof(DefaultMessages).Assembly.GetTypes()
                .Where(t => t.Namespace == typeof(DefaultMessages).Namespace
                            && t.Name.EndsWith("Messages", StringComparison.Ordinal)
                            && !FixedMessageTypes.Contains(t))
                .Select(t => t.FullName)
                .ToList();
            if (uncovered.Count > 0)
                throw new InvalidOperationException("Message types missing from the fixed message list: " + string.Join(", ", uncovered));

            var patterns = new List<Regex>();
            foreach (var type in FixedMessageTypes)
            {
                foreach (var field in type.GetFields(BindingFlags.Public | BindingFlags.NonPublic | BindingFlags.Static))
                {
                    if (!field.IsLiteral || field.FieldType != typeof(string))
                        continue;

                    var value = (string)field.GetRawConstantValue();
                    var pattern = "^" + Regex.Replace(Regex.Escape(value), @"\\\{\d+}", "(?s:.*)") + "$";
                    patterns.Add(new Regex(pattern, RegexOptions.CultureInvariant, TimeSpan.FromSeconds(2)));
                }
            }

            return patterns;
        });

        internal static readonly string[] CommonRejectedVariants =
        {
            "unsigned",
            "two-root-signatures",
            "two-references",
            "reference-to-non-root",
            "empty-reference-uri",
            "root-id-missing",
            "root-id-empty",
            "duplicate-ID",
            "duplicate-Id",
            "duplicate-id-lowercase",
            "duplicate-ID-in-ds-Object",
            "duplicate-Id-in-ds-Object",
            "content-altered",
            "wrong-key-with-keyinfo",
            "wrong-key-with-idp-cert-in-keyinfo",
            "sha1-default",
            "inclusive-c14n-transform",
            "c14n-withcomments-transform",
            "duplicate-enveloped",
            "missing-enveloped",
            "exc-c14n-withcomments-transform",
            "exc-c14n-withcomments-canonicalization",
            "hmac",
            "inclusive-c14n-canonicalization"
        };

        internal static TheoryData<string> CommonRejectedVariantData()
        {
            var data = new TheoryData<string>();
            foreach (var variant in CommonRejectedVariants)
                data.Add(variant);

            return data;
        }

        internal static XmlDocument ApplyVariant(XmlDocument unsigned, string variant)
        {
            var document = FixtureEncoding.Reparse(unsigned);
            var rootId = document.DocumentElement.GetAttribute("ID");

            switch (variant)
            {
                case "unsigned":
                    return document;

                case "two-root-signatures":
                    return FixtureSigner.Sign(document, new FixtureSigningOptions { DuplicateSignature = true });

                case "two-references":
                    return FixtureSigner.Sign(document, new FixtureSigningOptions { ExtraReferenceUri = "#" + rootId });

                case "reference-to-non-root":
                {
                    var otherId = SamlIds.New("_other");
                    AddExtensionsElementWithAttribute(document, "ID", otherId);

                    return FixtureSigner.Sign(document, new FixtureSigningOptions { ReferenceUri = "#" + otherId });
                }

                case "empty-reference-uri":
                    return FixtureSigner.Sign(document, new FixtureSigningOptions { ReferenceUri = string.Empty });

                case "root-id-missing":
                    document.DocumentElement.RemoveAttribute("ID");

                    return FixtureSigner.Sign(document, new FixtureSigningOptions { ReferenceUri = string.Empty });

                case "root-id-empty":
                    document.DocumentElement.SetAttribute("ID", string.Empty);

                    return FixtureSigner.Sign(document, new FixtureSigningOptions { ReferenceUri = string.Empty });

                case "duplicate-ID":
                    AddExtensionsElementWithAttribute(document, "ID", rootId);

                    return FixtureSigner.Sign(document);

                case "duplicate-Id":
                    AddExtensionsElementWithAttribute(document, "Id", rootId);

                    return FixtureSigner.Sign(document);

                case "duplicate-id-lowercase":
                    AddExtensionsElementWithAttribute(document, "id", rootId);

                    return FixtureSigner.Sign(document);

                case "duplicate-ID-in-ds-Object":
                    return FixtureSigner.Sign(document, new FixtureSigningOptions { ObjectIdAttributeName = "ID" });

                case "duplicate-Id-in-ds-Object":
                    return FixtureSigner.Sign(document, new FixtureSigningOptions { ObjectIdAttributeName = "Id" });

                case "content-altered":
                {
                    var signed = FixtureSigner.Sign(document);
                    signed.DocumentElement.SetAttribute("Consent", "urn:mpasshelperdotnet:tests:altered");

                    return FixtureEncoding.Reparse(signed);
                }

                case "wrong-key-with-keyinfo":
                    return FixtureSigner.Sign(document, new FixtureSigningOptions { Certificate = TestCertificates.WrongKey });

                case "wrong-key-with-idp-cert-in-keyinfo":
                    return FixtureSigner.Sign(document, new FixtureSigningOptions
                    {
                        Certificate = TestCertificates.WrongKey,
                        KeyInfoCertificate = TestCertificates.Idp
                    });

                case "rotation-cert":
                    return FixtureSigner.Sign(document, new FixtureSigningOptions { Certificate = TestCertificates.IdpRotation });

                case "sha1-default":
                case "sha1-allowed":
                    return FixtureSigner.Sign(document, FixtureSigningOptions.Sha1());

                case "inclusive-c14n-transform":
                    return FixtureSigner.Sign(document, Transforms(SignedXml.XmlDsigEnvelopedSignatureTransformUrl, SignedXml.XmlDsigC14NTransformUrl));

                case "c14n-withcomments-transform":
                    return FixtureSigner.Sign(document,
                        Transforms(SignedXml.XmlDsigEnvelopedSignatureTransformUrl, SignedXml.XmlDsigC14NWithCommentsTransformUrl));

                case "enveloped-only":
                    return FixtureSigner.Sign(document, FixtureSigningOptions.EnvelopedOnly());

                case "duplicate-enveloped":
                    return FixtureSigner.Sign(document, Transforms(SignedXml.XmlDsigEnvelopedSignatureTransformUrl,
                        SignedXml.XmlDsigEnvelopedSignatureTransformUrl, SignedXml.XmlDsigExcC14NTransformUrl));

                case "missing-enveloped":
                    return FixtureSigner.Sign(document, Transforms(SignedXml.XmlDsigExcC14NTransformUrl));

                case "exc-c14n-withcomments-transform":
                    return FixtureSigner.Sign(document,
                        Transforms(SignedXml.XmlDsigEnvelopedSignatureTransformUrl, SignedXml.XmlDsigExcC14NWithCommentsTransformUrl));

                case "exc-c14n-withcomments-canonicalization":
                    return FixtureSigner.Sign(document, new FixtureSigningOptions { CanonicalizationMethod = SignedXml.XmlDsigExcC14NWithCommentsTransformUrl });

                case "hmac":
                    return FixtureSigner.Sign(document, new FixtureSigningOptions { HmacKey = new byte[32] });

                case "inclusive-c14n-canonicalization":
                    return FixtureSigner.Sign(document, new FixtureSigningOptions { CanonicalizationMethod = SignedXml.XmlDsigC14NTransformUrl });

                default:
                    throw new ArgumentOutOfRangeException(nameof(variant), variant, "Unknown signature variant.");
            }
        }

        private static FixtureSigningOptions Transforms(params string[] uris)
            => new FixtureSigningOptions { TransformUris = new List<string>(uris) };

        internal static void AddExtensionsElementWithAttribute(XmlDocument document, string attributeName, string value)
        {
            var root = document.DocumentElement;
            var extensions = document.CreateElement("saml2p", "Extensions", SamlNs.Protocol);
            var data = document.CreateElement("t", "Data", SamlNs.TestMarker);
            data.SetAttribute(attributeName, value);
            extensions.AppendChild(data);

            XmlNode issuer = null;
            foreach (XmlNode child in root.ChildNodes)
            {
                if (child is XmlElement element && element.LocalName == "Issuer" && element.NamespaceURI == SamlNs.Assertion)
                {
                    issuer = element;
                    break;
                }
            }

            if (issuer != null)
                root.InsertAfter(extensions, issuer);
            else
                root.PrependChild(extensions);
        }
    }
}
