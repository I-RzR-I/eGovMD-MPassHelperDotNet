using System;
using System.Text;
using System.Xml;
using MPassHelperDotNet.Tests.Models.Saml;

namespace MPassHelperDotNet.Tests.Helpers.Saml
{
    internal static class SamlFixtureBuilder
    {
        private const string XmlnsNamespace = "http://www.w3.org/2000/xmlns/";

        internal static XmlDocument Build(ResponseFixture fixture, bool indent = false)
        {
            var document = NewDocument();
            var root = CreateRoot(document, "Response");
            SetAttribute(root, "ID", fixture.Id);
            SetAttribute(root, "Version", "2.0");
            SetAttribute(root, "IssueInstant", fixture.IssueInstantRaw ?? Time(fixture.IssueInstant));
            SetAttribute(root, "Destination", fixture.Destination);
            SetAttribute(root, "InResponseTo", fixture.InResponseTo);

            AppendTextElement(root, AssertionElement(document, "Issuer"), fixture.Issuer);

            if (!string.IsNullOrEmpty(fixture.DuplicateIdAttributeName) || fixture.EmbeddedDocument != null)
            {
                var extensions = ProtocolElement(document, "Extensions");
                if (!string.IsNullOrEmpty(fixture.DuplicateIdAttributeName))
                {
                    var data = document.CreateElement("t", "Data", SamlNs.TestMarker);
                    data.SetAttribute(fixture.DuplicateIdAttributeName, fixture.Id);
                    extensions.AppendChild(data);
                }

                if (fixture.EmbeddedDocument?.DocumentElement != null)
                    extensions.AppendChild(document.ImportNode(fixture.EmbeddedDocument.DocumentElement, true));

                root.AppendChild(extensions);
            }

            AppendStatus(document, root, fixture.StatusCode, fixture.SubStatusCode, fixture.StatusMessage);

            foreach (var assertion in fixture.Assertions)
                root.AppendChild(BuildAssertion(document, assertion));

            for (var i = 0; i < fixture.EncryptedAssertionCount; i++)
                root.AppendChild(BuildEncryptedElement(document, "EncryptedAssertion"));

            return Finish(document, indent);
        }

        internal static XmlDocument Build(LogoutRequestFixture fixture, bool indent = false)
        {
            var document = NewDocument();
            var root = CreateRoot(document, "LogoutRequest");
            SetAttribute(root, "ID", fixture.Id);
            SetAttribute(root, "Version", "2.0");
            SetAttribute(root, "IssueInstant", fixture.IssueInstantRaw ?? Time(fixture.IssueInstant));
            SetAttribute(root, "Destination", fixture.Destination);
            SetAttribute(root, "NotOnOrAfter", Time(fixture.NotOnOrAfter));

            AppendTextElement(root, AssertionElement(document, "Issuer"), fixture.Issuer);

            for (var i = 0; i < fixture.BaseIdCount; i++)
            {
                var baseId = AssertionElement(document, "BaseID");
                baseId.SetAttribute("NameQualifier", "test");
                root.AppendChild(baseId);
            }

            foreach (var nameId in fixture.NameIds)
                AppendTextElement(root, AssertionElement(document, "NameID"), nameId ?? string.Empty);

            for (var i = 0; i < fixture.EncryptedIdCount; i++)
                root.AppendChild(BuildEncryptedElement(document, "EncryptedID"));

            foreach (var sessionIndex in fixture.SessionIndexes)
                AppendTextElement(root, ProtocolElement(document, "SessionIndex"), sessionIndex ?? string.Empty);

            return Finish(document, indent);
        }

        internal static XmlDocument Build(LogoutResponseFixture fixture, bool indent = false)
        {
            var document = NewDocument();
            var root = CreateRoot(document, "LogoutResponse");
            SetAttribute(root, "ID", fixture.Id);
            SetAttribute(root, "Version", "2.0");
            SetAttribute(root, "IssueInstant", fixture.IssueInstantRaw ?? Time(fixture.IssueInstant));
            SetAttribute(root, "Destination", fixture.Destination);
            SetAttribute(root, "InResponseTo", fixture.InResponseTo);

            AppendTextElement(root, AssertionElement(document, "Issuer"), fixture.Issuer);
            AppendStatus(document, root, fixture.StatusCode, fixture.SubStatusCode, fixture.StatusMessage);

            return Finish(document, indent);
        }

        internal static string Time(DateTimeOffset? value)
            => value.HasValue ? XmlConvert.ToString(value.Value.UtcDateTime, XmlDateTimeSerializationMode.Utc) : null;

        private static XmlElement BuildAssertion(XmlDocument document, AssertionFixture fixture)
        {
            var assertion = AssertionElement(document, "Assertion");
            SetAttribute(assertion, "ID", fixture.Id);
            SetAttribute(assertion, "Version", "2.0");
            SetAttribute(assertion, "IssueInstant", Time(fixture.IssueInstant));

            AppendTextElement(assertion, AssertionElement(document, "Issuer"), fixture.Issuer);

            for (var s = 0; s < fixture.SubjectCount; s++)
            {
                var subject = AssertionElement(document, "Subject");
                if (fixture.NameId != null)
                {
                    for (var n = 0; n < fixture.NameIdCount; n++)
                        subject.AppendChild(BuildNameId(document, fixture));
                }

                foreach (var confirmation in fixture.SubjectConfirmations)
                {
                    var confirmationElement = AssertionElement(document, "SubjectConfirmation");
                    SetAttribute(confirmationElement, "Method", confirmation.Method);
                    foreach (var data in confirmation.Data)
                    {
                        var dataElement = AssertionElement(document, "SubjectConfirmationData");
                        SetAttribute(dataElement, "NotBefore", Time(data.NotBefore));
                        SetAttribute(dataElement, "NotOnOrAfter", Time(data.NotOnOrAfter));
                        SetAttribute(dataElement, "Recipient", data.Recipient);
                        SetAttribute(dataElement, "InResponseTo", data.InResponseTo);
                        SetAttribute(dataElement, "Address", data.Address);
                        confirmationElement.AppendChild(dataElement);
                    }

                    subject.AppendChild(confirmationElement);
                }

                assertion.AppendChild(subject);
            }

            for (var c = 0; c < fixture.ConditionsCount; c++)
            {
                var conditions = AssertionElement(document, "Conditions");
                SetAttribute(conditions, "NotBefore", Time(fixture.ConditionsNotBefore));
                SetAttribute(conditions, "NotOnOrAfter", Time(fixture.ConditionsNotOnOrAfter));
                foreach (var audiences in fixture.AudienceRestrictions)
                {
                    var restriction = AssertionElement(document, "AudienceRestriction");
                    foreach (var audience in audiences)
                        AppendTextElement(restriction, AssertionElement(document, "Audience"), audience ?? string.Empty);

                    conditions.AppendChild(restriction);
                }

                assertion.AppendChild(conditions);
            }

            if (fixture.AdviceEncryptedAssertionCount > 0)
            {
                var advice = AssertionElement(document, "Advice");
                for (var i = 0; i < fixture.AdviceEncryptedAssertionCount; i++)
                    advice.AppendChild(BuildEncryptedElement(document, "EncryptedAssertion"));

                assertion.AppendChild(advice);
            }

            for (var a = 0; a < fixture.AuthnStatementCount; a++)
            {
                var statement = AssertionElement(document, "AuthnStatement");
                SetAttribute(statement, "AuthnInstant", Time(fixture.AuthnInstant));
                SetAttribute(statement, "SessionIndex", fixture.SessionIndex);
                SetAttribute(statement, "SessionNotOnOrAfter", Time(fixture.SessionNotOnOrAfter));
                if (fixture.SubjectLocalityAddress != null)
                {
                    var locality = AssertionElement(document, "SubjectLocality");
                    locality.SetAttribute("Address", fixture.SubjectLocalityAddress);
                    statement.AppendChild(locality);
                }

                var context = AssertionElement(document, "AuthnContext");
                AppendTextElement(context, AssertionElement(document, "AuthnContextClassRef"), SamlNs.AuthnContextPasswordProtectedTransport);
                statement.AppendChild(context);
                assertion.AppendChild(statement);
            }

            if (fixture.Attributes.Count > 0)
            {
                var statement = AssertionElement(document, "AttributeStatement");
                foreach (var attribute in fixture.Attributes)
                {
                    var attributeElement = AssertionElement(document, "Attribute");
                    SetAttribute(attributeElement, "Name", attribute.Name);
                    foreach (var value in attribute.Values)
                    {
                        var valueElement = AssertionElement(document, "AttributeValue");
                        if (attribute.ValuesAsMarkup)
                        {
                            var markup = document.CreateElement("t", "b", SamlNs.TestMarker);
                            markup.AppendChild(document.CreateTextNode(value ?? string.Empty));
                            valueElement.AppendChild(markup);
                        }
                        else
                        {
                            valueElement.AppendChild(document.CreateTextNode(value ?? string.Empty));
                        }

                        attributeElement.AppendChild(valueElement);
                    }

                    statement.AppendChild(attributeElement);
                }

                assertion.AppendChild(statement);
            }

            return assertion;
        }

        private static XmlElement BuildNameId(XmlDocument document, AssertionFixture fixture)
        {
            var nameId = AssertionElement(document, "NameID");
            SetAttribute(nameId, "Format", fixture.NameIdFormat);

            var value = fixture.NameId;
            if (fixture.NameIdCommentPosition.HasValue &&
                fixture.NameIdCommentPosition.Value > 0 &&
                fixture.NameIdCommentPosition.Value < value.Length)
            {
                var position = fixture.NameIdCommentPosition.Value;
                nameId.AppendChild(document.CreateTextNode(value.Substring(0, position)));
                nameId.AppendChild(document.CreateComment("fixture-comment"));
                nameId.AppendChild(document.CreateTextNode(value.Substring(position)));
            }
            else
            {
                nameId.AppendChild(document.CreateTextNode(value));
            }

            return nameId;
        }

        private static XmlElement BuildEncryptedElement(XmlDocument document, string localName)
        {
            var element = AssertionElement(document, localName);
            var encryptedData = document.CreateElement("xenc", "EncryptedData", SamlNs.XmlEnc);
            encryptedData.SetAttribute("Type", SamlNs.XmlEnc + "Element");
            var cipherData = document.CreateElement("xenc", "CipherData", SamlNs.XmlEnc);
            var cipherValue = document.CreateElement("xenc", "CipherValue", SamlNs.XmlEnc);
            cipherValue.AppendChild(document.CreateTextNode("AAAA"));
            cipherData.AppendChild(cipherValue);
            encryptedData.AppendChild(cipherData);
            element.AppendChild(encryptedData);

            return element;
        }

        private static void AppendStatus(XmlDocument document, XmlElement root, string statusCode, string subStatusCode, string statusMessage)
        {
            if (statusCode == null)
                return;

            var status = ProtocolElement(document, "Status");
            var code = ProtocolElement(document, "StatusCode");
            code.SetAttribute("Value", statusCode);
            if (subStatusCode != null)
            {
                var subCode = ProtocolElement(document, "StatusCode");
                subCode.SetAttribute("Value", subStatusCode);
                code.AppendChild(subCode);
            }

            status.AppendChild(code);
            AppendTextElement(status, ProtocolElement(document, "StatusMessage"), statusMessage);
            root.AppendChild(status);
        }

        private static XmlDocument NewDocument() => new XmlDocument { PreserveWhitespace = true, XmlResolver = null };

        private static XmlElement CreateRoot(XmlDocument document, string localName)
        {
            var root = ProtocolElement(document, localName);
            var assertionPrefix = document.CreateAttribute("xmlns", "saml2", XmlnsNamespace);
            assertionPrefix.Value = SamlNs.Assertion;
            root.Attributes.Append(assertionPrefix);
            document.AppendChild(root);

            return root;
        }

        private static XmlElement ProtocolElement(XmlDocument document, string localName)
            => document.CreateElement("saml2p", localName, SamlNs.Protocol);

        private static XmlElement AssertionElement(XmlDocument document, string localName)
            => document.CreateElement("saml2", localName, SamlNs.Assertion);

        private static void SetAttribute(XmlElement element, string name, string value)
        {
            if (value != null)
                element.SetAttribute(name, value);
        }

        private static void AppendTextElement(XmlElement parent, XmlElement child, string text)
        {
            if (text == null)
                return;

            child.AppendChild(parent.OwnerDocument.CreateTextNode(text));
            parent.AppendChild(child);
        }

        private static XmlDocument Finish(XmlDocument document, bool indent)
        {
            if (!indent)
                return FixtureEncoding.Reparse(document);

            var builder = new StringBuilder();
            var settings = new XmlWriterSettings
            {
                Indent = true,
                IndentChars = "  ",
                OmitXmlDeclaration = true,
                NewLineChars = "\n",
                NewLineHandling = NewLineHandling.Replace
            };
            using (var writer = XmlWriter.Create(builder, settings))
            {
                document.Save(writer);
            }

            return FixtureEncoding.LoadXml(builder.ToString());
        }
    }
}
