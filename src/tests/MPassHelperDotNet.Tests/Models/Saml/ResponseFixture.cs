using System;
using System.Collections.Generic;
using System.Xml;
using MPassHelperDotNet.Tests.Helpers.Saml;

namespace MPassHelperDotNet.Tests.Models.Saml
{
    internal sealed class ResponseFixture
    {
        public string Id { get; set; } = SamlIds.New("_resp");

        public DateTimeOffset? IssueInstant { get; set; }

        public string IssueInstantRaw { get; set; }

        public string Destination { get; set; }

        public string InResponseTo { get; set; }

        public string Issuer { get; set; }

        public string StatusCode { get; set; } = SamlNs.StatusSuccess;

        public string SubStatusCode { get; set; }

        public string StatusMessage { get; set; }

        public List<AssertionFixture> Assertions { get; } = new List<AssertionFixture>();

        public int EncryptedAssertionCount { get; set; }

        public string DuplicateIdAttributeName { get; set; }

        public XmlDocument EmbeddedDocument { get; set; }
    }
}
