using System;
using System.Collections.Generic;
using MPassHelperDotNet.Tests.Helpers.Saml;

namespace MPassHelperDotNet.Tests.Models.Saml
{
    internal sealed class LogoutRequestFixture
    {
        public string Id { get; set; } = SamlIds.New("_logoutreq");

        public DateTimeOffset? IssueInstant { get; set; }

        public string IssueInstantRaw { get; set; }

        public string Destination { get; set; }

        public DateTimeOffset? NotOnOrAfter { get; set; }

        public string Issuer { get; set; }

        public List<string> NameIds { get; } = new List<string>();

        public int EncryptedIdCount { get; set; }

        public int BaseIdCount { get; set; }

        public List<string> SessionIndexes { get; } = new List<string>();
    }
}
