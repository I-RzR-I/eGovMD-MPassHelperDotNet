using System;
using MPassHelperDotNet.Tests.Helpers.Saml;

namespace MPassHelperDotNet.Tests.Models.Saml
{
    internal sealed class LogoutResponseFixture
    {
        public string Id { get; set; } = SamlIds.New("_logoutresp");

        public DateTimeOffset? IssueInstant { get; set; }

        public string IssueInstantRaw { get; set; }

        public string Destination { get; set; }

        public string InResponseTo { get; set; }

        public string Issuer { get; set; }

        public string StatusCode { get; set; } = SamlNs.StatusSuccess;

        public string SubStatusCode { get; set; }

        public string StatusMessage { get; set; }
    }
}
