using System;

namespace MPassHelperDotNet.Tests.Models.Saml
{
    internal sealed class SubjectConfirmationDataFixture
    {
        public string Recipient { get; set; }

        public DateTimeOffset? NotOnOrAfter { get; set; }

        public DateTimeOffset? NotBefore { get; set; }

        public string InResponseTo { get; set; }

        public string Address { get; set; }
    }
}
