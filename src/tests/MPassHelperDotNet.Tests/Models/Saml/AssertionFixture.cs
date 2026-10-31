using System;
using System.Collections.Generic;
using MPassHelperDotNet.Tests.Helpers.Saml;

namespace MPassHelperDotNet.Tests.Models.Saml
{
    internal sealed class AssertionFixture
    {
        public string Id { get; set; } = SamlIds.New("_assert");

        public DateTimeOffset? IssueInstant { get; set; }

        public string Issuer { get; set; }

        public int SubjectCount { get; set; } = 1;

        public string NameId { get; set; }

        public int NameIdCount { get; set; } = 1;

        public int? NameIdCommentPosition { get; set; }

        public string NameIdFormat { get; set; }

        public List<SubjectConfirmationFixture> SubjectConfirmations { get; } = new List<SubjectConfirmationFixture>();

        public int ConditionsCount { get; set; } = 1;

        public DateTimeOffset? ConditionsNotBefore { get; set; }

        public DateTimeOffset? ConditionsNotOnOrAfter { get; set; }

        public List<List<string>> AudienceRestrictions { get; } = new List<List<string>>();

        public int AdviceEncryptedAssertionCount { get; set; }

        public int AuthnStatementCount { get; set; } = 1;

        public DateTimeOffset? AuthnInstant { get; set; }

        public string SessionIndex { get; set; }

        public DateTimeOffset? SessionNotOnOrAfter { get; set; }

        public string SubjectLocalityAddress { get; set; }

        public List<AttributeFixture> Attributes { get; } = new List<AttributeFixture>();
    }
}
