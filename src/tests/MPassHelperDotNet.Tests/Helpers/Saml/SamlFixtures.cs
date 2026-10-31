using System;
using System.Collections.Generic;
using MPassHelperDotNet.Tests.Models.Hosting;
using MPassHelperDotNet.Tests.Models.Saml;

namespace MPassHelperDotNet.Tests.Helpers.Saml
{
    internal static class SamlFixtures
    {
        internal const string DefaultNameId = "2000000000001";

        internal const string DefaultAuthIp = "192.0.2.10";

        internal static readonly TimeSpan DefaultValidity = TimeSpan.FromMinutes(5);

        internal static ResponseFixture LoginResponse(MPassTestSettings settings, DateTimeOffset now, string inResponseTo)
        {
            var assertion = new AssertionFixture
            {
                IssueInstant = now,
                Issuer = settings.IdentityProviderIssuer,
                NameId = DefaultNameId,
                ConditionsNotBefore = now.AddMinutes(-1),
                ConditionsNotOnOrAfter = now.Add(DefaultValidity),
                AuthnInstant = now,
                SessionIndex = SamlIds.New("_session"),
                SubjectLocalityAddress = DefaultAuthIp
            };
            assertion.AudienceRestrictions.Add(new List<string> { settings.SamlRequestIssuer });

            var confirmation = new SubjectConfirmationFixture { Method = SamlNs.MethodBearer };
            confirmation.Data.Add(new SubjectConfirmationDataFixture
            {
                Recipient = settings.SamlServiceLoginDestination,
                NotOnOrAfter = now.Add(DefaultValidity),
                InResponseTo = inResponseTo
            });
            assertion.SubjectConfirmations.Add(confirmation);

            assertion.Attributes.Add(new AttributeFixture("FirstName", "TestFirstName"));
            assertion.Attributes.Add(new AttributeFixture("LastName", "TestLastName"));
            assertion.Attributes.Add(new AttributeFixture("BirthDate", "1990-05-17"));
            assertion.Attributes.Add(new AttributeFixture("Gender", "Male"));
            assertion.Attributes.Add(new AttributeFixture("EmailAddress", "test.user@example.test"));
            assertion.Attributes.Add(new AttributeFixture("MobilePhone", "+37360000000"));
            assertion.Attributes.Add(new AttributeFixture("IsResident", "true"));
            assertion.Attributes.Add(new AttributeFixture("Language", "ro"));

            var response = new ResponseFixture
            {
                IssueInstant = now,
                Destination = settings.SamlServiceLoginDestination,
                InResponseTo = inResponseTo,
                Issuer = settings.IdentityProviderIssuer,
                StatusCode = SamlNs.StatusSuccess
            };
            response.Assertions.Add(assertion);

            return response;
        }

        internal static LogoutRequestFixture LogoutRequest(MPassTestSettings settings, DateTimeOffset now, string nameId = DefaultNameId,
            string sessionIndex = "_session-default")
        {
            var request = new LogoutRequestFixture
            {
                IssueInstant = now,
                Destination = settings.SamlServiceSingleLogoutDestination,
                Issuer = settings.IdentityProviderIssuer
            };
            request.NameIds.Add(nameId);
            request.SessionIndexes.Add(sessionIndex);

            return request;
        }

        internal static LogoutResponseFixture LogoutResponse(MPassTestSettings settings, DateTimeOffset now, string inResponseTo)
            => new LogoutResponseFixture
            {
                IssueInstant = now,
                Destination = settings.SamlServiceLogoutDestination,
                InResponseTo = inResponseTo,
                Issuer = settings.IdentityProviderIssuer,
                StatusCode = SamlNs.StatusSuccess
            };
    }
}
