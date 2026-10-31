using System.Collections.Generic;
using MPassHelperDotNet.Tests.Helpers.Saml;

namespace MPassHelperDotNet.Tests.Models.Saml
{
    internal sealed class SubjectConfirmationFixture
    {
        public string Method { get; set; } = SamlNs.MethodBearer;

        public List<SubjectConfirmationDataFixture> Data { get; } = new List<SubjectConfirmationDataFixture>();
    }
}
