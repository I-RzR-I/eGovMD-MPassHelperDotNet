using System;

namespace MPassHelperDotNet.Tests.Helpers.Saml
{
    internal static class SamlIds
    {
        internal static string New(string prefix = "_id") => prefix + "-" + Guid.NewGuid().ToString("N");
    }
}
