using System;
using System.Net;
using System.Text.RegularExpressions;

namespace MPassHelperDotNet.Tests.Helpers.Saml
{
    internal static class HtmlFormReader
    {
        private static readonly TimeSpan MatchTimeout = TimeSpan.FromSeconds(2);
        private const RegexOptions Options = RegexOptions.IgnoreCase | RegexOptions.CultureInvariant;

        internal static string GetInputValue(string html, string name)
        {
            if (html == null)
                return null;

            var pattern = "<input\\b[^>]*\\bname=\"" + Regex.Escape(name) + "\"[^>]*\\bvalue=\"([^\"]*)\"";
            var match = Regex.Match(html, pattern, Options, MatchTimeout);

            return match.Success ? WebUtility.HtmlDecode(match.Groups[1].Value) : null;
        }

        internal static string GetFormAction(string html)
        {
            if (html == null)
                return null;

            var match = Regex.Match(html, "<form\\b[^>]*\\baction=\"([^\"]*)\"", Options, MatchTimeout);

            return match.Success ? WebUtility.HtmlDecode(match.Groups[1].Value) : null;
        }

        internal static int CountForms(string html)
            => html == null ? 0 : Regex.Matches(html, "<form\\b", Options, MatchTimeout).Count;

        internal static string GetSamlXml(string html, string samlVariable)
        {
            var value = GetInputValue(html, samlVariable);

            return value == null ? null : FixtureEncoding.FromBase64(value);
        }
    }
}
