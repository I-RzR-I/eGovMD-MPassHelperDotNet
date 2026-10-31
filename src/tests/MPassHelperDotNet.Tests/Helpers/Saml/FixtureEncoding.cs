using System;
using System.IO;
using System.Text;
using System.Xml;

namespace MPassHelperDotNet.Tests.Helpers.Saml
{
    internal static class FixtureEncoding
    {
        private static readonly UTF8Encoding Utf8NoBom = new UTF8Encoding(false);
        private static readonly UTF8Encoding Utf8Strict = new UTF8Encoding(false, true);

        internal static string ToXml(XmlDocument document) => document.OuterXml;

        internal static string ToBase64(XmlDocument document) => ToBase64(document.OuterXml);

        internal static string ToBase64(string xml) => Convert.ToBase64String(Utf8NoBom.GetBytes(xml));

        internal static string ToBase64(byte[] bytes) => Convert.ToBase64String(bytes);

        internal static string FromBase64(string base64) => Utf8Strict.GetString(Convert.FromBase64String(base64));

        internal static XmlDocument LoadXml(string xml)
        {
            var document = new XmlDocument { PreserveWhitespace = true, XmlResolver = null };
            var settings = new XmlReaderSettings { DtdProcessing = DtdProcessing.Prohibit, XmlResolver = null };
            using (var stringReader = new StringReader(xml))
            using (var reader = XmlReader.Create(stringReader, settings))
            {
                document.Load(reader);
            }

            return document;
        }

        internal static XmlDocument Reparse(XmlDocument document) => LoadXml(document.OuterXml);
    }
}
