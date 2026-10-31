using System;
using System.Security.Cryptography.Xml;
using System.Xml;

namespace MPassHelperDotNet.Tests.Helpers.Signing
{
    internal sealed class FixtureSignedXml : SignedXml
    {
        private readonly XmlElement _target;
        private readonly string _targetId;

        internal FixtureSignedXml(XmlDocument document, XmlElement target, string targetId)
            : base(document)
        {
            _target = target;
            _targetId = targetId;
        }

        public override XmlElement GetIdElement(XmlDocument document, string idValue)
        {
            if (!string.IsNullOrEmpty(_targetId) && string.Equals(idValue, _targetId, StringComparison.Ordinal))
                return _target;

            if (document == null || string.IsNullOrEmpty(idValue))
                return null;

            foreach (XmlNode node in document.SelectNodes("//*"))
            {
                if (!(node is XmlElement element))
                    continue;

                if (string.Equals(element.GetAttribute("ID"), idValue, StringComparison.Ordinal) ||
                    string.Equals(element.GetAttribute("Id"), idValue, StringComparison.Ordinal) ||
                    string.Equals(element.GetAttribute("id"), idValue, StringComparison.Ordinal))
                    return element;
            }

            return null;
        }
    }
}
