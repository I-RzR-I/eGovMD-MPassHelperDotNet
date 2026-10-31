using System.Security.Cryptography.Xml;
using System.Xml;

namespace MPassHelperDotNet.Tests.Helpers.Saml
{
    internal static class SamlNs
    {
        internal const string Protocol = "urn:oasis:names:tc:SAML:2.0:protocol";
        internal const string Assertion = "urn:oasis:names:tc:SAML:2.0:assertion";
        internal const string XmlDsig = SignedXml.XmlDsigNamespaceUrl;
        internal const string XmlEnc = "http://www.w3.org/2001/04/xmlenc#";

        internal const string TestMarker = "urn:mpasshelperdotnet:tests";

        internal const string StatusSuccess = "urn:oasis:names:tc:SAML:2.0:status:Success";
        internal const string StatusRequester = "urn:oasis:names:tc:SAML:2.0:status:Requester";
        internal const string StatusResponder = "urn:oasis:names:tc:SAML:2.0:status:Responder";
        internal const string StatusPartialLogout = "urn:oasis:names:tc:SAML:2.0:status:PartialLogout";
        internal const string StatusAuthnFailed = "urn:oasis:names:tc:SAML:2.0:status:AuthnFailed";
        internal const string StatusUnknownPrincipal = "urn:oasis:names:tc:SAML:2.0:status:UnknownPrincipal";

        internal const string MethodBearer = "urn:oasis:names:tc:SAML:2.0:cm:bearer";
        internal const string MethodHolderOfKey = "urn:oasis:names:tc:SAML:2.0:cm:holder-of-key";
        internal const string MethodSenderVouches = "urn:oasis:names:tc:SAML:2.0:cm:sender-vouches";

        internal const string AuthnContextPasswordProtectedTransport = "urn:oasis:names:tc:SAML:2.0:ac:classes:PasswordProtectedTransport";

        internal static XmlNamespaceManager CreateNamespaceManager(XmlDocument document)
        {
            var manager = new XmlNamespaceManager(document.NameTable);
            manager.AddNamespace("saml2p", Protocol);
            manager.AddNamespace("saml2", Assertion);
            manager.AddNamespace("ds", XmlDsig);
            manager.AddNamespace("t", TestMarker);

            return manager;
        }
    }
}
