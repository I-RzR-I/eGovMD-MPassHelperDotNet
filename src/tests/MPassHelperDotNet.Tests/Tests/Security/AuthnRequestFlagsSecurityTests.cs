using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;
using System.Xml;
using MPassHelperDotNet.Models.Dto.AuthService.LoginRequest;
using MPassHelperDotNet.Models.Dto.RequestBuilder.LoginRequest;
using MPassHelperDotNet.Tests.Helpers.Certificates;
using MPassHelperDotNet.Tests.Helpers.Hosting;
using MPassHelperDotNet.Tests.Helpers.Runtime;
using MPassHelperDotNet.Tests.Helpers.Saml;
using MPassHelperDotNet.Tests.Helpers.Signing;
using MPassHelperDotNet.Tests.Models.Hosting;
using Xunit;
using static MPassHelperDotNet.Tests.Helpers.Kits.AuthnRequestTestKit;
using static MPassHelperDotNet.Tests.Helpers.Kits.SecurityTestKit;

namespace MPassHelperDotNet.Tests.Tests.Security
{
    [Trait(TestAreas.Trait, TestAreas.Security)]
    public class AuthnRequestFlagsSecurityTests
    {
        public static TheoryData<bool, bool> Flags => new TheoryData<bool, bool>
        {
            { false, false },
            { true, false },
            { false, true },
            { true, true }
        };

        [Theory]
        [MemberData(nameof(Flags))]
        public async Task GenerateAuth_FlagsOnSignedRoot_Test(bool forceAuthn, bool isPassive)
        {
            using var context = ServiceFactory.Create();

            var result = await context.Auth.GenerateAuthRequestAsync(new GenerateAuthRequestDto
            {
                RelayState = "rs",
                ForceAuthn = forceAuthn,
                IsPassive = isPassive
            }, Ct);

            AssertAccepted(result);
            AssertFlags(RequestXml(result.Response.HtmlDocument), forceAuthn, isPassive);
        }

        [Theory]
        [MemberData(nameof(Flags))]
        public async Task BuildLogin_FlagsOnSignedRoot_Test(bool forceAuthn, bool isPassive)
        {
            using var context = ServiceFactory.Create();

            var result = await context.Builder.BuildLogInRequestAsync(new BuildLogInRequestDto
            {
                RelayState = "rs",
                ForceAuthn = forceAuthn,
                IsPassive = isPassive
            }, Ct);

            AssertAccepted(result);
            AssertFlags(RequestXml(result.Response.HtmlAuthDocument), forceAuthn, isPassive);
        }

        [Theory]
        [MemberData(nameof(Flags))]
        public async Task GenerateAuth_FlagsAndLanguage_SignedRoot_Test(bool forceAuthn, bool isPassive)
        {
            using var context = ServiceFactory.Create(new MPassTestSettings
            {
                SamlLoginDestination = "https://idp.test.local/saml/login?a=1"
            });

            var result = await context.Auth.GenerateAuthRequestAsync(new GenerateAuthRequestDto
            {
                RelayState = "rs",
                ForceAuthn = forceAuthn,
                IsPassive = isPassive,
                Language = "ru"
            }, Ct);

            AssertAccepted(result);
            var html = result.Response.HtmlDocument;
            var xml = RequestXml(html);
            AssertFlags(xml, forceAuthn, isPassive);
            const string expectedUrl = "https://idp.test.local/saml/login?a=1&lang=ru";
            Assert.Equal(expectedUrl, HtmlFormReader.GetFormAction(html));
            Assert.Equal(expectedUrl, FixtureEncoding.LoadXml(xml).DocumentElement.GetAttribute("Destination"));
        }

        [Fact]
        public async Task GenerateAuth_FlagsAltered_NotVerified_Test()
        {
            using var context = ServiceFactory.Create();

            var flagged = await context.Auth.GenerateAuthRequestAsync(new GenerateAuthRequestDto
            {
                RelayState = "rs", 
                ForceAuthn = true, 
                IsPassive = true
            }, Ct);
            var plain = await context.Auth.GenerateAuthRequestAsync(new GenerateAuthRequestDto
            {
                RelayState = "rs"
            }, Ct);

            AssertAccepted(flagged);
            AssertAccepted(plain);
            var flaggedXml = RequestXml(flagged.Response.HtmlDocument);
            var plainXml = RequestXml(plain.Response.HtmlDocument);
            Assert.True(VerifiesWith(flaggedXml, TestCertificates.Sp));
            Assert.True(VerifiesWith(plainXml, TestCertificates.Sp));

            Assert.False(VerifiesWith(ReplaceText(flaggedXml, " ForceAuthn=\"true\"", string.Empty), TestCertificates.Sp));
            Assert.False(VerifiesWith(ReplaceText(flaggedXml, " IsPassive=\"true\"", string.Empty), TestCertificates.Sp));
            Assert.False(VerifiesWith(ReplaceText(flaggedXml, "IsPassive=\"true\"", "IsPassive=\"false\""), TestCertificates.Sp));
            Assert.False(VerifiesWith(ReplaceText(plainXml, " AssertionConsumerServiceURL=", " ForceAuthn=\"true\" AssertionConsumerServiceURL="), TestCertificates.Sp));
            Assert.False(VerifiesWith(ReplaceText(plainXml, " AssertionConsumerServiceURL=", " IsPassive=\"true\" AssertionConsumerServiceURL="), TestCertificates.Sp));
        }

        private static void AssertFlags(string xml, bool forceAuthn, bool isPassive)
        {
            AssertSignedBySp(xml);

            var document = FixtureEncoding.LoadXml(xml);
            var root = document.DocumentElement;
            var ns = SamlNs.CreateNamespaceManager(document);
            Assert.Equal(AuthnRequestRoot, root.LocalName);

            var expected = new List<string>(BaseRootAttributes);
            if (forceAuthn)
                expected.Add("ForceAuthn");
            if (isPassive)
                expected.Add("IsPassive");
            Assert.Equal(expected.OrderBy(n => n, StringComparer.Ordinal), RootAttributeNames(root));

            Assert.Equal(forceAuthn ? "true" : string.Empty, root.GetAttribute("ForceAuthn"));
            Assert.Equal(isPassive ? "true" : string.Empty, root.GetAttribute("IsPassive"));
            Assert.Equal(forceAuthn ? 1 : 0, document.SelectNodes("//@ForceAuthn").Count);
            Assert.Equal(isPassive ? 1 : 0, document.SelectNodes("//@IsPassive").Count);

            var children = root.ChildNodes.Cast<XmlNode>().OfType<XmlElement>().Select(e => e.LocalName).ToList();
            Assert.Equal(new[] { "Issuer", "Signature", "NameIDPolicy" }, children);
            var nameIdPolicy = (XmlElement)root.SelectSingleNode("saml2p:NameIDPolicy", ns);
            Assert.NotNull(nameIdPolicy);
            Assert.Equal(new[] { "AllowCreate" }, nameIdPolicy.Attributes.Cast<XmlAttribute>().Select(a => a.Name));
            Assert.Single(FixtureSigner.DirectSignatures(root));
        }
    }
}
