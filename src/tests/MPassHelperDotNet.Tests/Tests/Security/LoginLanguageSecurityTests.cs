using System;
using System.Linq;
using System.Threading.Tasks;
using MPassHelperDotNet.Helpers;
using MPassHelperDotNet.Helpers.Messages;
using MPassHelperDotNet.Models.Dto.AuthService.LoginRequest;
using MPassHelperDotNet.Models.Dto.RequestBuilder.LoginRequest;
using MPassHelperDotNet.Tests.Helpers.Certificates;
using MPassHelperDotNet.Tests.Helpers.Hosting;
using MPassHelperDotNet.Tests.Helpers.Runtime;
using MPassHelperDotNet.Tests.Helpers.Saml;
using MPassHelperDotNet.Tests.Models.Hosting;
using RzR.ResultMessage.Abstractions;
using Xunit;
using static MPassHelperDotNet.Tests.Helpers.Kits.AuthnRequestTestKit;
using static MPassHelperDotNet.Tests.Helpers.Kits.SecurityTestKit;

namespace MPassHelperDotNet.Tests.Tests.Security
{
    [Trait(TestAreas.Trait, TestAreas.Security)]
    public class LoginLanguageSecurityTests
    {
        private static readonly string LanguageNotSupportedText =
            string.Format(RequestBuilderMessages.LanguageNotSupported, string.Join(", ", DefaultStaticInfo.AllowedLanguages));

        public static TheoryData<string> UnsupportedLanguages => new TheoryData<string>
        {
            "en\"",
            "en'",
            "en\" onmouseover=\"x",
            "en<b>",
            "<script>x</script>",
            "en&lang=ru",
            "en&amp;",
            "en#top",
            "en?x=1",
            "e n",
            "en ro",
            "en\r\nSet-Cookie: t=1",
            "en\u0000",
            "javascript:alert(1)",
            "JavaScript:x",
            "lang=en",
            "en%22",
            "%65%6E",
            "en-US",
            "ro,ru",
            "\u0435n",
            "en\u200B",
            "eng",
            "e",
            new string('e', 81),
            new string('r', 4096),
            "en" + new string(' ', 4096) + "x"
        };

        public static TheoryData<string, string> AcceptedLanguages => new TheoryData<string, string>
        {
            { "en", "en" },
            { "EN", "en" },
            { " Ro ", "ro" },
            { "\tru\r\n", "ru" }
        };

        public static TheoryData<string, string, string> Destinations => new TheoryData<string, string, string>
        {
            { "https://idp.test.local/saml/login", "en", "https://idp.test.local/saml/login?lang=en" },
            { "https://idp.test.local/saml/login?a=1&b=2", "ro", "https://idp.test.local/saml/login?a=1&b=2&lang=ro" },
            { "https://idp.test.local/saml/login?a=1#top", "ru", "https://idp.test.local/saml/login?a=1&lang=ru#top" },
            { "https://idp.test.local/saml/login#top", "en", "https://idp.test.local/saml/login?lang=en#top" },
            { "https://idp.test.local/saml/login?xlang=ro", "en", "https://idp.test.local/saml/login?xlang=ro&lang=en" },
            { "https://idp.test.local/saml/login?LANG=ro&a=1", "en", "https://idp.test.local/saml/login?LANG=ro&a=1" },
            { "https://idp.test.local/saml/login?a=\"x\"&c='y'", "ru", "https://idp.test.local/saml/login?a=\"x\"&c='y'&lang=ru" }
        };

        [Theory]
        [MemberData(nameof(UnsupportedLanguages))]
        public async Task GenerateAuth_UnsupportedLanguage_Rejected_Test(string language)
        {
            using var context = ServiceFactory.Create();
            var logCount = context.Logs.Entries.Count;

            var result = await context.Auth.GenerateAuthRequestAsync(new GenerateAuthRequestDto
            {
                RelayState = "rs",
                Language = language
            }, Ct);

            AssertLanguageRejected(result);
            Assert.Null(result.Response);
            Assert.Equal(logCount, context.Logs.Entries.Count);
        }

        [Theory]
        [MemberData(nameof(UnsupportedLanguages))]
        public async Task BuildLogin_UnsupportedLanguage_Rejected_Test(string language)
        {
            using var context = ServiceFactory.Create();

            var result = await context.Builder.BuildLogInRequestAsync(new BuildLogInRequestDto
            {
                RelayState = "rs", 
                Language = language
            }, Ct);

            AssertLanguageRejected(result);
            Assert.True(result.Response == null
                        || (string.IsNullOrEmpty(result.Response.HtmlAuthDocument) && string.IsNullOrEmpty(result.Response.SamlResponse)));
        }

        [Theory]
        [MemberData(nameof(UnsupportedLanguages))]
        public async Task GenerateAuth_WithFlags_LanguageRejected_Test(string language)
        {
            using var context = ServiceFactory.Create();

            var result = await context.Auth.GenerateAuthRequestAsync(new GenerateAuthRequestDto
            {
                RelayState = "rs",
                Language = language,
                ForceAuthn = true,
                IsPassive = true
            }, Ct);

            AssertLanguageRejected(result);
            Assert.Null(result.Response);
        }

        [Theory]
        [MemberData(nameof(AcceptedLanguages))]
        public async Task GenerateAuth_SupportedLanguage_Normalised_Test(string language, string expected)
        {
            using var context = ServiceFactory.Create();

            var result = await context.Auth.GenerateAuthRequestAsync(new GenerateAuthRequestDto
            {
                RelayState = "rs", 
                Language = language
            }, Ct);

            AssertAccepted(result);
            var html = result.Response.HtmlDocument;
            var expectedUrl = MPassTestSettings.DefaultIdpLoginUrl + "?lang=" + expected;
            Assert.Equal(expectedUrl, HtmlFormReader.GetFormAction(html));
            var xml = RequestXml(html);
            Assert.Equal(expectedUrl, FixtureEncoding.LoadXml(xml).DocumentElement.GetAttribute("Destination"));
            AssertSignedBySp(xml);
        }

        [Theory]
        [MemberData(nameof(Destinations))]
        public async Task GenerateAuth_DestinationMatchesForm_Test(string destination, string language, string expectedUrl)
        {
            using var context = ServiceFactory.Create(new MPassTestSettings
            {
                SamlLoginDestination = destination
            });

            var result = await context.Auth.GenerateAuthRequestAsync(new GenerateAuthRequestDto
            {
                RelayState = "rs", 
                Language = language
            }, Ct);

            AssertAccepted(result);
            AssertDestinationAndAction(result.Response.HtmlDocument, expectedUrl);
        }

        [Theory]
        [MemberData(nameof(Destinations))]
        public async Task BuildLogin_DestinationMatchesForm_Test(string destination, string language, string expectedUrl)
        {
            using var context = ServiceFactory.Create(new MPassTestSettings
            {
                SamlLoginDestination = destination
            });

            var result = await context.Builder.BuildLogInRequestAsync(new BuildLogInRequestDto
            {
                RelayState = "rs", 
                Language = language
            }, Ct);

            AssertAccepted(result);
            AssertDestinationAndAction(result.Response.HtmlAuthDocument, expectedUrl);
            Assert.Equal(FixtureEncoding.ToBase64(RequestXml(result.Response.HtmlAuthDocument)), result.Response.SamlResponse);
        }

        [Fact]
        public async Task GenerateAuth_LanguageInDestination_Signed_Test()
        {
            var settings = new MPassTestSettings
            {
                SamlLoginDestination = "https://idp.test.local/saml/login?a=1"
            };
            using var context = ServiceFactory.Create(settings);

            var result = await context.Auth.GenerateAuthRequestAsync(new GenerateAuthRequestDto
            {
                RelayState = "rs",
                Language = "ro"
            }, Ct);

            AssertAccepted(result);
            var xml = RequestXml(result.Response.HtmlDocument);
            Assert.True(VerifiesWith(xml, TestCertificates.Sp));
            Assert.False(VerifiesWith(ReplaceText(xml, "&amp;lang=ro\"", "&amp;lang=ru\""), TestCertificates.Sp));
            Assert.False(VerifiesWith(ReplaceText(xml, "?a=1&amp;lang=ro\"", "?a=1\""), TestCertificates.Sp));
        }

        [Fact]
        public async Task GenerateAuth_BlankLanguage_KeepsDestination_Test()
        {
            const string destination = "https://idp.test.local/saml/login?a=1&b=2";
            using var context = ServiceFactory.Create(new MPassTestSettings
            {
                SamlLoginDestination = destination
            });

            foreach (var language in new[] { null, string.Empty, "   ", "\r\n\t" })
            {
                var result = await context.Auth.GenerateAuthRequestAsync(new GenerateAuthRequestDto
                {
                    RelayState = "rs",
                    Language = language
                }, Ct);

                AssertAccepted(result);
                AssertDestinationAndAction(result.Response.HtmlDocument, destination);
            }
        }

        [Fact]
        public void AllowedLanguages_FixedLowercaseCodes_Test()
        {
            Assert.Equal(new[] { "ro", "ru", "en" }, DefaultStaticInfo.AllowedLanguages);
            Assert.All(DefaultStaticInfo.AllowedLanguages, l => Assert.Matches("^[a-z]{2}$", l));
            Assert.Equal("lang", DefaultStaticInfo.LanguageQueryParameter);
            Assert.Equal("Language is not supported, the allowed values are: ro, ru, en!", LanguageNotSupportedText);
        }

        private static void AssertLanguageRejected(IResult result)
        {
            AssertRejectedWith(result, LanguageNotSupportedText);
            AssertOnlyFixedMessages(result);
            Assert.All(MessageTexts(result), t => Assert.Equal(LanguageNotSupportedText, t));
        }

        private static void AssertDestinationAndAction(string html, string expectedUrl)
        {
            Assert.Equal(1, HtmlFormReader.CountForms(html));
            var action = HtmlFormReader.GetFormAction(html);
            var xml = RequestXml(html);
            var root = FixtureEncoding.LoadXml(xml).DocumentElement;

            Assert.Equal(expectedUrl, action);
            Assert.Equal(action, root.GetAttribute("Destination"));
            Assert.DoesNotContain("<script", html, StringComparison.OrdinalIgnoreCase);
            if (expectedUrl.IndexOfAny(new[] { '&', '"', '\'' }) >= 0)
            {
                Assert.DoesNotContain("action=\"" + expectedUrl + "\"", html, StringComparison.Ordinal);
                Assert.DoesNotContain("Destination=\"" + expectedUrl + "\"", xml, StringComparison.Ordinal);
            }

            if (expectedUrl.IndexOf('&') >= 0)
                Assert.Contains("&amp;", RawDestination(xml), StringComparison.Ordinal);

            AssertSignedBySp(xml);
            Assert.Equal(BaseRootAttributes.OrderBy(n => n, StringComparer.Ordinal), RootAttributeNames(root));
        }

        private static string RawDestination(string xml)
        {
            const string marker = "Destination=\"";
            var start = xml.IndexOf(marker, StringComparison.Ordinal);
            Assert.True(start >= 0);
            start += marker.Length;

            return xml.Substring(start, xml.IndexOf('"', start) - start);
        }
    }
}
