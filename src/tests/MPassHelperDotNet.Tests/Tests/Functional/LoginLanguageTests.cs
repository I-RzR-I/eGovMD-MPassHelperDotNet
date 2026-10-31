using System;
using System.Threading.Tasks;
using System.Xml;
using MPassHelperDotNet.Helpers;
using MPassHelperDotNet.Helpers.Messages;
using MPassHelperDotNet.Models.Dto.AuthService.LoginRequest;
using MPassHelperDotNet.Models.Dto.AuthService.LoginResponse;
using MPassHelperDotNet.Models.Dto.RequestBuilder.LoginRequest;
using MPassHelperDotNet.Tests.Helpers.Hosting;
using MPassHelperDotNet.Tests.Helpers.Kits;
using MPassHelperDotNet.Tests.Helpers.Runtime;
using MPassHelperDotNet.Tests.Helpers.Saml;
using MPassHelperDotNet.Tests.Models.Hosting;
using RzR.ResultMessage.Abstractions;
using Xunit;

namespace MPassHelperDotNet.Tests.Tests.Functional
{
    [Trait(TestAreas.Trait, TestAreas.Functional)]
    public class LoginLanguageTests
    {
        private const string Login = MPassTestSettings.DefaultIdpLoginUrl;

        private static readonly string LanguageNotSupportedText =
            string.Format(RequestBuilderMessages.LanguageNotSupported, string.Join(", ", DefaultStaticInfo.AllowedLanguages));

        [Theory]
        [InlineData("ro", "ro")]
        [InlineData("ru", "ru")]
        [InlineData("en", "en")]
        [InlineData("RO", "ro")]
        [InlineData("Ru", "ru")]
        [InlineData(" en ", "en")]
        [InlineData("\tEN\r\n", "en")]
        public async Task BuildLogin_SupportedLanguage_Normalised_Test(string language, string expected)
        {
            using var context = ServiceFactory.Create();

            var result = await Build(context, language);

            FunctionalTestKit.AssertSuccess(result);
            AssertLoginUrl(result.Response.HtmlAuthDocument, Login + "?lang=" + expected);
        }

        [Theory]
        [InlineData("RU", "ru")]
        [InlineData(" ro ", "ro")]
        public async Task GenerateAuth_SupportedLanguage_Normalised_Test(string language, string expected)
        {
            using var context = ServiceFactory.Create();

            var result = await context.Auth.GenerateAuthRequestAsync(new GenerateAuthRequestDto { RelayState = "rs", Language = language },
                TestContext.Current.CancellationToken);

            FunctionalTestKit.AssertSuccess(result);
            AssertLoginUrl(result.Response.HtmlDocument, Login + "?lang=" + expected);
        }

        [Theory]
        [InlineData("fr")]
        [InlineData("de")]
        [InlineData("ro-RO")]
        [InlineData("english")]
        [InlineData("r o")]
        [InlineData("ro&x=1")]
        [InlineData("ro#x")]
        [InlineData("e")]
        public async Task BuildLogin_UnsupportedLanguage_Fails_Test(string language)
        {
            using var context = ServiceFactory.Create();

            var result = await Build(context, language);

            FunctionalTestKit.AssertFailureWith(result, LanguageNotSupportedText);
            Assert.Contains(LanguageNotSupportedText, FunctionalTestKit.Texts(result));
            Assert.DoesNotContain(FunctionalTestKit.Texts(result), text => text.Contains("{0}", StringComparison.Ordinal));
            Assert.Null(result.Response);
        }

        [Theory]
        [InlineData("fr")]
        [InlineData("ro-RO")]
        public async Task GenerateAuth_UnsupportedLanguage_Fails_Test(string language)
        {
            using var context = ServiceFactory.Create();

            var result = await context.Auth.GenerateAuthRequestAsync(new GenerateAuthRequestDto { RelayState = "rs", Language = language },
                TestContext.Current.CancellationToken);

            FunctionalTestKit.AssertFailureWith(result, LanguageNotSupportedText);
            Assert.Contains(LanguageNotSupportedText, FunctionalTestKit.Texts(result));
            Assert.DoesNotContain(FunctionalTestKit.Texts(result), text => text.Contains("{0}", StringComparison.Ordinal));
            Assert.Null(result.Response);
        }

        [Fact]
        public void LanguageNotSupported_Message_ListsAllowed_Test()
        {
            Assert.Equal("Language is not supported, the allowed values are: {0}!", RequestBuilderMessages.LanguageNotSupported);
            Assert.Equal("Language is not supported, the allowed values are: ro, ru, en!", LanguageNotSupportedText);
            Assert.Equal(new[] { "ro", "ru", "en" }, DefaultStaticInfo.AllowedLanguages);
            Assert.Equal("lang", DefaultStaticInfo.LanguageQueryParameter);
        }

        [Theory]
        [InlineData(null)]
        [InlineData("")]
        [InlineData("   ")]
        [InlineData("\t")]
        public async Task BuildLogin_BlankLanguage_KeepsDestination_Test(string language)
        {
            using var context = ServiceFactory.Create();

            var result = await Build(context, language);

            FunctionalTestKit.AssertSuccess(result);
            AssertLoginUrl(result.Response.HtmlAuthDocument, Login);
            Assert.DoesNotContain("lang=", HtmlFormReader.GetFormAction(result.Response.HtmlAuthDocument), StringComparison.Ordinal);
        }

        [Theory]
        [InlineData("https://idp.test.local/saml/login?tenant=a", "https://idp.test.local/saml/login?tenant=a&lang=ru")]
        [InlineData("https://idp.test.local/saml/login?tenant=a&mode=b", "https://idp.test.local/saml/login?tenant=a&mode=b&lang=ru")]
        [InlineData("https://idp.test.local/saml/login#top", "https://idp.test.local/saml/login?lang=ru#top")]
        [InlineData("https://idp.test.local/saml/login?tenant=a#top", "https://idp.test.local/saml/login?tenant=a&lang=ru#top")]
        [InlineData("https://idp.test.local/saml/login?", "https://idp.test.local/saml/login?lang=ru")]
        [InlineData("https://idp.test.local/saml/login?tenant=a&", "https://idp.test.local/saml/login?tenant=a&lang=ru")]
        [InlineData("https://idp.test.local/saml/login?xlang=ro", "https://idp.test.local/saml/login?xlang=ro&lang=ru")]
        [InlineData("https://idp.test.local/saml/login?language=ro", "https://idp.test.local/saml/login?language=ro&lang=ru")]
        [InlineData("https://idp.test.local/saml/login?tenant=lang", "https://idp.test.local/saml/login?tenant=lang&lang=ru")]
        [InlineData("https://idp.test.local/saml/login#lang=ro", "https://idp.test.local/saml/login?lang=ru#lang=ro")]
        public async Task BuildLogin_DestinationShapes_LanguageAppended_Test(string destination, string expected)
        {
            using var context = ServiceFactory.Create(new MPassTestSettings { SamlLoginDestination = destination });

            var result = await Build(context, "RU");

            FunctionalTestKit.AssertSuccess(result);
            AssertLoginUrl(result.Response.HtmlAuthDocument, expected);
        }

        [Theory]
        [InlineData("https://idp.test.local/saml/login?lang=ro")]
        [InlineData("https://idp.test.local/saml/login?LANG=ro")]
        [InlineData("https://idp.test.local/saml/login?tenant=a&lang=ro")]
        [InlineData("https://idp.test.local/saml/login?tenant=a&Lang=ro#top")]
        [InlineData("https://idp.test.local/saml/login?lang")]
        [InlineData("https://idp.test.local/saml/login?lang=")]
        public async Task BuildLogin_DestinationHasLanguage_Kept_Test(string destination)
        {
            using var context = ServiceFactory.Create(new MPassTestSettings { SamlLoginDestination = destination });

            var result = await Build(context, "en");

            FunctionalTestKit.AssertSuccess(result);
            AssertLoginUrl(result.Response.HtmlAuthDocument, destination);
        }

        [Fact]
        public async Task BuildLogin_DestinationQuery_AmpersandEncoded_Test()
        {
            using var context = ServiceFactory.Create(new MPassTestSettings { SamlLoginDestination = "https://idp.test.local/saml/login?tenant=a" });

            var result = await Build(context, "ro");

            FunctionalTestKit.AssertSuccess(result);
            var html = result.Response.HtmlAuthDocument;
            Assert.Contains("action=\"https://idp.test.local/saml/login?tenant=a&amp;lang=ro\"", html, StringComparison.Ordinal);
            var xml = HtmlFormReader.GetSamlXml(html, "SAMLRequest");
            Assert.Contains("Destination=\"https://idp.test.local/saml/login?tenant=a&amp;lang=ro\"", xml, StringComparison.Ordinal);
        }

        [Fact]
        public async Task BuildLogin_LanguageWithFlags_AllApplied_Test()
        {
            using var context = ServiceFactory.Create();

            var result = await context.Builder.BuildLogInRequestAsync(
                new BuildLogInRequestDto { RelayState = "rs", Language = "en", ForceAuthn = true, IsPassive = true },
                TestContext.Current.CancellationToken);

            FunctionalTestKit.AssertSuccess(result);
            
            var root = AssertLoginUrl(result.Response.HtmlAuthDocument, Login + "?lang=en");
            Assert.Equal("true", root.GetAttribute("ForceAuthn"));
            Assert.Equal("true", root.GetAttribute("IsPassive"));
            Assert.Equal("rs", HtmlFormReader.GetInputValue(result.Response.HtmlAuthDocument, "RelayState"));
        }

        [Fact]
        public async Task BuildLogin_LongRelayState_FailsBeforeLanguage_Test()
        {
            using var context = ServiceFactory.Create();

            var result = await context.Builder.BuildLogInRequestAsync(
                new BuildLogInRequestDto { RelayState = new string('r', 100_000), Language = "fr" },
                TestContext.Current.CancellationToken);

            FunctionalTestKit.AssertFailureWith(result, RequestBuilderMessages.RelayStateTooLong);
            Assert.DoesNotContain(LanguageNotSupportedText, FunctionalTestKit.Texts(result));
            Assert.DoesNotContain(FunctionalTestKit.Texts(result), text => text.StartsWith("Language is not supported", StringComparison.Ordinal));
        }

        [Fact]
        public async Task GenerateAuth_LanguageThenGetUserData_Succeeds_Test()
        {
            using var context = ServiceFactory.Create();
            var ct = TestContext.Current.CancellationToken;

            var generated = await context.Auth.GenerateAuthRequestAsync(new GenerateAuthRequestDto { RelayState = "rs", Language = "ru" }, ct);

            FunctionalTestKit.AssertSuccess(generated);
            var requestId = generated.Response.AuthRequestId;
            var login = await context.Auth.GetUserDataFromAuthResponseAsync(new GetUserDataFromAuthResponseDto
            {
                SamlResponse = context.SignedBase64(context.NewLoginResponse(requestId)),
                AuthRequestId = requestId
            }, ct);

            FunctionalTestKit.AssertSuccess(login);
            Assert.Equal(requestId, login.Response.UserInfo.RequestId);
        }

        private static Task<IResult<BuildLogInRequestResultDto>> Build(MPassTestContext context, string language)
            => context.Builder.BuildLogInRequestAsync(new BuildLogInRequestDto { RelayState = "rs", Language = language },
                TestContext.Current.CancellationToken);

        private static XmlElement AssertLoginUrl(string html, string expected)
        {
            Assert.Equal(1, HtmlFormReader.CountForms(html));
            Assert.Equal(expected, HtmlFormReader.GetFormAction(html));
          
            var root = FunctionalTestKit.DecodeOnceToXml(HtmlFormReader.GetInputValue(html, "SAMLRequest")).DocumentElement;
            Assert.Equal("AuthnRequest", root.LocalName);
            Assert.Equal(expected, root.GetAttribute("Destination"));

            return root;
        }
    }
}
