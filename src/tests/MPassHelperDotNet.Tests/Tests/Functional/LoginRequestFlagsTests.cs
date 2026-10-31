using System.Threading.Tasks;
using System.Xml;
using MPassHelperDotNet.Models.Dto.AuthService.LoginRequest;
using MPassHelperDotNet.Models.Dto.AuthService.LoginResponse;
using MPassHelperDotNet.Models.Dto.RequestBuilder.LoginRequest;
using MPassHelperDotNet.Tests.Helpers.Hosting;
using MPassHelperDotNet.Tests.Helpers.Kits;
using MPassHelperDotNet.Tests.Helpers.Runtime;
using MPassHelperDotNet.Tests.Helpers.Saml;
using Xunit;

namespace MPassHelperDotNet.Tests.Tests.Functional
{
    [Trait(TestAreas.Trait, TestAreas.Functional)]
    public class LoginRequestFlagsTests
    {
        [Fact]
        public void LoginRequestDtos_New_FlagsFalseLanguageNull_Test()
        {
            var generate = new GenerateAuthRequestDto();
            var build = new BuildLogInRequestDto();

            Assert.False(generate.ForceAuthn);
            Assert.False(generate.IsPassive);
            Assert.Null(generate.Language);
            Assert.False(build.ForceAuthn);
            Assert.False(build.IsPassive);
            Assert.Null(build.Language);
        }

        [Fact]
        public async Task GenerateAuth_DefaultDto_MissingFlagAttributes_Test()
        {
            using var context = ServiceFactory.Create();

            var result = await context.Auth.GenerateAuthRequestAsync(new GenerateAuthRequestDto { RelayState = "rs" },
                TestContext.Current.CancellationToken);

            FunctionalTestKit.AssertSuccess(result);
            
            var raw = HtmlFormReader.GetSamlXml(result.Response.HtmlDocument, "SAMLRequest");
            var root = AuthnRequestRoot(result.Response.HtmlDocument);
            Assert.False(root.HasAttribute("ForceAuthn"));
            Assert.False(root.HasAttribute("IsPassive"));
            Assert.DoesNotContain("ForceAuthn", raw);
            Assert.DoesNotContain("IsPassive", raw);
        }

        [Theory]
        [InlineData(true, false)]
        [InlineData(false, true)]
        [InlineData(true, true)]
        [InlineData(false, false)]
        public async Task GenerateAuth_Flags_AttributesOnlyWhenSet_Test(bool forceAuthn, bool isPassive)
        {
            using var context = ServiceFactory.Create();

            var result = await context.Auth.GenerateAuthRequestAsync(
                new GenerateAuthRequestDto { RelayState = "rs", ForceAuthn = forceAuthn, IsPassive = isPassive },
                TestContext.Current.CancellationToken);

            FunctionalTestKit.AssertSuccess(result);
            AssertFlags(AuthnRequestRoot(result.Response.HtmlDocument), forceAuthn, isPassive);
        }

        [Theory]
        [InlineData(true, false)]
        [InlineData(false, true)]
        [InlineData(true, true)]
        [InlineData(false, false)]
        public async Task BuildLogin_Flags_AttributesOnlyWhenSetSigned_Test(bool forceAuthn, bool isPassive)
        {
            using var context = ServiceFactory.Create();

            var result = await context.Builder.BuildLogInRequestAsync(
                new BuildLogInRequestDto { RelayState = "rs", ForceAuthn = forceAuthn, IsPassive = isPassive },
                TestContext.Current.CancellationToken);

            FunctionalTestKit.AssertSuccess(result);
            var root = AuthnRequestRoot(result.Response.HtmlAuthDocument);
            AssertFlags(root, forceAuthn, isPassive);
            Assert.Equal(result.Response.AuthRequestId, root.GetAttribute("ID"));
            Assert.Equal(result.Response.SamlResponse, HtmlFormReader.GetInputValue(result.Response.HtmlAuthDocument, "SAMLRequest"));
            var ns = SamlNs.CreateNamespaceManager(root.OwnerDocument);
            Assert.NotNull(root.SelectSingleNode("ds:Signature", ns));
            Assert.Equal(context.Settings.SamlServiceLoginDestination, root.GetAttribute("AssertionConsumerServiceURL"));
        }

        [Fact]
        public async Task GenerateAuth_FlagsThenGetUserData_Succeeds_Test()
        {
            using var context = ServiceFactory.Create();
            var ct = TestContext.Current.CancellationToken;

            var generated = await context.Auth.GenerateAuthRequestAsync(
                new GenerateAuthRequestDto { RelayState = "rs", ForceAuthn = true, IsPassive = true }, ct);

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

        private static void AssertFlags(XmlElement root, bool forceAuthn, bool isPassive)
        {
            Assert.Equal(forceAuthn, root.HasAttribute("ForceAuthn"));
            Assert.Equal(isPassive, root.HasAttribute("IsPassive"));
            if (forceAuthn)
                Assert.Equal("true", root.GetAttribute("ForceAuthn"));
            if (isPassive)
                Assert.Equal("true", root.GetAttribute("IsPassive"));
            
            Assert.Equal("AuthnRequest", root.LocalName);
            Assert.Equal(SamlNs.Protocol, root.NamespaceURI);
        }

        private static XmlElement AuthnRequestRoot(string html)
            => FunctionalTestKit.DecodeOnceToXml(HtmlFormReader.GetInputValue(html, "SAMLRequest")).DocumentElement;
    }
}
