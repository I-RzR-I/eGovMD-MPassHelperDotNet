using System;
using System.Linq;
using System.Threading.Tasks;
using MPassHelperDotNet.Helpers.Messages;
using MPassHelperDotNet.Models.Dto.AuthService.LoginRequest;
using MPassHelperDotNet.Models.Dto.AuthService.LoginResponse;
using MPassHelperDotNet.Tests.Helpers.Certificates;
using MPassHelperDotNet.Tests.Helpers.Hosting;
using MPassHelperDotNet.Tests.Helpers.Kits;
using MPassHelperDotNet.Tests.Helpers.Runtime;
using MPassHelperDotNet.Tests.Helpers.Saml;
using MPassHelperDotNet.Tests.Models.Saml;
using MPassHelperDotNet.Tests.Models.Signing;
using Xunit;

namespace MPassHelperDotNet.Tests.Tests.Functional
{
    [Trait(TestAreas.Trait, TestAreas.Functional)]
    public class LoginFlowTests
    {
        [Theory]
        [MemberData(nameof(CulturesAndLayouts))]
        public async Task GetUserData_RootSigned_SucceedsMapsUser_Test(string culture, bool indent)
        {
            using var scope = new CultureScope(culture);
            using var context = ServiceFactory.Create();
            var requestId = FunctionalTestKit.NewRequestId();
            var fixture = context.NewLoginResponse(requestId);
            var assertion = fixture.Assertions[0];
            var samlResponse = context.SignedBase64(fixture, indent: indent);

            var result = await context.Auth.GetUserDataFromAuthResponseAsync(
                new GetUserDataFromAuthResponseDto { SamlResponse = samlResponse, AuthRequestId = requestId },
                TestContext.Current.CancellationToken);

            FunctionalTestKit.AssertSuccess(result);
            var user = result.Response.UserInfo;
            Assert.NotNull(user);
            Assert.Equal(SamlFixtures.DefaultNameId, user.Idnp);
            Assert.Equal(requestId, user.RequestId);
            Assert.Equal(SamlFixtures.DefaultAuthIp, user.AuthIp);
            Assert.Equal("TestFirstName", user.FirstName);
            Assert.Equal("TestLastName", user.LastName);
            Assert.Equal("Male", user.Gender);
            Assert.Equal("test.user@example.test", user.Email);
            Assert.Equal("+37360000000", user.MobilePhoneNumber);
            Assert.Equal("ro", user.Language);
            Assert.True(user.IsResident);
            Assert.Equal(new DateTime(1990, 5, 17), user.BirthDate);
            Assert.Equal(assertion.SessionIndex, result.Response.SessionIndexId);
            Assert.Equal(new[] { "TestFirstName" }, result.Response.UserAttributes["FirstName"]);
        }

        [Fact]
        public async Task GenerateAuth_ThenGetUserData_Succeeds_Test()
        {
            using var context = ServiceFactory.Create();
            var ct = TestContext.Current.CancellationToken;

            var generated = await context.Auth.GenerateAuthRequestAsync(new GenerateAuthRequestDto { RelayState = "rs-login" }, ct);

            FunctionalTestKit.AssertSuccess(generated);
            
            var authRequestId = generated.Response.AuthRequestId;
            Assert.Matches(FunctionalTestKit.RequestIdPattern, authRequestId);
           
            var html = generated.Response.HtmlDocument;
            Assert.Equal(1, HtmlFormReader.CountForms(html));
            Assert.Equal(context.Settings.SamlLoginDestination, HtmlFormReader.GetFormAction(html));
            Assert.Equal("rs-login", HtmlFormReader.GetInputValue(html, "RelayState"));
            
            var authnRequest = FunctionalTestKit.DecodeOnceToXml(HtmlFormReader.GetInputValue(html, "SAMLRequest"));
            var root = authnRequest.DocumentElement;
            Assert.Equal("AuthnRequest", root.LocalName);
            Assert.Equal(SamlNs.Protocol, root.NamespaceURI);
            Assert.Equal(authRequestId, root.GetAttribute("ID"));
            Assert.Equal(context.Settings.SamlLoginDestination, root.GetAttribute("Destination"));
            Assert.Equal(context.Settings.SamlServiceLoginDestination, root.GetAttribute("AssertionConsumerServiceURL"));
            Assert.Equal("2026-06-01T10:00:00Z", root.GetAttribute("IssueInstant"));
          
            var ns = SamlNs.CreateNamespaceManager(authnRequest);
            Assert.Equal(context.Settings.SamlRequestIssuer, root.SelectSingleNode("saml2:Issuer", ns)?.InnerText);
            Assert.NotNull(root.SelectSingleNode("ds:Signature", ns));

            var response = context.SignedBase64(context.NewLoginResponse(authRequestId));
            var login = await context.Auth.GetUserDataFromAuthResponseAsync(
                new GetUserDataFromAuthResponseDto { SamlResponse = response, AuthRequestId = authRequestId }, ct);

            FunctionalTestKit.AssertSuccess(login);
            Assert.Equal(authRequestId, login.Response.UserInfo.RequestId);
        }

        [Theory]
        [MemberData(nameof(Cultures))]
        public async Task GetUserData_InvalidBoolDate_SucceedsDefaults_Test(string culture)
        {
            using var scope = new CultureScope(culture);
            using var context = ServiceFactory.Create();
            var requestId = FunctionalTestKit.NewRequestId();
            var fixture = context.NewLoginResponse(requestId);
            var attributes = fixture.Assertions[0].Attributes;
            attributes.RemoveAll(a => a.Name == "IsResident" || a.Name == "BirthDate");
            attributes.Add(new AttributeFixture("IsResident", "da"));
            attributes.Add(new AttributeFixture("BirthDate", "not-a-date"));

            var result = await Login(context, fixture, requestId);

            FunctionalTestKit.AssertSuccess(result);
            Assert.False(result.Response.UserInfo.IsResident);
            Assert.Null(result.Response.UserInfo.BirthDate);
            Assert.Equal(new[] { "da" }, result.Response.UserAttributes["IsResident"]);
            Assert.Equal(new[] { "not-a-date" }, result.Response.UserAttributes["BirthDate"]);
        }

        [Theory]
        [MemberData(nameof(Cultures))]
        public async Task GetUserData_IsoBirthDate_ParsedInvariantly_Test(string culture)
        {
            using var scope = new CultureScope(culture);
            using var context = ServiceFactory.Create();
            var requestId = FunctionalTestKit.NewRequestId();
            var fixture = context.NewLoginResponse(requestId);

            var result = await Login(context, fixture, requestId);

            FunctionalTestKit.AssertSuccess(result);
            var birthDate = result.Response.UserInfo.BirthDate;
            Assert.NotNull(birthDate);
            Assert.Equal(new DateTime(1990, 5, 17, 0, 0, 0), birthDate.Value);
            Assert.Equal(DateTimeKind.Utc, birthDate.Value.Kind);
        }

        [Theory]
        [InlineData("1990-05-17T00:00:00+03:00")]
        [InlineData("1990-05-17T23:30:00-05:00")]
        [InlineData("1990-05-17T01:00:00+03:00")]
        [InlineData("1990-05-17T00:00:00Z")]
        [InlineData("1990-05-17")]
        public async Task GetUserData_BirthDateOffset_KeepsCalendarDate_Test(string birthDate)
        {
            using var scope = new CultureScope(TestCultures.Turkish);
            using var context = ServiceFactory.Create();
            var requestId = FunctionalTestKit.NewRequestId();
            var fixture = context.NewLoginResponse(requestId);
            var attributes = fixture.Assertions[0].Attributes;
            attributes.RemoveAll(a => a.Name == "BirthDate");
            attributes.Add(new AttributeFixture("BirthDate", birthDate));

            var result = await Login(context, fixture, requestId);

            FunctionalTestKit.AssertSuccess(result);
            Assert.Equal(new DateTime(1990, 5, 17, 0, 0, 0, DateTimeKind.Utc), result.Response.UserInfo.BirthDate);
            Assert.Equal(DateTimeKind.Utc, result.Response.UserInfo.BirthDate.Value.Kind);
        }

        [Theory]
        [MemberData(nameof(Cultures))]
        public async Task GetUserData_MixedCaseNames_MappedInvariantly_Test(string culture)
        {
            using var scope = new CultureScope(culture);
            using var context = ServiceFactory.Create();
            var requestId = FunctionalTestKit.NewRequestId();
            var fixture = context.NewLoginResponse(requestId);
            var attributes = fixture.Assertions[0].Attributes;
            attributes.Clear();
            attributes.Add(new AttributeFixture("ISRESIDENT", "true"));
            attributes.Add(new AttributeFixture("IDNO", "1003600000001"));
            attributes.Add(new AttributeFixture("NameIdentifier", "id-attr"));

            var result = await Login(context, fixture, requestId);

            FunctionalTestKit.AssertSuccess(result);
            Assert.True(result.Response.UserInfo.IsResident);
            Assert.Equal("1003600000001", result.Response.UserInfo.Idno);
            Assert.Equal("id-attr", result.Response.UserInfo.NameIdentifier);
        }

        [Fact]
        public async Task GetUserData_DuplicateAttributes_ValuesMerged_Test()
        {
            using var context = ServiceFactory.Create();
            var requestId = FunctionalTestKit.NewRequestId();
            var fixture = context.NewLoginResponse(requestId);
            var attributes = fixture.Assertions[0].Attributes;
            attributes.Add(new AttributeFixture("Role", "admin"));
            attributes.Add(new AttributeFixture("Role", "user", "viewer"));

            var result = await Login(context, fixture, requestId);

            FunctionalTestKit.AssertSuccess(result);
            Assert.Equal(new[] { "admin", "user", "viewer" }, result.Response.UserAttributes["Role"].ToArray());
        }

        [Fact]
        public async Task GetUserData_ValueWithMarkup_ReturnsInnerText_Test()
        {
            using var context = ServiceFactory.Create();
            var requestId = FunctionalTestKit.NewRequestId();
            var fixture = context.NewLoginResponse(requestId);
            fixture.Assertions[0].Attributes.Add(new AttributeFixture("Organization", "Acme & Sons") { ValuesAsMarkup = true });
            fixture.Assertions[0].Attributes.Add(new AttributeFixture("Note", "a<b>&\"c\""));

            var result = await Login(context, fixture, requestId);

            FunctionalTestKit.AssertSuccess(result);
            Assert.Equal(new[] { "Acme & Sons" }, result.Response.UserAttributes["Organization"]);
            Assert.Equal(new[] { "a<b>&\"c\"" }, result.Response.UserAttributes["Note"]);
        }

        [Fact]
        public async Task GetUserData_MultiValuedAttribute_Concatenated_Test()
        {
            using var context = ServiceFactory.Create();
            var requestId = FunctionalTestKit.NewRequestId();
            var fixture = context.NewLoginResponse(requestId);
            var attributes = fixture.Assertions[0].Attributes;
            attributes.RemoveAll(a => a.Name == "FirstName");
            attributes.Add(new AttributeFixture("FirstName", "TestFirstName", "TestMiddleName"));

            var result = await Login(context, fixture, requestId);

            FunctionalTestKit.AssertSuccess(result);
            Assert.Equal("TestFirstNameTestMiddleName", result.Response.UserInfo.FirstName);
            Assert.Equal(new[] { "TestFirstName", "TestMiddleName" }, result.Response.UserAttributes["FirstName"].ToArray());
        }

        [Fact]
        public async Task GetUserData_Parallel100_EachResultCorrect_Test()
        {
            using var context = ServiceFactory.Create();
            var cases = Enumerable.Range(0, 100).Select(i =>
            {
                var requestId = FunctionalTestKit.NewRequestId();
                var fixture = context.NewLoginResponse(requestId);
                var nameId = (2000000000000L + i).ToString(System.Globalization.CultureInfo.InvariantCulture);
                fixture.Assertions[0].NameId = nameId;
                var shouldFail = i % 5 == 4;
                var options = shouldFail ? new FixtureSigningOptions { Certificate = TestCertificates.WrongKey } : null;

                return new { requestId, nameId, shouldFail, saml = context.SignedBase64(fixture, options, indent: i % 2 == 0) };
            }).ToList();

            var results = await Task.WhenAll(cases.Select(c => Task.Run(async () =>
            {
                using var serviceScope = context.CreateScope();
                var auth = Microsoft.Extensions.DependencyInjection.ServiceProviderServiceExtensions
                    .GetRequiredService<MPassHelperDotNet.Abstractions.Services.IAuthMPassService>(serviceScope.ServiceProvider);

                return await auth.GetUserDataFromAuthResponseAsync(
                    new GetUserDataFromAuthResponseDto { SamlResponse = c.saml, AuthRequestId = c.requestId },
                    TestContext.Current.CancellationToken);
            })));

            for (var i = 0; i < cases.Count; i++)
            {
                if (cases[i].shouldFail)
                {
                    FunctionalTestKit.AssertFailure(results[i]);
                    continue;
                }

                FunctionalTestKit.AssertSuccess(results[i]);
                Assert.Equal(cases[i].nameId, results[i].Response.UserInfo.Idnp);
                Assert.Equal(cases[i].requestId, results[i].Response.UserInfo.RequestId);
            }
        }

        [Fact]
        public async Task GetUserData_NoAttributes_SucceedsWithIdnpOnly_Test()
        {
            using var context = ServiceFactory.Create();
            var requestId = FunctionalTestKit.NewRequestId();
            var fixture = context.NewLoginResponse(requestId);
            fixture.Assertions[0].Attributes.Clear();

            var result = await Login(context, fixture, requestId);

            FunctionalTestKit.AssertSuccess(result);
            Assert.Equal(SamlFixtures.DefaultNameId, result.Response.UserInfo.Idnp);
            Assert.Null(result.Response.UserInfo.FirstName);
            Assert.Null(result.Response.UserInfo.BirthDate);
            Assert.Empty(result.Response.UserAttributes);
        }

        [Fact]
        public async Task GetUserData_Parallel20SameMessage_OneSucceeds_Test()
        {
            using var context = ServiceFactory.Create();
            var requestId = FunctionalTestKit.NewRequestId();
            var saml = context.SignedBase64(context.NewLoginResponse(requestId));

            var results = await Task.WhenAll(Enumerable.Range(0, 20).Select(_ => Task.Run(async () =>
            {
                using var serviceScope = context.CreateScope();
                var auth = Microsoft.Extensions.DependencyInjection.ServiceProviderServiceExtensions
                    .GetRequiredService<MPassHelperDotNet.Abstractions.Services.IAuthMPassService>(serviceScope.ServiceProvider);

                return await auth.GetUserDataFromAuthResponseAsync(
                    new GetUserDataFromAuthResponseDto { SamlResponse = saml, AuthRequestId = requestId }, TestContext.Current.CancellationToken);
            })));

            Assert.Single(results, r => r.IsSuccess);
            Assert.All(results.Where(r => !r.IsSuccess),
                r => FunctionalTestKit.AssertFailureWith(r, SamlLoadValidationMessages.SamlReplayDetected));
        }

        public static TheoryData<string> Cultures => TestCultures.All;

        public static TheoryData<string, bool> CulturesAndLayouts
        {
            get
            {
                var data = new TheoryData<string, bool>();
                foreach (var culture in new[] { TestCultures.Turkish, TestCultures.Romanian, TestCultures.English })
                {
                    data.Add(culture, false);
                    data.Add(culture, true);
                }

                return data;
            }
        }

        private static Task<RzR.ResultMessage.Abstractions.IResult<GetUserDataFromAuthResponseResultDto>> Login(
            MPassTestContext context, ResponseFixture fixture, string requestId)
            => context.Auth.GetUserDataFromAuthResponseAsync(
                new GetUserDataFromAuthResponseDto { SamlResponse = context.SignedBase64(fixture), AuthRequestId = requestId },
                TestContext.Current.CancellationToken);
    }
}
