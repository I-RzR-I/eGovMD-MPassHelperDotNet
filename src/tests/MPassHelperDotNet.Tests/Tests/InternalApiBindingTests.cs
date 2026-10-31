using System;
using System.Collections.Generic;
using System.Security.Cryptography.X509Certificates;
using System.Xml;
using Microsoft.Extensions.Logging;
using MPassHelperDotNet.Configurations.Certificate;
using MPassHelperDotNet.Extensions;
using MPassHelperDotNet.Helpers.SAML;
using MPassHelperDotNet.Models.Dto;
using MPassHelperDotNet.Models.Internal.Result;
using RzR.ResultMessage.Abstractions;
using Xunit;

namespace MPassHelperDotNet.Tests.Tests
{
    public class InternalApiBindingTests
    {
        [Fact]
        public void InternalHelperSignatures_VisibleAndBind_Test()
        {
            Func<XmlDocument, X509Certificate2Collection, string, bool, ILogger, IResult<bool>> verifySignature =
                SamlMessageLoadAndVerifyHelper.VerifySignature;
            Func<string, int, ILogger, IResult<XmlDocument>> loadFromBase64 = SamlXmlLoadHelper.LoadFromBase64;
            Func<string, ILogger, IResult<XmlDocument>> loadFromXmlString = SamlXmlLoadHelper.LoadFromXmlString;
            Func<string, X509Certificate2, ILogger, IResult<string>> signSaml = SamlMessageSignatureHelper.SignSaml;
            Func<LoadAndVerifyLoginResponseResult, ILogger, IResult<AuthMPassUserInfo>> getAuthUserDetails =
                SamlMessageParseHelper.GetAuthUserDetails;
            Func<IEnumerable<string>, X509Certificate2Collection> loadAll = CertificateLoader.LoadAll;

            Assert.NotNull(verifySignature);
            Assert.NotNull(loadFromBase64);
            Assert.NotNull(loadFromXmlString);
            Assert.NotNull(signSaml);
            Assert.NotNull(getAuthUserDetails);
            Assert.NotNull(loadAll);
            Assert.True(((string)null).IsRelayStateWithinLimit());
        }
    }
}
