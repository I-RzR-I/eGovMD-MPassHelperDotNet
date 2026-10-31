// ***********************************************************************
//  Assembly         : RzR.Shared.eGovMD.MPassHelperDotNet
//  Author           : RzR
//  Created On       : 2023-06-15 18:53
// 
//  Last Modified By : RzR
//  Last Modified On : 2026-09-25 18:46
// ***********************************************************************
//  <copyright file="SamlMessageSignatureHelper.cs" company="">
//   Copyright (c) RzR. All rights reserved.
//  </copyright>
// 
//  <summary>
//  </summary>
// ***********************************************************************

#region U S A G E S

using System;
using System.Security.Cryptography.X509Certificates;
using System.Security.Cryptography.Xml;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Logging.Abstractions;
using RzR.ResultMessage;
using RzR.ResultMessage.Abstractions;
using RzR.Extensions.Domain.Primitives;
using RzR.Extensions.Domain.Text;
using MPassHelperDotNet.Helpers.Logging;
using MPassHelperDotNet.Helpers.Messages;

// ReSharper disable RedundantArgumentDefaultValue

#endregion

namespace MPassHelperDotNet.Helpers.SAML
{
    /// <summary>
    ///     SAML message signature helper
    /// </summary>
    internal static class SamlMessageSignatureHelper
    {
        /// <summary>
        ///     Sign SAML string.
        /// </summary>
        /// <param name="xmlSaml">SAML xml string.</param>
        /// <param name="privateCertificate">Private certificate for sign.</param>
        /// <param name="logger">
        ///     (Optional) Optional. Logger for caught exceptions. The default value is null (no logging).
        /// </param>
        /// <returns>
        ///     Return signed XML string.
        /// </returns>
        internal static IResult<string> SignSaml(string xmlSaml, X509Certificate2 privateCertificate, ILogger logger = null)
        {
            logger ??= NullLogger.Instance;

            if (xmlSaml.IsNullOrEmpty())
            {
                return Result<string>
                    .Failure(string.Format(DefaultMessages.ArgumentNullMessage, nameof(xmlSaml)));
            }

            if (privateCertificate.IsNull())
            {
                return Result<string>
                    .Failure(string.Format(DefaultMessages.ArgumentNullMessage, nameof(privateCertificate)));
            }

            try
            {
                var loadDocument = SamlXmlLoadHelper.LoadFromXmlString(xmlSaml, logger);
                if (loadDocument.IsFailure)
                {
                    return Result<string>.Failure(DefaultMessages.ErrorSignSamlXml);
                }

                var doc = loadDocument.Response;
                var messageId = doc.DocumentElement?.GetAttribute("ID");
                if (messageId.IsNullOrEmpty())
                {
                    return Result<string>.Failure(DefaultMessages.ErrorSignSamlXml);
                }

                using (var signingKey = privateCertificate.GetRSAPrivateKey())
                {
                    if (signingKey.IsNull())
                        return Result<string>.Failure(DefaultMessages.ErrorSignSamlXml);

                    var keyInfo = new KeyInfo();
                    keyInfo.AddClause(new KeyInfoX509Data(privateCertificate, X509IncludeOption.EndCertOnly));

                    var signedXml = new SignedXml(doc)
                    {
                        SigningKey = signingKey,
                        KeyInfo = keyInfo
                    };

                    signedXml.SignedInfo!.CanonicalizationMethod = SignedXml.XmlDsigExcC14NTransformUrl;
                    signedXml.SignedInfo.SignatureMethod = SignedXml.XmlDsigRSASHA256Url;

                    var reference = new Reference("#" + messageId) { DigestMethod = SignedXml.XmlDsigSHA256Url };
                    reference.AddTransform(new XmlDsigEnvelopedSignatureTransform());
                    reference.AddTransform(new XmlDsigExcC14NTransform());
                    signedXml.AddReference(reference);

                    signedXml.ComputeSignature();

                    // insert after Issuer
                    doc.DocumentElement!.InsertAfter(signedXml.GetXml(), doc.DocumentElement.FirstChild);
                }

                return Result<string>
                    .Success(doc.OuterXml);
            }
            catch (Exception e)
            {
                ExceptionLogHelper.LogCaughtException(logger, e, nameof(SignSaml));

                return Result<string>
                    .Failure(DefaultMessages.ErrorSignSamlXml);
            }
        }
    }
}