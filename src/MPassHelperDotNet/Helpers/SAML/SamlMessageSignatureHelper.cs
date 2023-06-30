// ***********************************************************************
//  Assembly         : RzR.Shared.eGovMD.MPassHelperDotNet
//  Author           : RzR
//  Created On       : 2023-06-15 18:53
// 
//  Last Modified By : RzR
//  Last Modified On : 2023-06-28 16:26
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
using System.Xml;
using AggregatedGenericResultMessage;
using AggregatedGenericResultMessage.Abstractions;
using AggregatedGenericResultMessage.Extensions.Result;
using DomainCommonExtensions.CommonExtensions;

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
        ///     Sign SAML string
        /// </summary>
        /// <param name="xmlSaml">SAML xml string</param>
        /// <param name="privateCertificate">Private certificate for sign</param>
        /// <returns>Return signed XML string</returns>
        internal static IResult<string> SignSaml(string xmlSaml, X509Certificate2 privateCertificate)
        {
            try
            {
                var doc = new XmlDocument();
                doc.LoadXml(xmlSaml);

                var keyInfo = new KeyInfo();
                keyInfo.AddClause(new KeyInfoX509Data(privateCertificate));

                var signedXml = new SignedXml(doc) { SigningKey = privateCertificate.PrivateKey, KeyInfo = keyInfo };
                signedXml.SignedInfo.CanonicalizationMethod = SignedXml.XmlDsigExcC14NTransformUrl;

                if (!doc.DocumentElement.IsNull())
                {
                    var messageId = doc.DocumentElement?.GetAttribute("ID");
                    var reference = new Reference("#" + messageId);
                    reference.AddTransform(new XmlDsigEnvelopedSignatureTransform());
                    signedXml.AddReference(reference);
                }

                signedXml.ComputeSignature();

                // insert after Issuer
                doc.DocumentElement?.InsertAfter(signedXml.GetXml(), doc.DocumentElement.FirstChild);

                return Result<string>.Success(doc.OuterXml);
            }
            catch (Exception e)
            {
                return Result<string>
                    .Failure(DefaultMessages.ErrorSignSamlXml)
                    .WithError(e);
            }
        }

        /// <summary>
        ///     Verify signed XML/SAML document
        /// </summary>
        /// <param name="document">XML document to be checked</param>
        /// <param name="publicCertificate">Public certificate</param>
        /// <returns></returns>
        /// <remarks>Return if is valid or not</remarks>
        internal static IResult<bool> Verify(XmlDocument document, X509Certificate2 publicCertificate)
        {
            try
            {
                var signedXml = new SignedXml(document);
                if (document.DocumentElement.IsNull())
                    return Result<bool>.Success(signedXml.CheckSignature(publicCertificate, true));

                var signatureNode = document.DocumentElement?["Signature", "http://www.w3.org/2000/09/xmldsig#"];
                if (signatureNode.IsNull())
                    return Result<bool>.Success(false);

                signedXml.LoadXml(signatureNode);

                return Result<bool>.Success(signedXml.CheckSignature(publicCertificate, true));
            }
            catch (Exception e)
            {
                return Result<bool>
                    .Failure(DefaultMessages.ErrorVerifySignedSamlXml)
                    .WithError(e);
            }
        }
    }
}