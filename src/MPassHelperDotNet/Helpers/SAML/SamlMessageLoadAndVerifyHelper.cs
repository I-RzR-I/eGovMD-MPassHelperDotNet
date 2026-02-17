// ***********************************************************************
//  Assembly         : RzR.Shared.eGovMD.MPassHelperDotNet
//  Author           : RzR
//  Created On       : 2023-06-17 21:35
// 
//  Last Modified By : RzR
//  Last Modified On : 2023-06-28 16:26
// ***********************************************************************
//  <copyright file="SamlMessageLoadAndVerifyHelper.cs" company="">
//   Copyright (c) RzR. All rights reserved.
//  </copyright>
// 
//  <summary>
//  </summary>
// ***********************************************************************

#region U S A G E S

using System;
using System.Collections.Generic;
using System.Linq;
using System.Security.Cryptography.X509Certificates;
using System.Security.Cryptography.Xml;
using System.Xml;
using AggregatedGenericResultMessage;
using AggregatedGenericResultMessage.Abstractions;
using AggregatedGenericResultMessage.Extensions.Result;
using DomainCommonExtensions.CommonExtensions;
using DomainCommonExtensions.DataTypeExtensions;
using MPassHelperDotNet.Extensions.SAML;
using MPassHelperDotNet.Models.Internal.Request;
using MPassHelperDotNet.Models.Internal.Result;

// ReSharper disable PossibleNullReferenceException
// ReSharper disable RedundantArgumentDefaultValue

#endregion

namespace MPassHelperDotNet.Helpers.SAML
{
    /// <summary>
    ///     SAML message load and verify it helper
    /// </summary>
    internal static class SamlMessageLoadAndVerifyHelper
    {
        /// <summary>
        ///     Load and verify LOGIN response
        /// </summary>
        /// <param name="request">Input validation params</param>
        /// <returns></returns>
        /// <remarks></remarks>
        internal static IResult<LoadAndVerifyLoginResponseResult> LoadAndVerifyLoginResponse(LoadAndVerifyLoginResponseRequest request)
        {
            try
            {
                var validationResult = new LoadAndVerifyLoginResponseResult { Attributes = new Dictionary<string, IList<string>>() };
                var generalValidation = LoadAndVerifyAnyResponse(new LoadAndVerifySamlAnyResponseRequest
                {
                    TimeOut = request.TimeOut,
                    ExpectedDestination = request.ExpectedDestination,
                    ExpectedRequestId = request.ExpectedRequestId,
                    IdpCertificate = request.IdpCertificate,
                    SamlResponse = request.SamlResponse,
                    ValidStatusCodes = new[] { DefaultStaticInfo.SamlUrnStatusSuccess }
                });
                if (!generalValidation.IsSuccess)
                    return new Result<LoadAndVerifyLoginResponseResult> { IsSuccess = false, Response = null, Messages = generalValidation.Messages };

                // get to Assertion
                var assertionNode = generalValidation.Response.XmlDocument.SelectSingleNode("/saml2p:Response/saml2:Assertion", generalValidation.Response.NamespaceManager);
                if (assertionNode.IsNull())
                    return Result<LoadAndVerifyLoginResponseResult>.Failure(DefaultMessages.SamlLoadValidation.SamlNotContainsAssertion);

                // verify Audience
                var audienceNode = assertionNode?
                    .SelectSingleNode("saml2:Conditions/saml2:AudienceRestriction/saml2:Audience", generalValidation.Response.NamespaceManager);
                if (audienceNode.IsNull() || audienceNode?.InnerText != request.ExpectedAudience)
                    return Result<LoadAndVerifyLoginResponseResult>.Failure(DefaultMessages.SamlLoadValidation.SamlNotFotThisService);

                // get SessionIndex
                var sessionIndexAttribute = assertionNode?
                    .SelectSingleNode("saml2:AuthnStatement/@SessionIndex", generalValidation.Response.NamespaceManager);
                // ReSharper disable once PossibleNullReferenceException
                if (sessionIndexAttribute.IsNull() || sessionIndexAttribute.Value.IsNullOrEmpty())
                    return Result<LoadAndVerifyLoginResponseResult>.Failure(DefaultMessages.SamlLoadValidation.SamlAssertionAuthStatementNotContainsSessionIndex);
                validationResult.SessionIndex = sessionIndexAttribute.Value;

                // get to Subject
                var subjectNode = assertionNode?.SelectSingleNode("saml2:Subject", generalValidation.Response.NamespaceManager);
                if (subjectNode.IsNull())
                    return Result<LoadAndVerifyLoginResponseResult>.Failure(DefaultMessages.SamlLoadValidation.SamlNoSubjectInAssertion);

                // verify SubjectConfirmationData, according to [SAMLProf, 4.1.4.3]
                if (!(subjectNode?.SelectSingleNode("saml2:SubjectConfirmation/saml2:SubjectConfirmationData",
                    generalValidation.Response.NamespaceManager) is XmlElement subjectConfirmationDataNode))
                    return Result<LoadAndVerifyLoginResponseResult>.Failure(DefaultMessages.SamlLoadValidation.SamlNoSubjectConfirmationInAssertion);

                if (!subjectConfirmationDataNode.GetAttribute("Recipient")
                    .Equals(request.ExpectedDestination, StringComparison.CurrentCultureIgnoreCase))
                    return Result<LoadAndVerifyLoginResponseResult>.Failure(DefaultMessages.SamlLoadValidation.InvalidSamlResponseNotForService);

                if (!subjectConfirmationDataNode.HasAttribute("NotOnOrAfter") ||
                    XmlConvert.ToDateTime(subjectConfirmationDataNode.GetAttribute("NotOnOrAfter"),
                        XmlDateTimeSerializationMode.Utc) < DateTime.UtcNow)
                    return Result<LoadAndVerifyLoginResponseResult>.Failure(DefaultMessages.SamlLoadValidation.SamlNotOnOrAfter);

                // get NameID, which is normally an user identifier code
                var nameIdNode = subjectNode.SelectSingleNode("saml2:NameID", generalValidation.Response.NamespaceManager);
                // ReSharper disable once PossibleNullReferenceException
                if (nameIdNode.IsNull() || nameIdNode.InnerText.IsNullOrEmpty())
                    return Result<LoadAndVerifyLoginResponseResult>.Failure(DefaultMessages.SamlLoadValidation.SamlNotSubjectInAssertion);
                validationResult.NameId = nameIdNode.InnerText;

                // get attributes
                if (!generalValidation.Response.NamespaceManager.IsNull())
                {
                    // ReSharper disable once PossibleNullReferenceException
                    foreach (XmlElement attributeElement in assertionNode.SelectNodes(
                                 "saml2:AttributeStatement/saml2:Attribute", generalValidation.Response.NamespaceManager))
                    {
                        var attributeName = attributeElement.GetAttribute("Name");
                        var attributeValues =
                            (attributeElement.SelectNodes("saml2:AttributeValue", generalValidation.Response.NamespaceManager) ?? throw new InvalidOperationException())
                            .Cast<XmlElement>()
                            .Select(attributeValueElement => attributeValueElement.InnerXml).ToList();
                        validationResult.Attributes.Add(attributeName, attributeValues);
                    }
                }

                return Result<LoadAndVerifyLoginResponseResult>.Success(validationResult);
            }
            catch (Exception e)
            {
                return Result<LoadAndVerifyLoginResponseResult>
                    .Failure(DefaultMessages.SamlLoadValidation.InvalidErrorOnLoadAndValidationLoginSaml)
                    .WithError(e);
            }
        }

        /// <summary>
        ///     Load and verify  LOGOUT request
        /// </summary>
        /// <param name="request">Input validation params</param>
        /// <returns></returns>
        internal static IResult<LoadAndVerifyLogoutRequestResult> LoadAndVerifyLogoutRequest(LoadAndVerifyLogoutRequestRequest request)
        {
            try
            {
                var xmlDocument = new XmlDocument();
                xmlDocument.LoadXml(request.SamlRequest.Base64Decode());

                // verify Signature
                var signatureValidation = VerifySignature(xmlDocument, request.IdpCertificate);
                if (!signatureValidation.IsSuccess || !signatureValidation.Response)
                    return Result<LoadAndVerifyLogoutRequestResult>.Failure(DefaultMessages.SamlLoadValidation.SamlLogOutRequestInvalidSignature);

                var xmlNamespaceManager = xmlDocument.ToResponseSamlNsManager();

                // verify IssueInstant
                var issueInstantAttribute = xmlDocument.SelectSingleNode("/saml2p:LogoutRequest/@IssueInstant", xmlNamespaceManager);
                if (issueInstantAttribute.IsNull() ||
                    (DateTime.UtcNow -
                     XmlConvert.ToDateTime(issueInstantAttribute?.Value!, XmlDateTimeSerializationMode.Utc)).Duration() >
                    request.TimeOut)
                    return Result<LoadAndVerifyLogoutRequestResult>.Failure(DefaultMessages.SamlLoadValidation.SamlLogOutRequestExpired);

                // verify Destination, according to [SAMLBind, 3.5.5.2]
                var requestDestination = xmlDocument.SelectSingleNode("/saml2p:LogoutRequest/@Destination", xmlNamespaceManager);
                if (requestDestination.IsNull() ||
                    !requestDestination.Value!.Equals(request.ExpectedDestination, StringComparison.CurrentCultureIgnoreCase))
                    return Result<LoadAndVerifyLogoutRequestResult>.Failure(DefaultMessages.SamlLoadValidation.SamlLogOutRequestNotForThisService);

                // verify NameID
                var nameIdElement = xmlDocument.SelectSingleNode("/saml2p:LogoutRequest/saml2:NameID", xmlNamespaceManager);
                if (nameIdElement.IsNull() || (request.ExpectedNameId != null &&
                                               !nameIdElement.InnerText.Equals(request.ExpectedNameId, StringComparison.CurrentCultureIgnoreCase)))
                    return Result<LoadAndVerifyLogoutRequestResult>.Failure(DefaultMessages.SamlLoadValidation.SamlLogOutRequestIsForDifferentUser);

                // verify SessionIndex
                var sessionIndexElement = xmlDocument.SelectSingleNode("/saml2p:LogoutRequest/saml2p:SessionIndex", xmlNamespaceManager);
                if (sessionIndexElement.IsNull() || (request.ExpectedSessionIndex != null &&
                                                     // ReSharper disable once PossibleNullReferenceException
                                                     !sessionIndexElement.InnerText.Equals(request.ExpectedSessionIndex, StringComparison.CurrentCultureIgnoreCase)))
                    return Result<LoadAndVerifyLogoutRequestResult>.Failure(DefaultMessages.SamlLoadValidation.SamlLogOutRequestIsNoExceptedInUserSession);

                // get LogoutRequest ID
                var logoutRequestIdAttribute = xmlDocument.SelectSingleNode("/saml2p:LogoutRequest/@ID", xmlNamespaceManager);
                if (logoutRequestIdAttribute.IsNull())
                    return Result<LoadAndVerifyLogoutRequestResult>.Failure(DefaultMessages.SamlLoadValidation.SamlLogOutRequestIsNoId);

                return Result<LoadAndVerifyLogoutRequestResult>
                    .Success(new LoadAndVerifyLogoutRequestResult { XmlDocument = xmlDocument, RequestId = logoutRequestIdAttribute?.Value });
            }
            catch (Exception e)
            {
                return Result<LoadAndVerifyLogoutRequestResult>
                    .Failure(DefaultMessages.SamlLoadValidation.InvalidErrorOnLoadAndValidationLogoutRequestSaml)
                    .WithError(e);
            }
        }

        /// <summary>
        ///     Load and verify SAML LOGOUT response
        /// </summary>
        /// <param name="request">Input validation params</param>
        /// <returns></returns>
        /// <remarks></remarks>
        internal static IResult<LoadAndVerifyLogoutResponseResult> LoadAndVerifyLogoutResponse(LoadAndVerifyLogoutResponseRequest request)
        {
            try
            {
                var generalValidation = LoadAndVerifyAnyResponse(new LoadAndVerifySamlAnyResponseRequest
                {
                    TimeOut = request.TimeOut,
                    ExpectedDestination = request.ExpectedDestination,
                    ExpectedRequestId = request.ExpectedRequestId,
                    IdpCertificate = request.IdpCertificate,
                    SamlResponse = request.SamlResponse,
                    ValidStatusCodes = new[] { DefaultStaticInfo.SamlUrnStatusSuccess, DefaultStaticInfo.SamlUrnStatusPartialLogout }
                });
                if (!generalValidation.IsSuccess)
                    return new Result<LoadAndVerifyLogoutResponseResult> { IsSuccess = false, Response = null, Messages = generalValidation.Messages };

                return Result<LoadAndVerifyLogoutResponseResult>
                    .Success(new LoadAndVerifyLogoutResponseResult { XmlNamespace = generalValidation.Response.NamespaceManager });
            }
            catch (Exception e)
            {
                return Result<LoadAndVerifyLogoutResponseResult>
                    .Failure(DefaultMessages.SamlLoadValidation.InvalidErrorOnLoadAndValidationLogoutResponseSaml)
                    .WithError(e);
            }
        }

        /// <summary>
        ///     Load and verify  login or logout SAML response
        /// </summary>
        /// <param name="request">Required validation input data</param>
        /// <returns></returns>
        /// <remarks></remarks>
        private static IResult<LoadAndVerifySamlAnyResponseResult> LoadAndVerifyAnyResponse(LoadAndVerifySamlAnyResponseRequest request)
        {
            try
            {
                var xmlDocument = new XmlDocument();
                var xmlNamespace = xmlDocument.ToResponseSamlNsManager();
                xmlDocument.LoadXml(request.SamlResponse.Base64Decode());
                var responseElement = xmlDocument.DocumentElement;
                if (responseElement.IsNull())
                    return Result<LoadAndVerifySamlAnyResponseResult>
                        .Failure(DefaultMessages.SamlLoadValidation.InvalidSamlResponse);

                //verify Signature 
                var validationSignature = VerifySignature(xmlDocument, request.IdpCertificate);
                if (!validationSignature.IsSuccess)
                    return new Result<LoadAndVerifySamlAnyResponseResult> { IsSuccess = false, Messages = validationSignature.Messages };

                if (!validationSignature.Response)
                    return Result<LoadAndVerifySamlAnyResponseResult>
                        .Failure(DefaultMessages.SamlLoadValidation.InvalidSamlResponseSignature);

                // verify IssueInstant
                var issueInstant = responseElement?.GetAttribute("IssueInstant");
                if (issueInstant.IsNullOrEmpty())
                    return Result<LoadAndVerifySamlAnyResponseResult>
                        .Failure(DefaultMessages.SamlLoadValidation.InvalidSamlResponseIsExpired);

                var issuerInstantDateTime = XmlConvert.ToDateTime(issueInstant!, XmlDateTimeSerializationMode.Utc);
                if (issueInstant.IsNullOrEmpty() || (DateTime.UtcNow - issuerInstantDateTime).Duration() > request.TimeOut)
                    return Result<LoadAndVerifySamlAnyResponseResult>
                        .Failure(DefaultMessages.SamlLoadValidation.InvalidSamlResponseIsExpired);

                // verify Destination, according to [SAMLBind, 3.5.5.2]
                var responseDestination = responseElement?.GetAttribute("Destination");
                if (responseDestination.IsNull() || !responseDestination!.Equals(request.ExpectedDestination, StringComparison.CurrentCultureIgnoreCase))
                    return Result<LoadAndVerifySamlAnyResponseResult>
                        .Failure(DefaultMessages.SamlLoadValidation.InvalidSamlResponseNotForService);

                // verify InResponseTo
                if (responseElement?.GetAttribute("InResponseTo") != request.ExpectedRequestId)
                    return Result<LoadAndVerifySamlAnyResponseResult>
                        .Failure(DefaultMessages.SamlLoadValidation.InvalidSamlResponseNotExpected);

                // verify StatusCode
                var statusCodeValueAttribute = responseElement?.SelectSingleNode("saml2p:Status/saml2p:StatusCode/@Value", xmlNamespace);
                if (statusCodeValueAttribute.IsNull())
                    return Result<LoadAndVerifySamlAnyResponseResult>
                        .Failure(DefaultMessages.SamlLoadValidation.InvalidSamlResponseMissingStatusCodeValue);

                if (!request.ValidStatusCodes.Contains(statusCodeValueAttribute?.Value, StringComparer.OrdinalIgnoreCase))
                {
                    var requesterStatus = responseElement?.SelectSingleNode("saml2p:Status/saml2p:StatusCode/saml2p:StatusCode/@Value", xmlNamespace);
                    if (requesterStatus != null)
                    {
                        var status = requesterStatus.InnerText.Split(":").Last();
                        if (status.Equals("UnknownPrincipal"))
                            return Result<LoadAndVerifySamlAnyResponseResult>
                                .Failure(DefaultMessages.SamlLoadValidation.InvalidSamlResponseUnknownPrincipal);
                    }

                    var statusMessageNode = responseElement?.SelectSingleNode("saml2p:Status/saml2p:StatusMessage", xmlNamespace);
                    return Result<LoadAndVerifySamlAnyResponseResult>
                        .Failure(string.Format(DefaultMessages.SamlLoadValidation.InvalidSamlResponseStatusCode, statusCodeValueAttribute?.Value, statusMessageNode?.InnerText));
                }

                return Result<LoadAndVerifySamlAnyResponseResult>
                    .Success(new LoadAndVerifySamlAnyResponseResult { NamespaceManager = xmlNamespace, XmlDocument = xmlDocument });
            }
            catch (Exception e)
            {
                return Result<LoadAndVerifySamlAnyResponseResult>
                    .Failure(DefaultMessages.ErrorOnLoadAndVerifySamlResponse)
                    .WithError(e);
            }
        }

        /// <summary>
        ///     Verify SAML signature
        /// </summary>
        /// <param name="document">XML document</param>
        /// <param name="publicCertificate">Service public certificate</param>
        /// <returns>Return signature validation result</returns>
        /// <remarks></remarks>
        private static IResult<bool> VerifySignature(XmlDocument document, X509Certificate2 publicCertificate)
        {
            try
            {
                var signedXml = new SignedXml(document);
                if (document.DocumentElement == null)
                    return Result<bool>.Success(signedXml.CheckSignature(publicCertificate, true));

                var signatureNode = document.DocumentElement["Signature", "http://www.w3.org/2000/09/xmldsig#"];
                if (signatureNode == null)
                    return Result<bool>.Success(false);

                signedXml.LoadXml(signatureNode);

                return Result<bool>.Success(signedXml.CheckSignature(publicCertificate, true));
            }
            catch (Exception e)
            {
                return Result<bool>
                    .Failure(DefaultMessages.SamlLoadValidation.ErrorOnValidateSamlSignature)
                    .WithError(e);
            }
        }
    }
}