// ***********************************************************************
//  Assembly         : RzR.Shared.eGovMD.MPassHelperDotNet
//  Author           : RzR
//  Created On       : 2023-06-17 21:35
// 
//  Last Modified By : RzR
//  Last Modified On : 2026-09-25 18:20
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
using System.Globalization;
using System.Linq;
using System.Security.Cryptography.X509Certificates;
using System.Security.Cryptography.Xml;
using System.Text;
using System.Xml;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Logging.Abstractions;
using RzR.ResultMessage;
using RzR.ResultMessage.Abstractions;
using RzR.ResultMessage.Extensions.Result;
using RzR.ResultMessage.Extensions.Result.Messages;
using RzR.Extensions.Domain.Primitives;
using RzR.Extensions.Domain.Text;
using MPassHelperDotNet.Configurations.Certificate;
using MPassHelperDotNet.Extensions.SAML;
using MPassHelperDotNet.Helpers.Logging;
using MPassHelperDotNet.Models.Internal.Request;
using MPassHelperDotNet.Models.Internal.Result;
using MPassHelperDotNet.Helpers.Messages;

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
        ///     (Immutable)
        ///     Markup characters removed from an identity provider status text.
        /// </summary>
        private const string StatusTextRemovedCharacters = "<>&\"'";

        /// <summary>
        ///     (Immutable)
        ///     Accepted xs:dateTime form: optional fractional seconds, optional time zone (Z or an
        ///     offset)
        /// </summary>
        private static readonly string[] XmlDateTimeFormats = { "yyyy'-'MM'-'dd'T'HH':'mm':'ss.FFFFFFFK" };

        /// <summary>
        ///     Load and verify LOGIN response.
        /// </summary>
        /// <exception cref="InvalidOperationException">
        ///     Thrown when the requested operation is invalid.
        /// </exception>
        /// <param name="request">Input validation params.</param>
        /// <returns>
        ///     The verify login response.
        /// </returns>
        internal static IResult<LoadAndVerifyLoginResponseResult> LoadAndVerifyLoginResponse(LoadAndVerifyLoginResponseRequest request)
        {
            try
            {
                var validationResult = new LoadAndVerifyLoginResponseResult
                {
                    Attributes = new Dictionary<string, IList<string>>()
                };
                var generalValidation = LoadAndVerifyAnyResponse(new LoadAndVerifySamlAnyResponseRequest
                {
                    TimeOut = request.TimeOut,
                    ExpectedDestination = request.ExpectedDestination,
                    ExpectedRequestId = request.ExpectedRequestId,
                    IdpCertificates = GetCandidateCertificates(request.IdpCertificates, request.IdpCertificate),
                    SamlResponse = request.SamlResponse,
                    ValidStatusCodes = new[] { DefaultStaticInfo.SamlUrnStatusSuccess },
                    ExpectedRootLocalName = "Response",
                    ExpectedIssuer = request.ExpectedIssuer,
                    ClockSkew = request.ClockSkew,
                    CurrentUtc = request.CurrentUtc,
                    AllowSha1Signatures = request.AllowSha1Signatures,
                    MaxMessageLength = request.MaxMessageLength,
                    Logger = request.Logger
                });
                if (generalValidation.IsFailure)
                {
                    return new Result<LoadAndVerifyLoginResponseResult>
                    {
                        IsSuccess = false, 
                        Response = null, 
                        Messages = generalValidation.Messages
                    };
                }

                var xmlDocument = generalValidation.Response.XmlDocument;
                var responseElement = xmlDocument.DocumentElement;
                var currentUtc = ToUtcInstant(request.CurrentUtc);
                var clockSkew = request.ClockSkew;

                // EncryptedAssertion is not supported, wherever it is placed
                if (xmlDocument.GetElementsByTagName("EncryptedAssertion", DefaultStaticInfo.UrnSaml2Assertion).Count != 0)
                    return Result<LoadAndVerifyLoginResponseResult>.Failure(SamlLoadValidationMessages.SamlEncryptedAssertionNotSupported);

                // get to Assertion: exactly one, as a direct child of the signed root, and no other Assertion anywhere
                var assertionNodes = GetChildElements(responseElement, "Assertion", DefaultStaticInfo.UrnSaml2Assertion);
                if (assertionNodes.Count.IsZero())
                {
                    return Result<LoadAndVerifyLoginResponseResult>.
                        Failure(SamlLoadValidationMessages.SamlNotContainsAssertion);
                }

                // the direct children are part of the document-wide count, so one count covers both rules
                if (xmlDocument.GetElementsByTagName("Assertion", DefaultStaticInfo.UrnSaml2Assertion).Count != 1)
                {
                    return Result<LoadAndVerifyLoginResponseResult>
                        .Failure(SamlLoadValidationMessages.SamlAssertionCountInvalid);
                }

                var assertionNode = assertionNodes[0];
                var assertionId = assertionNode.GetAttribute("ID");
                if (assertionId.IsNullOrEmpty())
                {
                    return Result<LoadAndVerifyLoginResponseResult>
                        .Failure(SamlLoadValidationMessages.InvalidSamlResponse);
                }

                // verify Assertion Issuer
                if (IsIssuerValid(assertionNode, request.ExpectedIssuer).IsFalse())
                {
                    return Result<LoadAndVerifyLoginResponseResult>
                        .Failure(SamlLoadValidationMessages.SamlIssuerInvalid);
                }

                // verify Conditions
                var conditionsNode = GetSingleChildElement(assertionNode, "Conditions", DefaultStaticInfo.UrnSaml2Assertion);
                if (conditionsNode.IsNull())
                {
                    return Result<LoadAndVerifyLoginResponseResult>
                        .Failure(SamlLoadValidationMessages.SamlConditionsInvalid);
                }

                if (conditionsNode.HasAttribute("NotBefore"))
                {
                    if (TryReadUtcInstant(conditionsNode.GetAttribute("NotBefore"), out var conditionsNotBefore).IsFalse())
                    {
                        return Result<LoadAndVerifyLoginResponseResult>
                            .Failure(SamlLoadValidationMessages.SamlDateInvalid);
                    }

                    if (conditionsNotBefore - currentUtc > clockSkew)
                    {
                        return Result<LoadAndVerifyLoginResponseResult>
                            .Failure(SamlLoadValidationMessages.SamlConditionsInvalid);
                    }
                }

                if (conditionsNode.HasAttribute("NotOnOrAfter"))
                {
                    if (TryReadUtcInstant(conditionsNode.GetAttribute("NotOnOrAfter"), out var notOnOrAfter).IsFalse())
                    {
                        return Result<LoadAndVerifyLoginResponseResult>
                            .Failure(SamlLoadValidationMessages.SamlDateInvalid);
                    }

                    if (IsBeforeNotOnOrAfter(currentUtc, notOnOrAfter, clockSkew).IsFalse())
                    {
                        return Result<LoadAndVerifyLoginResponseResult>
                            .Failure(SamlLoadValidationMessages.SamlNotOnOrAfter);
                    }
                }

                // verify Audience: at least one AudienceRestriction, and every AudienceRestriction must contain this service
                var audienceRestrictionNodes = GetChildElements(conditionsNode, "AudienceRestriction", DefaultStaticInfo.UrnSaml2Assertion);
                if (audienceRestrictionNodes.Count.IsZero() || request.ExpectedAudience.IsNullOrEmpty() ||
                    !audienceRestrictionNodes.All(audienceRestriction =>
                        GetChildElements(audienceRestriction, "Audience", DefaultStaticInfo.UrnSaml2Assertion)
                            .Any(audienceNode => string.Equals(audienceNode.InnerText, request.ExpectedAudience, StringComparison.Ordinal))))
                {
                    return Result<LoadAndVerifyLoginResponseResult>
                        .Failure(SamlLoadValidationMessages.SamlNotFotThisService);
                }

                // get SessionIndex
                var authnStatementNode = GetSingleChildElement(assertionNode, "AuthnStatement", DefaultStaticInfo.UrnSaml2Assertion);
                var sessionIndex = authnStatementNode?.GetAttribute("SessionIndex");
                if (authnStatementNode.IsNull() || sessionIndex.IsNullOrEmpty())
                {
                    return Result<LoadAndVerifyLoginResponseResult>
                        .Failure(SamlLoadValidationMessages.SamlAssertionAuthStatementNotContainsSessionIndex);
                }

                validationResult.SessionIndex = sessionIndex;

                if (authnStatementNode.HasAttribute("SessionNotOnOrAfter"))
                {
                    if (TryReadUtcInstant(authnStatementNode.GetAttribute("SessionNotOnOrAfter"), out var sessionNotOnOrAfter).IsFalse())
                    {
                        return Result<LoadAndVerifyLoginResponseResult>
                            .Failure(SamlLoadValidationMessages.SamlDateInvalid);
                    }

                    if (IsBeforeNotOnOrAfter(currentUtc, sessionNotOnOrAfter, clockSkew).IsFalse())
                    {
                        return Result<LoadAndVerifyLoginResponseResult>
                            .Failure(SamlLoadValidationMessages.SamlNotOnOrAfter);
                    }
                }

                var authIp = GetSingleChildElement(authnStatementNode, "SubjectLocality", DefaultStaticInfo.UrnSaml2Assertion)?.GetAttribute("Address");
                validationResult.AuthIp = authIp.IsNullOrEmpty() ? null : authIp;

                // get to Subject
                var subjectNode = GetSingleChildElement(assertionNode, "Subject", DefaultStaticInfo.UrnSaml2Assertion);
                if (subjectNode.IsNull())
                {
                    return Result<LoadAndVerifyLoginResponseResult>
                        .Failure(SamlLoadValidationMessages.SamlNoSubjectInAssertion);
                }

                // verify SubjectConfirmationData, according to [SAMLProf, 4.1.4.2 - 4.1.4.3]: at least one bearer confirmation must be valid
                var subjectConfirmationValidation = VerifyBearerSubjectConfirmation(subjectNode, request, currentUtc);
                if (subjectConfirmationValidation.IsFailure)
                {
                    return new Result<LoadAndVerifyLoginResponseResult>
                    {
                        IsSuccess = false, 
                        Response = null, 
                        Messages = subjectConfirmationValidation.Messages
                    };
                }

                // get NameID, which is normally an user identifier code
                var nameIdNode = GetSingleChildElement(subjectNode, "NameID", DefaultStaticInfo.UrnSaml2Assertion);
                if (nameIdNode.IsNull() || nameIdNode.InnerText.IsNullOrEmpty())
                {
                    return Result<LoadAndVerifyLoginResponseResult>
                        .Failure(SamlLoadValidationMessages.SamlNotSubjectInAssertion);
                }

                validationResult.NameId = nameIdNode.InnerText;

                // get attributes
                if (generalValidation.Response.NamespaceManager.IsNotNull())
                {
                    foreach (XmlElement attributeElement in assertionNode.SelectNodes(
                                 "saml2:AttributeStatement/saml2:Attribute", generalValidation.Response.NamespaceManager))
                    {
                        var attributeName = attributeElement.GetAttribute("Name");
                        
                        // InnerText: attribute values are text; markup inside a value is never returned as markup
                        var attributeValues =
                            (attributeElement.SelectNodes("saml2:AttributeValue", generalValidation.Response.NamespaceManager) ?? throw new InvalidOperationException())
                            .Cast<XmlElement>()
                            .Select(attributeValueElement => attributeValueElement.InnerText).ToList();

                        if (validationResult.Attributes.TryGetValue(attributeName, out var existingValues))
                        {
                            foreach (var attributeValue in attributeValues)
                                existingValues.Add(attributeValue);
                        }
                        else
                            validationResult.Attributes.Add(attributeName, attributeValues);
                    }
                }

                validationResult.InResponseTo = responseElement.GetAttribute("InResponseTo");
                validationResult.AssertionId = assertionId;
                validationResult.ResponseId = generalValidation.Response.ResponseId;
                validationResult.ReplayExpiresAtUtc = GetReplayExpiresAtUtc(generalValidation.Response.IssueInstantUtc, request.TimeOut, clockSkew);

                return Result<LoadAndVerifyLoginResponseResult>.Success(validationResult);
            }
            catch (Exception e)
            {
                ExceptionLogHelper.LogCaughtException(request?.Logger, e, nameof(LoadAndVerifyLoginResponse));

                return Result<LoadAndVerifyLoginResponseResult>
                    .Failure(SamlLoadValidationMessages.InvalidErrorOnLoadAndValidationLoginSaml);
            }
        }

        /// <summary>
        ///     Load and verify  LOGOUT request.
        /// </summary>
        /// <remarks>
        ///     The expected user identifier (NameID) and session index are required.
        /// </remarks>
        /// <param name="request">Input validation params.</param>
        /// <returns>
        ///     The verify logout request.
        /// </returns>
        internal static IResult<LoadAndVerifyLogoutRequestResult> LoadAndVerifyLogoutRequest(LoadAndVerifyLogoutRequestRequest request)
        {
            try
            {
                if (request.ExpectedNameId.IsNullOrEmpty() || request.ExpectedSessionIndex.IsNullOrEmpty())
                {
                    return Result<LoadAndVerifyLogoutRequestResult>
                        .Failure(SamlLoadValidationMessages.SamlLogOutExpectationRequired);
                }

                var loadResult = SamlXmlLoadHelper.LoadFromBase64(request.SamlRequest, request.MaxMessageLength, request.Logger);
                if (loadResult.IsFailure)
                {
                    return new Result<LoadAndVerifyLogoutRequestResult>
                    {
                        IsSuccess = false, 
                        Response = null, 
                        Messages = loadResult.Messages
                    };
                }
                var xmlDocument = loadResult.Response;

                // verify Signature
                var signatureValidation = VerifySignature(xmlDocument, GetCandidateCertificates(request.IdpCertificates, request.IdpCertificate),
                    "LogoutRequest", request.AllowSha1Signatures, request.Logger);
                if (signatureValidation.IsFailure|| signatureValidation.Response.IsFalse())
                {
                    return Result<LoadAndVerifyLogoutRequestResult>
                        .Failure(SamlLoadValidationMessages.SamlLogOutRequestInvalidSignature)
                        .WithMessages(signatureValidation.Messages);
                }

                // the signature check guarantees the root is a saml2p:LogoutRequest, so its attributes are read directly
                var logoutRequestElement = xmlDocument.DocumentElement;
                var currentUtc = ToUtcInstant(request.CurrentUtc);

                // verify IssueInstant: not later than now + skew, not older than timeout + skew
                var issueInstantValue = logoutRequestElement.GetAttribute("IssueInstant");
                if (issueInstantValue.IsNullOrEmpty())
                {
                    return Result<LoadAndVerifyLogoutRequestResult>
                        .Failure(SamlLoadValidationMessages.SamlLogOutRequestExpired);
                }

                if (TryReadUtcInstant(issueInstantValue, out var issueInstant).IsFalse())
                {
                    return Result<LoadAndVerifyLogoutRequestResult>
                        .Failure(SamlLoadValidationMessages.SamlDateInvalid);
                }

                if (IsIssueInstantInWindow(issueInstant, currentUtc, request.TimeOut, request.ClockSkew).IsFalse())
                {
                    return Result<LoadAndVerifyLogoutRequestResult>
                        .Failure(SamlLoadValidationMessages.SamlLogOutRequestExpired);
                }

                // verify Destination, according to [SAMLBind, 3.5.5.2]
                var requestDestination = logoutRequestElement.GetAttribute("Destination");
                if (requestDestination.IsNullOrEmpty() || request.ExpectedDestination.IsNullOrEmpty() ||
                    !requestDestination.Equals(request.ExpectedDestination, StringComparison.OrdinalIgnoreCase))
                {
                    return Result<LoadAndVerifyLogoutRequestResult>
                        .Failure(SamlLoadValidationMessages.SamlLogOutRequestNotForThisService);
                }

                // verify Issuer
                if (IsIssuerValid(logoutRequestElement, request.ExpectedIssuer).IsFalse())
                {
                    return Result<LoadAndVerifyLogoutRequestResult>
                        .Failure(SamlLoadValidationMessages.SamlIssuerInvalid);
                }

                // verify NameID: exactly one plain NameID, no encrypted or abstract identifier
                var nameIdElements = GetChildElements(logoutRequestElement, "NameID", DefaultStaticInfo.UrnSaml2Assertion);
                if (nameIdElements.Count != 1 ||
                    !GetChildElements(logoutRequestElement, "EncryptedID", DefaultStaticInfo.UrnSaml2Assertion).Count.IsZero() ||
                    !GetChildElements(logoutRequestElement, "BaseID", DefaultStaticInfo.UrnSaml2Assertion).Count.IsZero())
                {
                    return Result<LoadAndVerifyLogoutRequestResult>
                        .Failure(SamlLoadValidationMessages.SamlLogOutNameIdInvalid);
                }

                if (!string.Equals(nameIdElements[0].InnerText, request.ExpectedNameId, StringComparison.Ordinal))
                {
                    return Result<LoadAndVerifyLogoutRequestResult>
                        .Failure(SamlLoadValidationMessages.SamlLogOutRequestIsForDifferentUser);
                }

                // verify SessionIndex: any of the listed session indexes may match
                var sessionIndexElements = GetChildElements(logoutRequestElement, "SessionIndex", DefaultStaticInfo.UrnSaml2Protocol);
                if (!sessionIndexElements.Any(sessionIndexElement =>
                        string.Equals(sessionIndexElement.InnerText, request.ExpectedSessionIndex, StringComparison.Ordinal)))
                {
                    return Result<LoadAndVerifyLogoutRequestResult>
                        .Failure(SamlLoadValidationMessages.SamlLogOutRequestIsNoExceptedInUserSession);
                }

                // verify NotOnOrAfter, when present
                if (logoutRequestElement.HasAttribute("NotOnOrAfter"))
                {
                    if (TryReadUtcInstant(logoutRequestElement.GetAttribute("NotOnOrAfter"), out var notOnOrAfter).IsFalse())
                    {
                        return Result<LoadAndVerifyLogoutRequestResult>
                            .Failure(SamlLoadValidationMessages.SamlDateInvalid);
                    }

                    if (IsBeforeNotOnOrAfter(currentUtc, notOnOrAfter, request.ClockSkew).IsFalse())
                    {
                        return Result<LoadAndVerifyLogoutRequestResult>
                            .Failure(SamlLoadValidationMessages.SamlLogOutRequestExpired);
                    }
                }

                // get LogoutRequest ID
                var logoutRequestId = logoutRequestElement.GetAttribute("ID");
                if (logoutRequestId.IsNullOrEmpty())
                {
                    return Result<LoadAndVerifyLogoutRequestResult>
                        .Failure(SamlLoadValidationMessages.SamlLogOutRequestIsNoId);
                }

                return Result<LoadAndVerifyLogoutRequestResult>
                    .Success(new LoadAndVerifyLogoutRequestResult
                    {
                        XmlDocument = xmlDocument,
                        RequestId = logoutRequestId,
                        ReplayExpiresAtUtc = GetReplayExpiresAtUtc(issueInstant, request.TimeOut, request.ClockSkew)
                    });
            }
            catch (Exception e)
            {
                ExceptionLogHelper.LogCaughtException(request?.Logger, e, nameof(LoadAndVerifyLogoutRequest));

                return Result<LoadAndVerifyLogoutRequestResult>
                    .Failure(SamlLoadValidationMessages.InvalidErrorOnLoadAndValidationLogoutRequestSaml);
            }
        }

        /// <summary>
        ///     Load and verify SAML LOGOUT response.
        /// </summary>
        /// <param name="request">Input validation params.</param>
        /// <returns>
        ///     The verify logout response.
        /// </returns>
        internal static IResult<LoadAndVerifyLogoutResponseResult> LoadAndVerifyLogoutResponse(LoadAndVerifyLogoutResponseRequest request)
        {
            try
            {
                var generalValidation = LoadAndVerifyAnyResponse(new LoadAndVerifySamlAnyResponseRequest
                {
                    TimeOut = request.TimeOut,
                    ExpectedDestination = request.ExpectedDestination,
                    ExpectedRequestId = request.ExpectedRequestId,
                    IdpCertificates = GetCandidateCertificates(request.IdpCertificates, request.IdpCertificate),
                    SamlResponse = request.SamlResponse,
                    ValidStatusCodes = new[] { DefaultStaticInfo.SamlUrnStatusSuccess, DefaultStaticInfo.SamlUrnStatusPartialLogout },
                    ExpectedRootLocalName = "LogoutResponse",
                    ExpectedIssuer = request.ExpectedIssuer,
                    ClockSkew = request.ClockSkew,
                    CurrentUtc = request.CurrentUtc,
                    AllowSha1Signatures = request.AllowSha1Signatures,
                    MaxMessageLength = request.MaxMessageLength,
                    Logger = request.Logger
                });
                if (generalValidation.IsFailure)
                {
                    return new Result<LoadAndVerifyLogoutResponseResult>
                    {
                        IsSuccess = false,
                        Response = null, 
                        Messages = generalValidation.Messages
                    };
                }

                return Result<LoadAndVerifyLogoutResponseResult>
                    .Success(new LoadAndVerifyLogoutResponseResult
                    {
                        XmlNamespace = generalValidation.Response.NamespaceManager,
                        ResponseId = generalValidation.Response.ResponseId,
                        ReplayExpiresAtUtc = GetReplayExpiresAtUtc(generalValidation.Response.IssueInstantUtc, request.TimeOut, request.ClockSkew)
                    });
            }
            catch (Exception e)
            {
                ExceptionLogHelper.LogCaughtException(request?.Logger, e, nameof(LoadAndVerifyLogoutResponse));

                return Result<LoadAndVerifyLogoutResponseResult>
                    .Failure(SamlLoadValidationMessages.InvalidErrorOnLoadAndValidationLogoutResponseSaml);
            }
        }

        /// <summary>
        ///     Load and verify  login or logout SAML response.
        /// </summary>
        /// <remarks>
        ///     The status is interpreted only after the signature and the protocol checks succeed.
        /// </remarks>
        /// <param name="request">Required validation input data.</param>
        /// <returns>
        ///     The verify any response.
        /// </returns>
        private static IResult<LoadAndVerifySamlAnyResponseResult> LoadAndVerifyAnyResponse(LoadAndVerifySamlAnyResponseRequest request)
        {
            try
            {
                // an unsolicited response (no expected request id) is never accepted
                if (request.ExpectedRequestId.IsMissing())
                {
                    return Result<LoadAndVerifySamlAnyResponseResult>
                        .Failure(DefaultMessages.ExpectedRequestIdRequired);
                }

                var loadResult = SamlXmlLoadHelper.LoadFromBase64(request.SamlResponse, request.MaxMessageLength, request.Logger);
                if (loadResult.IsFailure)
                {
                    return new Result<LoadAndVerifySamlAnyResponseResult>
                    {
                        IsSuccess = false,
                        Messages = loadResult.Messages
                    };
                }

                var xmlDocument = loadResult.Response;
                var xmlNamespace = xmlDocument.ToResponseSamlNsManager();
                var responseElement = xmlDocument.DocumentElement;

                if (responseElement.IsNull())
                {
                    return Result<LoadAndVerifySamlAnyResponseResult>
                        .Failure(SamlLoadValidationMessages.InvalidSamlResponse);
                }

                //verify Signature
                var validationSignature = VerifySignature(xmlDocument, request.IdpCertificates, request.ExpectedRootLocalName,
                    request.AllowSha1Signatures, request.Logger);
                if (validationSignature.IsFailure)
                {
                    return new Result<LoadAndVerifySamlAnyResponseResult>
                    {
                        IsSuccess = false,
                        Messages = validationSignature.Messages
                    };
                }

                if (validationSignature.Response.IsFalse())
                {
                    return Result<LoadAndVerifySamlAnyResponseResult>
                        .Failure(SamlLoadValidationMessages.InvalidSamlResponseSignature)
                        .WithMessages(validationSignature.Messages);
                }

                // verify IssueInstant: not later than now + skew, not older than timeout + skew
                var issueInstant = responseElement.GetAttribute("IssueInstant");
                if (issueInstant.IsNullOrEmpty())
                {
                    return Result<LoadAndVerifySamlAnyResponseResult>
                        .Failure(SamlLoadValidationMessages.InvalidSamlResponseIsExpired);
                }

                if (TryReadUtcInstant(issueInstant, out var issueInstantUtc).IsFalse())
                {
                    return Result<LoadAndVerifySamlAnyResponseResult>
                        .Failure(SamlLoadValidationMessages.SamlDateInvalid);
                }

                if (IsIssueInstantInWindow(issueInstantUtc, ToUtcInstant(request.CurrentUtc), request.TimeOut, request.ClockSkew).IsFalse())
                {
                    return Result<LoadAndVerifySamlAnyResponseResult>
                        .Failure(SamlLoadValidationMessages.InvalidSamlResponseIsExpired);
                }

                // verify Destination, according to [SAMLBind, 3.5.5.2]
                var responseDestination = responseElement.GetAttribute("Destination");
                if (responseDestination.IsNullOrEmpty() || request.ExpectedDestination.IsNullOrEmpty() ||
                    !responseDestination.Equals(request.ExpectedDestination, StringComparison.OrdinalIgnoreCase))
                {
                    return Result<LoadAndVerifySamlAnyResponseResult>
                        .Failure(SamlLoadValidationMessages.InvalidSamlResponseNotForService);
                }

                // verify InResponseTo
                if (!string.Equals(responseElement.GetAttribute("InResponseTo"), request.ExpectedRequestId, StringComparison.Ordinal))
                {
                    return Result<LoadAndVerifySamlAnyResponseResult>
                        .Failure(SamlLoadValidationMessages.InvalidSamlResponseNotExpected);
                }

                // verify Issuer (required)
                if (IsIssuerValid(responseElement, request.ExpectedIssuer).IsFalse())
                {
                    return Result<LoadAndVerifySamlAnyResponseResult>
                        .Failure(SamlLoadValidationMessages.SamlIssuerInvalid);
                }

                // verify StatusCode
                var statusCodeValueAttribute = responseElement.SelectSingleNode("saml2p:Status/saml2p:StatusCode/@Value", xmlNamespace);
                if (statusCodeValueAttribute.IsNull())
                {
                    return Result<LoadAndVerifySamlAnyResponseResult>
                        .Failure(SamlLoadValidationMessages.InvalidSamlResponseMissingStatusCodeValue);
                }

                if (!request.ValidStatusCodes.Contains(statusCodeValueAttribute.Value, StringComparer.OrdinalIgnoreCase))
                {
                    var requesterStatus = responseElement.SelectSingleNode("saml2p:Status/saml2p:StatusCode/saml2p:StatusCode/@Value", xmlNamespace);
                    if (requesterStatus != null)
                    {
                        if (string.Equals(requesterStatus.Value, DefaultStaticInfo.SamlUrnStatusUnknownPrincipal, StringComparison.Ordinal))
                        {
                            return Result<LoadAndVerifySamlAnyResponseResult>
                                .Failure(SamlLoadValidationMessages.InvalidSamlResponseUnknownPrincipal);
                        }

                        if (string.Equals(requesterStatus.Value, DefaultStaticInfo.SamlUrnStatusAuthnFailed, StringComparison.Ordinal))
                        {
                            return Result<LoadAndVerifySamlAnyResponseResult>
                                .Failure(DefaultMessages.AuthCanceled);
                        }

                        if (string.Equals(requesterStatus.Value, DefaultStaticInfo.SamlUrnStatusNoPassive, StringComparison.Ordinal))
                        {
                            return Result<LoadAndVerifySamlAnyResponseResult>
                                .Failure(SamlLoadValidationMessages.InvalidSamlResponseNoPassive);
                        }
                    }

                    var statusMessageNode = responseElement.SelectSingleNode("saml2p:Status/saml2p:StatusMessage", xmlNamespace);
                    
                    return Result<LoadAndVerifySamlAnyResponseResult>
                        .Failure(string.Format(SamlLoadValidationMessages.InvalidSamlResponseStatusCode,
                            ToSafeStatusText(statusCodeValueAttribute.Value), ToSafeStatusText(statusMessageNode?.InnerText)));
                }

                return Result<LoadAndVerifySamlAnyResponseResult>
                    .Success(new LoadAndVerifySamlAnyResponseResult
                    {
                        NamespaceManager = xmlNamespace,
                        XmlDocument = xmlDocument,
                        ResponseId = responseElement.GetAttribute("ID"),
                        IssueInstantUtc = issueInstantUtc
                    });
            }
            catch (Exception e)
            {
                ExceptionLogHelper.LogCaughtException(request?.Logger, e, nameof(LoadAndVerifyAnyResponse));

                return Result<LoadAndVerifySamlAnyResponseResult>
                    .Failure(DefaultMessages.ErrorOnLoadAndVerifySamlResponse);
            }
        }

        /// <summary>
        ///     Verify SAML signature.
        /// </summary>
        /// <param name="document">XML document.</param>
        /// <param name="idpCertificates">
        ///     Identity provider certificates (primary and rotation); success if any one verifies.
        /// </param>
        /// <param name="expectedRootLocalName">Expected local name of the signed root element.</param>
        /// <param name="allowSha1">Allow RSA-SHA1/SHA-1 signatures.</param>
        /// <param name="logger">
        ///     (Optional) Optional. Logger for caught exceptions. The default value is null (no logging).
        /// </param>
        /// <returns>
        ///     Return signature validation result: <c>true</c> only when the root element is signed by
        ///     one of the certificates. A rejected signature is a successful result with <c>false</c>
        ///     and a message naming the reason.
        /// </returns>
        internal static IResult<bool> VerifySignature(XmlDocument document, X509Certificate2Collection idpCertificates,
            string expectedRootLocalName, bool allowSha1, ILogger logger = null)
        {
            logger ??= NullLogger.Instance;
            try
            {
                if (idpCertificates.IsNull() || idpCertificates.Count.IsZero())
                {
                    logger.LogWarning("{Operation}: no identity provider certificate is configured", nameof(VerifySignature));

                    return Result<bool>.Success(false);
                }

                var root = document?.DocumentElement;
                if (root.IsNull() ||
                    !string.Equals(root.LocalName, expectedRootLocalName, StringComparison.Ordinal) ||
                    !string.Equals(root.NamespaceURI, DefaultStaticInfo.UrnSaml2Protocol, StringComparison.Ordinal))
                {
                    return SignatureRejected(SamlLoadValidationMessages.SamlRootTypeInvalid, logger);
                }

                var rootId = root.GetAttribute("ID");
                if (rootId.IsNullOrEmpty())
                {
                    return SignatureRejected(SamlLoadValidationMessages.SamlRootIdMissing, logger);
                }

                var signatureElements = GetChildElements(root, "Signature", SignedXml.XmlDsigNamespaceUrl);
                if (signatureElements.Count != 1)
                {
                    return SignatureRejected(SamlLoadValidationMessages.SamlSignatureStructureInvalid, logger);
                }

                var signatureElement = signatureElements[0];

                if (CountIdAttributes(document, rootId) != 1)
                {
                    return SignatureRejected(SamlLoadValidationMessages.SamlDuplicateId, logger);
                }

                var allowedSignatureMethods = allowSha1
                    ? DefaultStaticInfo.AllowedSignatureMethods.Concat(DefaultStaticInfo.Sha1SignatureMethods).ToArray()
                    : DefaultStaticInfo.AllowedSignatureMethods;
                var allowedDigestMethods = allowSha1
                    ? DefaultStaticInfo.AllowedDigestMethods.Concat(DefaultStaticInfo.Sha1DigestMethods).ToArray()
                    : DefaultStaticInfo.AllowedDigestMethods;

                foreach (var publicCertificate in idpCertificates)
                {
                    // only RSA keys are accepted (HMAC and DSA are not in the algorithm allow-list)
                    if (publicCertificate.IsNull() ||
                        !string.Equals(publicCertificate.PublicKey.Oid.Value, DefaultStaticInfo.RsaPublicKeyOid, StringComparison.Ordinal))
                        continue;

                    var signedXml = new RootBoundSignedXml(document, root, rootId);
                    signedXml.LoadXml(signatureElement);
                    var signedInfo = signedXml.SignedInfo;

                    if (signedInfo.IsNull() || signedInfo.References.Count != 1 ||
                        !(signedInfo.References[0] is Reference reference) ||
                        !string.Equals(reference.Uri, "#" + rootId, StringComparison.Ordinal))
                    {
                        return SignatureRejected(SamlLoadValidationMessages.SamlSignatureStructureInvalid, logger);
                    }

                    var transformChain = reference.TransformChain;
                    var envelopedTransformCount = 0;
                    var exclusiveC14NTransformCount = 0;
                    for (var index = 0; index < transformChain.Count; index++)
                    {
                        var transformAlgorithm = transformChain[index].Algorithm;
                       
                        if (string.Equals(transformAlgorithm, SignedXml.XmlDsigEnvelopedSignatureTransformUrl, StringComparison.Ordinal))
                            envelopedTransformCount++;
                        else if (string.Equals(transformAlgorithm, SignedXml.XmlDsigExcC14NTransformUrl, StringComparison.Ordinal))
                            exclusiveC14NTransformCount++;
                        else
                            return SignatureRejected(SamlLoadValidationMessages.SamlCanonicalizationNotAllowed, logger);
                    }

                    if (transformChain.Count > 2 || envelopedTransformCount != 1 || exclusiveC14NTransformCount > 1)
                    {
                        return SignatureRejected(SamlLoadValidationMessages.SamlCanonicalizationNotAllowed, logger);
                    }

                    if (!string.Equals(signedInfo.CanonicalizationMethod, SignedXml.XmlDsigExcC14NTransformUrl, StringComparison.Ordinal))
                    {
                        return SignatureRejected(SamlLoadValidationMessages.SamlCanonicalizationNotAllowed, logger);
                    }

                    if (!allowedSignatureMethods.Contains(signedInfo.SignatureMethod, StringComparer.Ordinal) ||
                        !allowedDigestMethods.Contains(reference.DigestMethod, StringComparer.Ordinal))
                    {
                        return SignatureRejected(SamlLoadValidationMessages.SamlSignatureAlgorithmNotAllowed, logger);
                    }

                    if (signedXml.CheckSignature(publicCertificate, true))
                        return Result<bool>.Success(true);
                }

                return Result<bool>.Success(false);
            }
            catch (Exception e)
            {
                ExceptionLogHelper.LogCaughtException(logger, e, nameof(VerifySignature));

                return Result<bool>
                    .Failure(SamlLoadValidationMessages.ErrorOnValidateSamlSignature);
            }
        }

        /// <summary>
        ///     Rejected signature result: a successful result with <c>false</c> and the rejection reason.
        /// </summary>
        /// <param name="message">Rejection reason.</param>
        /// <param name="logger">Logger.</param>
        /// <returns>
        ///     Return the rejected signature result.
        /// </returns>
        private static IResult<bool> SignatureRejected(string message, ILogger logger)
        {
            logger.LogWarning("{Operation} rejected the signature: {Reason}", nameof(VerifySignature), message);

            return Result<bool>.Success(false).AddError(message);
        }

        /// <summary>
        ///     Count the ID-like attributes (local name <c>ID</c>, <c>Id</c> or <c>id</c>, any
        ///     namespace) that carry the given value, over every element of the document (including the
        ///     signature and its objects).
        /// </summary>
        /// <param name="document">XML document.</param>
        /// <param name="idValue">ID value.</param>
        /// <returns>
        ///     Return the number of attributes that carry the value.
        /// </returns>
        private static int CountIdAttributes(XmlDocument document, string idValue)
        {
            var count = 0;
            foreach (XmlElement element in document.GetElementsByTagName("*"))
            {
                foreach (XmlAttribute attribute in element.Attributes)
                {
                    if ((attribute.LocalName == "ID" || attribute.LocalName == "Id" || attribute.LocalName == "id") &&
                        string.Equals(attribute.Value, idValue, StringComparison.Ordinal))
                        count++;
                }
            }

            return count;
        }

        /// <summary>
        ///     Get the direct child elements with the given local name and namespace.
        /// </summary>
        /// <param name="parent">Parent node.</param>
        /// <param name="localName">Element local name.</param>
        /// <param name="namespaceUri">Element namespace URI.</param>
        /// <returns>
        ///     Return the matching child elements, in document order.
        /// </returns>
        private static List<XmlElement> GetChildElements(XmlNode parent, string localName, string namespaceUri)
        {
            var childElements = new List<XmlElement>();
            foreach (XmlNode childNode in parent.ChildNodes)
            {
                if (childNode is XmlElement childElement &&
                    string.Equals(childElement.LocalName, localName, StringComparison.Ordinal) &&
                    string.Equals(childElement.NamespaceURI, namespaceUri, StringComparison.Ordinal))
                    childElements.Add(childElement);
            }

            return childElements;
        }

        /// <summary>
        ///     Get the single direct child element with the given local name and namespace.
        /// </summary>
        /// <param name="parent">Parent node.</param>
        /// <param name="localName">Element local name.</param>
        /// <param name="namespaceUri">Element namespace URI.</param>
        /// <returns>
        ///     Return the child element, or null when there is none or more than one.
        /// </returns>
        private static XmlElement GetSingleChildElement(XmlNode parent, string localName, string namespaceUri)
        {
            var childElements = GetChildElements(parent, localName, namespaceUri);

            return childElements.Count == 1 
                ? childElements[0]
                : null;
        }

        /// <summary>
        ///     Get the identity provider certificates that may verify the signature: the given
        ///     collection plus the single certificate when it is set and not already in the collection
        ///     (same thumbprint).
        /// </summary>
        /// <param name="idpCertificates">Identity provider certificates (primary and rotation)</param>
        /// <param name="idpCertificate">Optional. Single identity provider certificate.</param>
        /// <returns>
        ///     Return the candidate certificates; a new collection is created only when the single
        ///     certificate is added.
        /// </returns>
        private static X509Certificate2Collection GetCandidateCertificates(X509Certificate2Collection idpCertificates,
            X509Certificate2 idpCertificate)
        {
            if (idpCertificate.IsNull() ||
                (!idpCertificates.IsNull() && CertificateLoader.ContainsThumbprint(idpCertificates, idpCertificate.Thumbprint)))
                return idpCertificates;

            var certificates = new X509Certificate2Collection();
            if (!idpCertificates.IsNull())
                certificates.AddRange(idpCertificates);
            certificates.Add(idpCertificate);

            return certificates;
        }

        /// <summary>
        ///     Verify that the message has exactly one Issuer child equal to the expected issuer
        ///     (Ordinal).
        /// </summary>
        /// <param name="parent">Message root or Assertion element.</param>
        /// <param name="expectedIssuer">Expected issuer (identity provider EntityID)</param>
        /// <returns>
        ///     Return true if the issuer is the expected one.
        /// </returns>
        private static bool IsIssuerValid(XmlNode parent, string expectedIssuer)
        {
            if (expectedIssuer.IsNullOrEmpty())
                return false;

            var issuerNode = GetSingleChildElement(parent, "Issuer", DefaultStaticInfo.UrnSaml2Assertion);

            return issuerNode.IsNotNull() && string.Equals(issuerNode.InnerText, expectedIssuer, StringComparison.Ordinal);
        }

        /// <summary>
        ///     Verify the bearer subject confirmation, according to [SAMLProf, 4.1.4.2]: at least one
        ///     confirmation with the bearer method must have exactly one SubjectConfirmationData with
        ///     the expected Recipient and InResponseTo, a valid NotOnOrAfter and no NotBefore.
        ///     Confirmations with another method are ignored.
        /// </summary>
        /// <param name="subjectNode">Assertion Subject element.</param>
        /// <param name="request">Input validation params.</param>
        /// <param name="currentUtc">Current UTC instant.</param>
        /// <returns>
        ///     Return the NotOnOrAfter of the accepted SubjectConfirmationData.
        /// </returns>
        private static IResult<DateTimeOffset?> VerifyBearerSubjectConfirmation(XmlNode subjectNode, 
            LoadAndVerifyLoginResponseRequest request, DateTimeOffset currentUtc)
        {
            // the reason of the last rejected bearer confirmation is returned when none is accepted
            var rejectionMessage = SamlLoadValidationMessages.SamlBearerConfirmationMissing;
            foreach (var subjectConfirmationNode in GetChildElements(subjectNode, "SubjectConfirmation", DefaultStaticInfo.UrnSaml2Assertion))
            {
                if (!string.Equals(subjectConfirmationNode.GetAttribute("Method"), DefaultStaticInfo.SamlBearerMethod, StringComparison.Ordinal))
                    continue;

                var subjectConfirmationDataNodes = GetChildElements(subjectConfirmationNode, "SubjectConfirmationData", DefaultStaticInfo.UrnSaml2Assertion);
                if (subjectConfirmationDataNodes.Count != 1)
                {
                    rejectionMessage = subjectConfirmationDataNodes.Count.IsZero()
                        ? SamlLoadValidationMessages.SamlNoSubjectConfirmationInAssertion
                        : SamlLoadValidationMessages.SamlSubjectConfirmationInvalid;
                    continue;
                }

                var subjectConfirmationDataNode = subjectConfirmationDataNodes[0];
                var recipient = subjectConfirmationDataNode.GetAttribute("Recipient");
                if (recipient.IsNullOrEmpty() || request.ExpectedDestination.IsNullOrEmpty() ||
                    !recipient.Equals(request.ExpectedDestination, StringComparison.OrdinalIgnoreCase))
                {
                    rejectionMessage = SamlLoadValidationMessages.InvalidSamlResponseNotForService;
                    continue;
                }

                if (subjectConfirmationDataNode.HasAttribute("NotBefore"))
                {
                    rejectionMessage = SamlLoadValidationMessages.SamlSubjectConfirmationInvalid;
                    continue;
                }

                if (subjectConfirmationDataNode.HasAttribute("NotOnOrAfter").IsFalse())
                {
                    rejectionMessage = SamlLoadValidationMessages.SamlNotOnOrAfter;
                    continue;
                }

                if (TryReadUtcInstant(subjectConfirmationDataNode.GetAttribute("NotOnOrAfter"), out var notOnOrAfter).IsFalse())
                {
                    rejectionMessage = SamlLoadValidationMessages.SamlDateInvalid;
                    continue;
                }

                if (IsBeforeNotOnOrAfter(currentUtc, notOnOrAfter, request.ClockSkew).IsFalse())
                {
                    rejectionMessage = SamlLoadValidationMessages.SamlNotOnOrAfter;
                    continue;
                }

                if (!string.Equals(subjectConfirmationDataNode.GetAttribute("InResponseTo"), request.ExpectedRequestId, StringComparison.Ordinal))
                {
                    rejectionMessage = SamlLoadValidationMessages.SamlInResponseToInvalid;
                    continue;
                }

                return Result<DateTimeOffset?>.Success(notOnOrAfter);
            }

            return Result<DateTimeOffset?>.Failure(rejectionMessage);
        }

        /// <summary>
        ///     Read a SAML date-time value (xs:dateTime) as an UTC instant.
        /// </summary>
        /// <remarks>
        ///     Only the xs:dateTime form is accepted, parsed with the invariant culture. A value without
        ///     a time zone is UTC, according to [SAMLCore, 1.3.3]. Any parse failure, including a value
        ///     outside the supported range, means the value is not valid.
        /// </remarks>
        /// <param name="value">Attribute value.</param>
        /// <param name="instant">[out] Parsed instant.</param>
        /// <returns>
        ///     Return true if the value is present and valid.
        /// </returns>
        private static bool TryReadUtcInstant(string value, out DateTimeOffset instant)
        {
            instant = default;
            if (value.IsNullOrEmpty())
                return false;

            try
            {
                instant = DateTimeOffset.ParseExact(value, XmlDateTimeFormats, CultureInfo.InvariantCulture,
                    DateTimeStyles.AssumeUniversal | DateTimeStyles.AdjustToUniversal);

                return true;
            }
            catch (Exception)
            {
                return false;
            }
        }

        /// <summary>
        ///     Convert the validation clock value to an UTC instant.
        /// </summary>
        /// <param name="currentUtc">Current UTC time.</param>
        /// <returns>
        ///     Return the UTC instant.
        /// </returns>
        private static DateTimeOffset ToUtcInstant(DateTime currentUtc)
        {
            var utcDateTime = currentUtc.Kind == DateTimeKind.Local
                ? currentUtc.ToUniversalTime()
                : DateTime.SpecifyKind(currentUtc, DateTimeKind.Utc);

            return new DateTimeOffset(utcDateTime, TimeSpan.Zero);
        }

        /// <summary>
        ///     Verify the message IssueInstant: not later than now + skew and not older than timeout +
        ///     skew.
        /// </summary>
        /// <param name="issueInstant">Message IssueInstant.</param>
        /// <param name="currentUtc">Current UTC instant.</param>
        /// <param name="timeOut">Message timeout.</param>
        /// <param name="clockSkew">Allowed clock skew.</param>
        /// <returns>
        ///     Return true if the IssueInstant is accepted.
        /// </returns>
        private static bool IsIssueInstantInWindow(DateTimeOffset issueInstant, DateTimeOffset currentUtc, TimeSpan timeOut, TimeSpan clockSkew)
            => issueInstant - currentUtc <= clockSkew && currentUtc - issueInstant <= timeOut + clockSkew;

        /// <summary>
        ///     Verify a NotOnOrAfter value: now - skew must be earlier than NotOnOrAfter.
        /// </summary>
        /// <param name="currentUtc">Current UTC instant.</param>
        /// <param name="notOnOrAfter">NotOnOrAfter value.</param>
        /// <param name="clockSkew">Allowed clock skew.</param>
        /// <returns>
        ///     Return true if the value is still valid.
        /// </returns>
        private static bool IsBeforeNotOnOrAfter(DateTimeOffset currentUtc, DateTimeOffset notOnOrAfter, TimeSpan clockSkew)
            => currentUtc - notOnOrAfter < clockSkew;

        /// <summary>
        ///     Get the instant until which the message ID must be kept by the replay cache: IssueInstant
        ///     + timeout + clock skew + max(clock skew, <see cref="DefaultStaticInfo.MinReplayCommitMargin" />).
        /// </summary>
        /// <remarks>
        ///     A message is accepted only while its root IssueInstant is at most timeout + skew in the
        ///     past, so the entry never needs to outlive that window. The extra margin covers the delay
        ///     between the verification and the replay commit. NotOnOrAfter values are not used, so a
        ///     far-future value cannot keep an entry in the cache.
        /// </remarks>
        /// <param name="issueInstant">
        ///     Message IssueInstant (already validated against the current time)
        /// </param>
        /// <param name="timeOut">Message timeout.</param>
        /// <param name="clockSkew">Allowed clock skew.</param>
        /// <returns>
        ///     Return the replay cache expiry (UTC)
        /// </returns>
        private static DateTimeOffset GetReplayExpiresAtUtc(DateTimeOffset issueInstant, TimeSpan timeOut, TimeSpan clockSkew)
        {
            var commitMargin = clockSkew > DefaultStaticInfo.MinReplayCommitMargin 
                ? clockSkew 
                : DefaultStaticInfo.MinReplayCommitMargin;
            var lifetime = timeOut + clockSkew + commitMargin;

            return issueInstant > DateTimeOffset.MaxValue - lifetime
                ? DateTimeOffset.MaxValue 
                : issueInstant + lifetime;
        }

        /// <summary>
        ///     Make an identity provider status text safe for a result message: control characters and
        ///     the markup characters <c>&lt; &gt; &amp; " '</c> removed, and the length capped.
        /// </summary>
        /// <remarks>
        ///     Result messages are untrusted plain text: a consumer must encode them before display.
        /// </remarks>
        /// <param name="statusText">Status code or status message from the identity provider.</param>
        /// <returns>
        ///     Return the safe status text.
        /// </returns>
        private static string ToSafeStatusText(string statusText)
        {
            if (statusText.IsNullOrEmpty())
                return statusText;

            var safeText = new StringBuilder(Math.Min(statusText.Length, DefaultStaticInfo.StatusMessageMaxLength));
            foreach (var character in statusText)
            {
                if (safeText.Length >= DefaultStaticInfo.StatusMessageMaxLength)
                {
                    if (char.IsHighSurrogate(safeText[safeText.Length - 1]))
                        safeText.Length--;
                    break;
                }
                if (!char.IsControl(character) && StatusTextRemovedCharacters.IndexOf(character) < 0)
                    safeText.Append(character);
            }

            return safeText.ToString();
        }
    }
}
