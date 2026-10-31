// ***********************************************************************
//  Assembly         : RzR.Shared.eGovMD.MPassHelperDotNet
//  Author           : RzR
//  Created On       : 2026-09-22 13:40
// 
//  Last Modified By : RzR
//  Last Modified On : 2026-09-22 13:40
// ***********************************************************************
//  <copyright file="SamlLoadValidationMessages.cs" company="">
//   Copyright (c) RzR. All rights reserved.
//  </copyright>
// 
//  <summary>
//  </summary>
// ***********************************************************************

namespace MPassHelperDotNet.Helpers.Messages
{
    /// <summary>
    ///     SAML load and validation messages
    /// </summary>
    internal static class SamlLoadValidationMessages
    {
        internal const string ErrorOnValidateSamlSignature = "An error occurred on try to verify SAML";
        internal const string InvalidSamlResponse = "Invalid SAML response!";
        internal const string InvalidSamlResponseSignature = "Invalid SAML Response signature!";
        internal const string InvalidSamlResponseIsExpired = "Invalid SAML Response, current response is expired!";
        internal const string InvalidSamlResponseNotForService = "Invalid SAML Response, current response is not for this Service!";
        internal const string InvalidSamlResponseNotExpected = "Invalid SAML Response, current response not expected (Different SAML reference id)! Auth is not for this service!";
        internal const string InvalidSamlResponseMissingStatusCodeValue = "Invalid SAML Response, current response does not contain a StatusCode Value!";
        internal const string InvalidSamlResponseUnknownPrincipal = "Invalid SAML Response, unknown principal!";
        internal const string InvalidSamlResponseNoPassive = "Passive authentication is not possible, the user is not signed in at MPass!";
        internal const string InvalidSamlResponseStatusCode = "Received failed SAML Response, status code: '{0}', status message: '{1}'!";
        internal const string InvalidErrorOnLoadAndValidationLoginSaml = "An error occurred on try to load and validate SAML login!";
        internal const string InvalidErrorOnLoadAndValidationLogoutResponseSaml = "An error occurred on try to load and validate SAML logout response!";
        internal const string InvalidErrorOnLoadAndValidationLogoutRequestSaml = "An error occurred on try to load and validate SAML logout request!";
        internal const string SamlNotContainsAssertion = "SAML Response does not contain an Assertion!";
        internal const string SamlNotFotThisService = "The SAML Assertion is not for this Service!";
        internal const string SamlAssertionAuthStatementNotContainsSessionIndex = "The SAML Assertion AuthStatement does not contain a SessionIndex!";
        internal const string SamlNoSubjectInAssertion = "No Subject found in SAML Assertion!";
        internal const string SamlNotOnOrAfter = "Expired SAML Assertion!";
        internal const string SamlNotSubjectInAssertion = "No Subject/NameID found in SAML Assertion!";
        internal const string SamlNoSubjectConfirmationInAssertion = "No Subject/SubjectConfirmation/SubjectConfirmationData found in SAML Assertion!";
        internal const string SamlLogOutRequestInvalidSignature = "SAML LogoutRequest signature invalid!";
        internal const string SamlLogOutRequestExpired = "SAML LogoutRequest is expired!";
        internal const string SamlLogOutRequestNotForThisService = "SAML LogoutRequest is not for this Service!";
        internal const string SamlLogOutRequestIsForDifferentUser = "The SAML LogoutRequest received is for a different user!";
        internal const string SamlLogOutRequestIsNoExceptedInUserSession = "The SAML LogoutRequest is not expected in this user session!";
        internal const string SamlLogOutRequestIsNoId = "The SAML LogoutRequest does not have an ID!";
        internal const string SamlRootTypeInvalid = "Invalid SAML message, unexpected root element!";
        internal const string SamlRootIdMissing = "Invalid SAML message, the root element does not have an ID!";
        internal const string SamlSignatureStructureInvalid = "Invalid SAML message, the signature structure is not valid!";
        internal const string SamlSignatureAlgorithmNotAllowed = "Invalid SAML message, the signature algorithm is not allowed!";
        internal const string SamlCanonicalizationNotAllowed = "Invalid SAML message, the canonicalization or transform algorithm is not allowed!";
        internal const string SamlDuplicateId = "Invalid SAML message, duplicate element ID!";
        internal const string SamlAssertionCountInvalid = "Invalid SAML Response, exactly one Assertion is required!";
        internal const string SamlEncryptedAssertionNotSupported = "Invalid SAML Response, encrypted assertions are not supported!";
        internal const string SamlIssuerInvalid = "Invalid SAML message, the issuer is missing or not expected!";
        internal const string SamlConditionsInvalid = "Invalid SAML Assertion, the conditions are not valid!";
        internal const string SamlBearerConfirmationMissing = "Invalid SAML Assertion, no bearer subject confirmation found!";
        internal const string SamlSubjectConfirmationInvalid = "Invalid SAML Assertion, the subject confirmation is not valid!";
        internal const string SamlInResponseToInvalid = "Invalid SAML message, InResponseTo does not match the expected request id!";
        internal const string SamlDateInvalid = "Invalid SAML message, a date value is missing or not valid!";
        internal const string SamlMessageTooLarge = "Invalid SAML message, the message is too large!";
        internal const string SamlMessageEncodingInvalid = "Invalid SAML message, the message encoding is not valid!";
        internal const string SamlXmlInvalid = "Invalid SAML message, the XML is not valid!";
        internal const string SamlProcessingInstructionNotAllowed = "Invalid SAML message, processing instructions are not allowed!";
        internal const string SamlReplayDetected = "Invalid SAML message, the message was already processed!";
        internal const string SamlLogOutExpectationRequired = "The expected user identifier and session index are required to validate a SAML LogoutRequest!";
        internal const string SamlLogOutNameIdInvalid = "The SAML LogoutRequest must contain exactly one NameID!";
    }
}
