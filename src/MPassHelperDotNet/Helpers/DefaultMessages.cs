// ***********************************************************************
//  Assembly         : RzR.Shared.eGovMD.MPassHelperDotNet
//  Author           : RzR
//  Created On       : 2023-06-13 20:41
// 
//  Last Modified By : RzR
//  Last Modified On : 2023-06-28 16:26
// ***********************************************************************
//  <copyright file="DefaultMessages.cs" company="">
//   Copyright (c) RzR. All rights reserved.
//  </copyright>
// 
//  <summary>
//  </summary>
// ***********************************************************************

// ReSharper disable ClassNeverInstantiated.Global

namespace MPassHelperDotNet.Helpers
{
    /// <summary>
    ///     Default result message
    /// </summary>
    internal static class DefaultMessages
    {
        internal const string InvalidCertificatePathOrPassword = "Invalid service certificate path or password!";
        internal const string ErrorBuildSamlAuthRequest = "An error occurred on auth request build!";
        internal const string ErrorBuildSamlLogoutRequest = "An error occurred on logout request build!";
        internal const string ErrorBuildSamlLogoutResponse = "An error occurred on logout response build!";
        internal const string ArgumentNullMessage = "Value cannot be null. Parameter name: {0}";
        internal const string ErrorGetUserIdentifierFromSaml = "An error occurred on try to get user identifier code from SAML Request!";
        internal const string ErrorGetUserAuthDetailsFromSaml = "An error occurred on try to get user auth details from SAML Request!";
        internal const string XmlDocumentElementNull = "XML document element is null!";
        internal const string AuthCanceled = "Authentication canceled!";
        internal const string AuthFailed = "Authentication failed!";
        internal const string NoChildInSaml2Attribute = "No find any child for attribute: '{0}'!";
        internal const string ErrorSignSamlXml = "An error occurred on try to sign SAML document!";
        internal const string ErrorVerifySignedSamlXml = "An error occurred on try to verify SAML document signature!";
        internal const string ErrorOnLoadAndVerifySamlResponse = "An error occurred on try to load and verify SAML response";

        /// <summary>
        ///     SAML load and validation messages
        /// </summary>
        internal class SamlLoadValidation
        {
            internal const string ErrorOnValidateSamlSignature = "An error occurred on try to verify SAML";
            internal const string InvalidSamlResponse = "Invalid SAML response!";
            internal const string InvalidSamlResponseSignature = "Invalid SAML Response signature!";
            internal const string InvalidSamlResponseIsExpired = "Invalid SAML Response, current response is expired!";
            internal const string InvalidSamlResponseNotForService = "Invalid SAML Response, current response is not for this Service!";
            internal const string InvalidSamlResponseNotExpected = "Invalid SAML Response, current response not expected (Different SAML reference id)! Auth is not for this service!";
            internal const string InvalidSamlResponseMissingStatusCodeValue = "Invalid SAML Response, current response does not contain a StatusCode Value!";
            internal const string InvalidSamlResponseUnknownPrincipal = "Invalid SAML Response, unknown principal!";
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
        }

        /// <summary>
        ///     Request builder messages
        /// </summary>
        internal class RequestBuilder
        {
            internal const string ErrorBuildAuthRequest = "An error occurred on generate/buid auth request!";
            internal const string ErrorBuildLogOutRequest = "An error occurred on generate/buid logout request!";
            internal const string ErrorBuildLogOutResponse = "An error occurred on generate/buid logout response!";
        }

        internal class AuthData
        {
            internal const string ErrorOnGenerateAuthUserData = "An error occurred on generate auth user info!";
        }
    }
}