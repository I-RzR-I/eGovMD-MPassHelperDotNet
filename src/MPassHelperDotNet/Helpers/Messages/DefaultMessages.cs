// ***********************************************************************
//  Assembly         : RzR.Shared.eGovMD.MPassHelperDotNet
//  Author           : RzR
//  Created On       : 2023-06-13 20:41
// 
//  Last Modified By : RzR
//  Last Modified On : 2026-09-24 15:16
// ***********************************************************************
//  <copyright file="DefaultMessages.cs" company="">
//   Copyright (c) RzR. All rights reserved.
//  </copyright>
// 
//  <summary>
//  </summary>
// ***********************************************************************

// ReSharper disable ClassNeverInstantiated.Global

namespace MPassHelperDotNet.Helpers.Messages
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
        internal const string ExpectedRequestIdRequired = "The expected SAML request id is required!";
        internal const string PingCommunicationProblem = "Communication problem";
    }
}