// ***********************************************************************
//  Assembly         : RzR.Shared.eGovMD.MPassHelperDotNet
//  Author           : RzR
//  Created On       : 2026-09-24 17:04
// 
//  Last Modified By : RzR
//  Last Modified On : 2026-09-24 17:04
// ***********************************************************************
//  <copyright file="RequestBuilderMessages.cs" company="">
//   Copyright (c) RzR. All rights reserved.
//  </copyright>
// 
//  <summary>
//  </summary>
// ***********************************************************************

namespace MPassHelperDotNet.Helpers.Messages
{
    /// <summary>
    ///     Request builder messages
    /// </summary>
    internal static class RequestBuilderMessages
    {
        internal const string ErrorBuildAuthRequest = "An error occurred on generate/buid auth request!";
        internal const string ErrorBuildLogOutRequest = "An error occurred on generate/buid logout request!";
        internal const string ErrorBuildLogOutResponse = "An error occurred on generate/buid logout response!";
        internal const string RelayStateTooLong = "RelayState is too long, the maximum length is 80 bytes (UTF-8)!";
        internal const string ErrorSignRequest = "An error occurred on sign the SAML message!";
        internal const string LanguageNotSupported = "Language is not supported, the allowed values are: {0}!";
    }
}
