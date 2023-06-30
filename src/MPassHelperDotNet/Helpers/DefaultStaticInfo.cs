// ***********************************************************************
//  Assembly         : RzR.Shared.eGovMD.MPassHelperDotNet
//  Author           : RzR
//  Created On       : 2023-06-17 21:16
// 
//  Last Modified By : RzR
//  Last Modified On : 2023-06-28 16:26
// ***********************************************************************
//  <copyright file="DefaultStaticInfo.cs" company="">
//   Copyright (c) RzR. All rights reserved.
//  </copyright>
// 
//  <summary>
//  </summary>
// ***********************************************************************

namespace MPassHelperDotNet.Helpers
{
    /// <summary>
    ///     Internal information used to help generate data
    /// </summary>
    internal static class DefaultStaticInfo
    {
        internal const string SamlUrnStatusSuccess = "urn:oasis:names:tc:SAML:2.0:status:Success";
        internal const string SamlUrnStatusPartialLogout = "urn:oasis:names:tc:SAML:2.0:status:PartialLogout";
        internal const string UrnSaml2Protocol = "urn:oasis:names:tc:SAML:2.0:protocol";
        internal const string UrnSaml2Assertion = "urn:oasis:names:tc:SAML:2.0:assertion";

        /// <summary>
        ///     Template MPass redirect HTML
        /// </summary>
        internal const string DefaultRedirectHtml = @"
                        <!DOCTYPE html>
                        
                        <html lang='en' xmlns='http://www.w3.org/1999/xhtml'>
                        <head>
                            <meta charset='utf-8' />
                            <title>redirecting...</title>
                        </head>
                        <body onload='document.forms[0].submit();'>
                            <div>Redirecting to MPass...</div>
                            <form method='POST' action='{PostUrl}'>
                                <input type='hidden' name='{SAMLVariable}' value='{SAMLMessage}' />
                                <input type='hidden' name='RelayState' value='{RelayState}' />
                        
                                <noscript>
                                    <p>
                                        <strong>Note:</strong>
                                        Since your browser does not support Javascript, please click the Continue button once to proceed.
                                    </p>
                                    <div>
                                        <input type='submit' value='Continue' />
                                    </div>
                                </noscript>
                            </form>
                        </body>
                        </html>
                        ";
    }
}