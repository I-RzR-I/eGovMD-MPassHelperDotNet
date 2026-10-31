// ***********************************************************************
//  Assembly         : RzR.Shared.eGovMD.MPassHelperDotNet
//  Author           : RzR
//  Created On       : 2023-06-15 08:25
// 
//  Last Modified By : RzR
//  Last Modified On : 2026-09-24 09:35
// ***********************************************************************
//  <copyright file="SamlMessageBuildHelper.cs" company="">
//   Copyright (c) RzR. All rights reserved.
//  </copyright>
// 
//  <summary>
//  </summary>
// ***********************************************************************

#region U S A G E S

using System;
using System.Security;
using System.Xml;
using RzR.ResultMessage;
using RzR.ResultMessage.Abstractions;
using RzR.Extensions.Domain.Text;
using MPassHelperDotNet.Helpers.Messages;

#endregion

namespace MPassHelperDotNet.Helpers.SAML
{
    /// <summary>
    ///     SAML message build helper
    /// </summary>
    internal static class SamlMessageBuildHelper
    {
        /// <summary>
        ///     Build SAML auth request.
        /// </summary>
        /// <param name="requestId">Auth request id.</param>
        /// <param name="destination">Auth destination.</param>
        /// <param name="assertionConsumerUrl">Customer URL.</param>
        /// <param name="issuer">Auth issuer.</param>
        /// <param name="issueInstantUtc">Message IssueInstant (UTC)</param>
        /// <param name="forceAuthn">Add <c>ForceAuthn="true"</c> to the request.</param>
        /// <param name="isPassive">Add <c>IsPassive="true"</c> to the request.</param>
        /// <returns>
        ///     Return build auth request as string.
        /// </returns>
        internal static IResult<string> BuildAuthStringRequest(string requestId, string destination,
            string assertionConsumerUrl, string issuer, DateTime issueInstantUtc, bool forceAuthn, bool isPassive)
        {
            if (requestId.IsNullOrEmpty())
                return Result<string>.Failure(string.Format(DefaultMessages.ArgumentNullMessage, nameof(requestId)));

            if (destination.IsNullOrEmpty())
                return Result<string>.Failure(string.Format(DefaultMessages.ArgumentNullMessage, nameof(destination)));

            if (assertionConsumerUrl.IsNullOrEmpty())
                return Result<string>.Failure(string.Format(DefaultMessages.ArgumentNullMessage, nameof(assertionConsumerUrl)));

            if (issuer.IsNullOrEmpty())
                return Result<string>.Failure(string.Format(DefaultMessages.ArgumentNullMessage, nameof(issuer)));

            try
            {
                const string template =
                    @"<saml2p:AuthnRequest ID=""{0}"" Version=""2.0"" IssueInstant=""{1}"" Destination=""{2}"" AssertionConsumerServiceURL=""{3}""{5} xmlns:saml2p=""urn:oasis:names:tc:SAML:2.0:protocol"" xmlns:saml2=""urn:oasis:names:tc:SAML:2.0:assertion"">" +
                    @"<saml2:Issuer>{4}</saml2:Issuer>" +
                    @"<saml2p:NameIDPolicy AllowCreate=""true""/>" +
                    @"</saml2p:AuthnRequest>";

                var optionalAttributes = (forceAuthn ? @" ForceAuthn=""true""" : string.Empty)
                    + (isPassive ? @" IsPassive=""true""" : string.Empty);

                return Result<string>
                    .Success(string.Format(template, EscapeXmlValue(requestId), EscapeXmlValue(FormatIssueInstant(issueInstantUtc)),
                        EscapeXmlValue(destination), EscapeXmlValue(assertionConsumerUrl), EscapeXmlValue(issuer), optionalAttributes));
            }
            catch (Exception)
            {
                return Result<string>
                    .Failure(DefaultMessages.ErrorBuildSamlAuthRequest);
            }
        }

        /// <summary>
        ///     Build SAML logout request.
        /// </summary>
        /// <param name="requestId">Logout request id.</param>
        /// <param name="destination">Logout destination.</param>
        /// <param name="issuer">Logout issuer.</param>
        /// <param name="nameId">User identifier code to logout.</param>
        /// <param name="sessionIndex">Current user session index.</param>
        /// <param name="issueInstantUtc">Message IssueInstant (UTC)</param>
        /// <returns>
        ///     Return build logout request as string.
        /// </returns>
        internal static IResult<string> BuildLogoutStringRequest(string requestId, string destination, 
            string issuer, string nameId, string sessionIndex, DateTime issueInstantUtc)
        {
            if (requestId.IsNullOrEmpty())
                return Result<string>.Failure(string.Format(DefaultMessages.ArgumentNullMessage, nameof(requestId)));

            if (destination.IsNullOrEmpty())
                return Result<string>.Failure(string.Format(DefaultMessages.ArgumentNullMessage, nameof(destination)));

            if (issuer.IsNullOrEmpty())
                return Result<string>.Failure(string.Format(DefaultMessages.ArgumentNullMessage, nameof(issuer)));

            if (nameId.IsNullOrEmpty())
                return Result<string>.Failure(string.Format(DefaultMessages.ArgumentNullMessage, nameof(nameId)));

            if (sessionIndex.IsNullOrEmpty())
                return Result<string>.Failure(string.Format(DefaultMessages.ArgumentNullMessage, nameof(sessionIndex)));
            try
            {
                const string template =
                    @"<saml2p:LogoutRequest ID=""{0}"" Version=""2.0"" IssueInstant=""{1}"" Destination=""{2}"" xmlns:saml2p=""urn:oasis:names:tc:SAML:2.0:protocol"" xmlns:saml2=""urn:oasis:names:tc:SAML:2.0:assertion"">" +
                    @"<saml2:Issuer>{3}</saml2:Issuer>" +
                    @"<saml2:NameID>{4}</saml2:NameID>" +
                    @"<saml2p:SessionIndex>{5}</saml2p:SessionIndex>" +
                    @"</saml2p:LogoutRequest>";

                return Result<string>.Success(string.Format(template, EscapeXmlValue(requestId), EscapeXmlValue(FormatIssueInstant(issueInstantUtc)),
                    EscapeXmlValue(destination), EscapeXmlValue(issuer), EscapeXmlValue(nameId), EscapeXmlValue(sessionIndex)));
            }
            catch (Exception)
            {
                return Result<string>
                    .Failure(DefaultMessages.ErrorBuildSamlLogoutRequest);
            }
        }

        /// <summary>
        ///     Build SAML logout response.
        /// </summary>
        /// <param name="responseId">Logout response id.</param>
        /// <param name="destination">Logout destination.</param>
        /// <param name="requestId">Logout response request id.</param>
        /// <param name="issuer">Logout issuer.</param>
        /// <param name="issueInstantUtc">Message IssueInstant (UTC)</param>
        /// <returns>
        ///     Return build logout response as string.
        /// </returns>
        internal static IResult<string> BuildLogoutStringResponse(string responseId, string destination, 
            string requestId, string issuer, DateTime issueInstantUtc)
        {
            if (responseId.IsNullOrEmpty())
                return Result<string>.Failure(string.Format(DefaultMessages.ArgumentNullMessage, nameof(responseId)));

            if (destination.IsNullOrEmpty())
                return Result<string>.Failure(string.Format(DefaultMessages.ArgumentNullMessage, nameof(destination)));

            if (requestId.IsNullOrEmpty())
                return Result<string>.Failure(string.Format(DefaultMessages.ArgumentNullMessage, nameof(requestId)));

            if (issuer.IsNullOrEmpty())
                return Result<string>.Failure(string.Format(DefaultMessages.ArgumentNullMessage, nameof(issuer)));

            try
            {
                const string template =
                    @"<saml2p:LogoutResponse ID=""{0}"" Version=""2.0"" IssueInstant=""{1}"" Destination=""{2}"" InResponseTo=""{3}"" xmlns:saml2p=""urn:oasis:names:tc:SAML:2.0:protocol"" xmlns:saml2=""urn:oasis:names:tc:SAML:2.0:assertion"">" +
                    @"<saml2:Issuer>{4}</saml2:Issuer>" +
                    @"<saml2p:Status>" +
                    @"<saml2p:StatusCode Value=""" + DefaultStaticInfo.SamlUrnStatusSuccess + @"""/>" +
                    @"</saml2p:Status>" +
                    @"</saml2p:LogoutResponse>";

                return Result<string>.Success(string.Format(template, EscapeXmlValue(responseId), EscapeXmlValue(FormatIssueInstant(issueInstantUtc)),
                    EscapeXmlValue(destination), EscapeXmlValue(requestId), EscapeXmlValue(issuer)));
            }
            catch (Exception)
            {
                return Result<string>
                    .Failure(DefaultMessages.ErrorBuildSamlLogoutResponse);
            }
        }

        /// <summary>
        ///     Escape a value for use inside an XML attribute value or element text of the message
        ///     templates.
        /// </summary>
        /// <exception cref="XmlException">
        ///     The value contains characters that are not allowed in XML.
        /// </exception>
        /// <param name="value">Raw value.</param>
        /// <returns>
        ///     Return the value with the XML markup characters (&amp; &lt; &gt; &quot; &apos;) escaped.
        /// </returns>
        private static string EscapeXmlValue(string value)
            => SecurityElement.Escape(XmlConvert.VerifyXmlChars(value));

        /// <summary>
        ///     Format the message IssueInstant as an xs:dateTime in UTC ('Z')
        /// </summary>
        /// <param name="issueInstantUtc">Message IssueInstant (UTC)</param>
        /// <returns>
        ///     Return the formatted IssueInstant.
        /// </returns>
        private static string FormatIssueInstant(DateTime issueInstantUtc)
            => XmlConvert.ToString(issueInstantUtc, XmlDateTimeSerializationMode.Utc);
    }
}