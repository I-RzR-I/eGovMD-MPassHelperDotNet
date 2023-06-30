// ***********************************************************************
//  Assembly         : RzR.Shared.eGovMD.MPassHelperDotNet
//  Author           : RzR
//  Created On       : 2023-06-15 17:18
// 
//  Last Modified By : RzR
//  Last Modified On : 2023-06-28 16:26
// ***********************************************************************
//  <copyright file="SamlMessageParseHelper.cs" company="">
//   Copyright (c) RzR. All rights reserved.
//  </copyright>
// 
//  <summary>
//  </summary>
// ***********************************************************************

#region U S A G E S

using System;
using System.Xml;
using AggregatedGenericResultMessage;
using AggregatedGenericResultMessage.Abstractions;
using AggregatedGenericResultMessage.Extensions.Result;
using DomainCommonExtensions.CommonExtensions;
using DomainCommonExtensions.DataTypeExtensions;
using MPassHelperDotNet.Extensions.SAML;
using MPassHelperDotNet.Models.Dto;
// ReSharper disable ConstantConditionalAccessQualifier

#endregion

namespace MPassHelperDotNet.Helpers.SAML
{
    /// <summary>
    ///     SAML message parse helper
    /// </summary>
    internal static class SamlMessageParseHelper
    {
        private const string SuccessStatusCode = "urn:oasis:names:tc:SAML:2.0:status:Success";
        private const string FailedAuthStatusCode = "urn:oasis:names:tc:SAML:2.0:status:AuthnFailed";

        /// <summary>
        ///     Get user identifier code from SAML request
        /// </summary>
        /// <param name="samlRequest">SAML request</param>
        /// <returns>Return user identifier code</returns>
        /// <remarks></remarks>
        internal static IResult<string> GetUserIdentifierFromSamlRequest(string samlRequest)
        {
            if (samlRequest.IsNullOrEmpty())
                return Result<string>.Failure(string.Format(DefaultMessages.ArgumentNullMessage, nameof(samlRequest)));
            try
            {
                var xmlDocument = new XmlDocument();
                var xmlNamespaceManager = xmlDocument.ToRequestSamlNsManager();

                xmlDocument.LoadXml(samlRequest.Base64Decode());
                if (xmlDocument.DocumentElement.IsNull())
                    return null;

                var responseNode = xmlDocument.DocumentElement?.SelectSingleNode("/samlp:LogoutRequest/saml:NameID", xmlNamespaceManager);

                return Result<string>.Success(responseNode?.InnerXml);
            }
            catch (Exception e)
            {
                return Result<string>
                    .Failure(DefaultMessages.ErrorGetUserIdentifierFromSaml)
                    .WithError(e);
            }
        }

        /// <summary>
        ///     Get auth user details from XML response (SAML)
        /// </summary>
        /// <param name="xmlResponse">XML data, decoded from SAML</param>
        /// <param name="isDecoded">
        ///     Bit to check if sended/input string is decoded from SAML or not.
        ///     Default value is 'true', means it's in clear format.
        /// </param>
        /// <returns>Return parsed user auth details</returns>
        internal static IResult<AuthMPassUserInfo> GetAuthUserDetails(string xmlResponse, bool isDecoded = true)
        {
            if (xmlResponse.IsNullOrEmpty())
                return Result<AuthMPassUserInfo>.Failure(string.Format(DefaultMessages.ArgumentNullMessage, nameof(xmlResponse)));

            if (isDecoded == false)
                xmlResponse = xmlResponse.Base64Decode();
            try
            {
                var xmlDocument = new XmlDocument();
                var xmlNamespaceManager = xmlDocument.ToResponseSamlNsManager();

                xmlDocument.LoadXml(xmlResponse);
                if (xmlDocument.DocumentElement.IsNull())
                    return Result<AuthMPassUserInfo>.Failure(DefaultMessages.XmlDocumentElementNull);

                var responseNode = xmlDocument.DocumentElement?.SelectSingleNode("/saml2p:Response", xmlNamespaceManager);
                var statusNode = responseNode?.SelectSingleNode("saml2p:Status", xmlNamespaceManager);
                var statusCodeNode = statusNode?.SelectSingleNode("saml2p:StatusCode", xmlNamespaceManager);
                var statusCode = statusCodeNode?.Attributes?["Value"]?.Value;

                if (statusCode != SuccessStatusCode)
                {
                    var statusFail = statusNode?.SelectSingleNode("saml2p:StatusCode/saml2p:StatusCode", xmlNamespaceManager);
                    var statusFailCode = statusFail?.Attributes?["Value"]?.Value;

                    return Result<AuthMPassUserInfo>
                        .Failure(statusFailCode == FailedAuthStatusCode
                            ? DefaultMessages.AuthCanceled
                            : DefaultMessages.AuthFailed);
                }

                var assertionNode = responseNode.SelectSingleNode("saml2:Assertion", xmlNamespaceManager);
                var subjectNode = assertionNode?.SelectSingleNode("saml2:Subject", xmlNamespaceManager);
                //var nameIdNode = assertionNode?.SelectSingleNode("saml2:NameID", xmlNamespaceManager);
                var childNodes = assertionNode?.SelectSingleNode("saml2:AttributeStatement", xmlNamespaceManager)
                    ?.ChildNodes;

                if (childNodes.IsNull())
                    return Result<AuthMPassUserInfo>.Failure(string.Format(DefaultMessages.NoChildInSaml2Attribute, "saml2:AttributeStatement"));

                var userInfo = new AuthMPassUserInfo
                {
                    Idnp = subjectNode?.SelectSingleNode("saml2:NameID", xmlNamespaceManager)?.InnerText, 
                    RequestId = xmlDocument.DocumentElement.Attributes["InResponseTo"]?.Value
                };

                var authChildNodes = assertionNode?.SelectSingleNode("saml2:AuthnStatement", xmlNamespaceManager)
                    ?.ChildNodes;
                if (!authChildNodes.IsNull())
                    foreach (XmlNode tag in authChildNodes!)
                        if (tag.LocalName.Equals("SubjectLocality"))
                            userInfo.AuthIp = tag?.Attributes?["Address"]?.Value;

                foreach (XmlNode tag in childNodes!)
                {
                    var name = tag.Attributes?["Name"]?.Value ?? string.Empty;
                    switch (name.ToLower())
                    {
                        case "nameidentifier":
                            userInfo.NameIdentifier = tag.InnerText;
                            break;
                        case "firstname":
                            userInfo.FirstName = tag.InnerText;
                            break;
                        case "lastname":
                            userInfo.LastName = tag.InnerText;
                            break;
                        case "birthdate":
                            userInfo.BirthDate = DateTime.Parse(tag.InnerText);
                            break;
                        case "gender":
                            userInfo.Gender = tag.InnerText;
                            break;
                        case "emailaddress":
                            userInfo.Email = tag.InnerText;
                            break;
                        case "mobilephone":
                            userInfo.MobilePhoneNumber = tag.InnerText;
                            break;
                        case "phone":
                            userInfo.PhoneNumber = tag.InnerText;
                            break;
                        case "language":
                            userInfo.Language = tag.InnerText;
                            break;
                    }
                }

                return Result<AuthMPassUserInfo>.Success(userInfo);
            }
            catch (Exception e)
            {
                return Result<AuthMPassUserInfo>
                    .Failure(DefaultMessages.ErrorGetUserAuthDetailsFromSaml)
                    .WithError(e);
            }
        }
    }
}