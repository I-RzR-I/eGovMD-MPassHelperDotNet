// ***********************************************************************
//  Assembly         : RzR.Shared.eGovMD.MPassHelperDotNet
//  Author           : RzR
//  Created On       : 2023-06-15 09:09
// 
//  Last Modified By : RzR
//  Last Modified On : 2023-06-28 16:26
// ***********************************************************************
//  <copyright file="SamlNsManagerExtensions.cs" company="">
//   Copyright (c) RzR. All rights reserved.
//  </copyright>
// 
//  <summary>
//  </summary>
// ***********************************************************************

#region U S A G E S

using System.Xml;
using DomainCommonExtensions.CommonExtensions;
using MPassHelperDotNet.Helpers;

#endregion

namespace MPassHelperDotNet.Extensions.SAML
{
    /// <summary>
    ///     SAML namespace Manager extensions
    /// </summary>
    internal static class SamlNsManagerExtensions
    {
        private static XmlNamespaceManager _xmlRequestNsManager;
        private static XmlNamespaceManager _xmlResponseNsManager;

        /// <summary>
        ///     XML document to request SAML namespace manager.
        ///     Get a <see cref="XmlNamespaceManager" /> with two namespaces required
        ///     when parsing saml requests/responses.
        /// </summary>
        /// <param name="xmlDocument">
        ///     XML document that contains the SAML Request or an empty document that will be used
        ///     for SAML request
        /// </param>
        /// <returns>Return SAML namespace manager object required for processing saml requests</returns>
        internal static XmlNamespaceManager ToRequestSamlNsManager(this XmlDocument xmlDocument)
        {
            if (!_xmlRequestNsManager.IsNull())
                return _xmlRequestNsManager;
            _xmlRequestNsManager = new XmlNamespaceManager(xmlDocument.NameTable);

            _xmlRequestNsManager.AddNamespace("samlp", DefaultStaticInfo.UrnSaml2Protocol);
            _xmlRequestNsManager.AddNamespace("saml", DefaultStaticInfo.UrnSaml2Assertion);

            return _xmlRequestNsManager;
        }

        /// <summary>
        ///     XML document to response SAML namespace manager.
        ///     Get a <see cref="XmlNamespaceManager" /> with two namespaces required
        ///     when parsing saml requests/responses.
        /// </summary>
        /// <param name="xmlDocument">
        ///     XML document that contains the SAML Response or an empty document
        ///     that will be used for SAML response
        /// </param>
        /// <returns>Return SAML namespace manager object required for processing saml responses</returns>
        internal static XmlNamespaceManager ToResponseSamlNsManager(this XmlDocument xmlDocument)
        {
            if (!_xmlResponseNsManager.IsNull())
                return _xmlResponseNsManager;
            _xmlResponseNsManager = new XmlNamespaceManager(xmlDocument.NameTable);

            _xmlResponseNsManager.AddNamespace("saml2p", DefaultStaticInfo.UrnSaml2Protocol);
            _xmlResponseNsManager.AddNamespace("saml2", DefaultStaticInfo.UrnSaml2Assertion);

            return _xmlResponseNsManager;
        }
    }
}