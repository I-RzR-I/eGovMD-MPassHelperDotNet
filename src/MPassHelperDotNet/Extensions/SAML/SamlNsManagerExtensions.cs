// ***********************************************************************
//  Assembly         : RzR.Shared.eGovMD.MPassHelperDotNet
//  Author           : RzR
//  Created On       : 2023-06-15 09:09
// 
//  Last Modified By : RzR
//  Last Modified On : 2026-09-22 14:22
// ***********************************************************************
//  <copyright file="SamlNsManagerExtensions.cs" company="">
//   Copyright (c) RzR. All rights reserved.
//  </copyright>
// 
//  <summary>
//  </summary>
// ***********************************************************************

#region U S A G E S

using System.Security.Cryptography.Xml;
using System.Xml;
using MPassHelperDotNet.Helpers;

#endregion

namespace MPassHelperDotNet.Extensions.SAML
{
    /// <summary>
    ///     SAML namespace Manager extensions
    /// </summary>
    internal static class SamlNsManagerExtensions
    {
        /// <summary>
        ///     XML document to response SAML namespace manager. Get a new <see cref="XmlNamespaceManager" />
        ///     with the namespaces required when parsing saml requests/responses (<c>saml2p</c>, <c>
        ///     saml2</c> and <c>ds</c>).
        /// </summary>
        /// <param name="xmlDocument">
        ///     XML document that contains the SAML message. The manager is bound to the name table of
        ///     this document, so it must be created after the document is loaded and used only with this
        ///     document.
        /// </param>
        /// <returns>
        ///     Return a new SAML namespace manager object required for processing saml messages.
        /// </returns>
        internal static XmlNamespaceManager ToResponseSamlNsManager(this XmlDocument xmlDocument)
        {
            // A new manager per document: a shared static instance would be bound to the name table of the first document
            // and is not thread safe.
            var xmlNamespaceManager = new XmlNamespaceManager(xmlDocument.NameTable);

            xmlNamespaceManager.AddNamespace("saml2p", DefaultStaticInfo.UrnSaml2Protocol);
            xmlNamespaceManager.AddNamespace("saml2", DefaultStaticInfo.UrnSaml2Assertion);
            xmlNamespaceManager.AddNamespace("ds", SignedXml.XmlDsigNamespaceUrl);

            return xmlNamespaceManager;
        }
    }
}