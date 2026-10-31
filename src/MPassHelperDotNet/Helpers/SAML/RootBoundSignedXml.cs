// ***********************************************************************
//  Assembly         : RzR.Shared.eGovMD.MPassHelperDotNet
//  Author           : RzR
//  Created On       : 2026-09-23 17:37
// 
//  Last Modified By : RzR
//  Last Modified On : 2026-09-23 17:37
// ***********************************************************************
//  <copyright file="RootBoundSignedXml.cs" company="">
//   Copyright (c) RzR. All rights reserved.
//  </copyright>
// 
//  <summary>
//  </summary>
// ***********************************************************************

#region U S A G E S

using System;
using System.Security.Cryptography.Xml;
using System.Xml;
using RzR.Extensions.Domain.Primitives;

#endregion

namespace MPassHelperDotNet.Helpers.SAML
{
    /// <summary>
    ///     Signed XML bound to the captured SAML root element.
    /// </summary>
    /// <seealso cref="T:System.Security.Cryptography.Xml.SignedXml"/>
    internal sealed class RootBoundSignedXml : SignedXml
    {
        private readonly XmlElement _root;
        private readonly string _rootId;

        /// <summary>
        ///     Initializes a new instance of the <see cref="RootBoundSignedXml" /> class.
        /// </summary>
        /// <param name="document">Verified XML document.</param>
        /// <param name="root">Captured root element of the document.</param>
        /// <param name="rootId">Captured root ID.</param>
        internal RootBoundSignedXml(XmlDocument document, XmlElement root, string rootId) : base(document)
        {
            _root = root;
            _rootId = rootId;
        }

        /// <summary>
        ///     Resolve a Reference ID: only the captured root, with the captured ID (Ordinal), is
        ///     returned.
        /// </summary>
        /// <param name="document">XML document.</param>
        /// <param name="idValue">Reference ID.</param>
        /// <returns>
        ///     Return the captured root element, or null for any other ID or document.
        /// </returns>
        public override XmlElement GetIdElement(XmlDocument document, string idValue)
        {
            if (document.IsNull() || !ReferenceEquals(document!.DocumentElement, _root))
                return null;

            return string.Equals(idValue, _rootId, StringComparison.Ordinal) ? document.DocumentElement : null;
        }
    }
}
