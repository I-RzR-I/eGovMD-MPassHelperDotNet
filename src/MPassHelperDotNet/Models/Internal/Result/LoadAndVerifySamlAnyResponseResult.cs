// ***********************************************************************
//  Assembly         : RzR.Shared.eGovMD.MPassHelperDotNet
//  Author           : RzR
//  Created On       : 2023-06-17 21:44
// 
//  Last Modified By : RzR
//  Last Modified On : 2026-09-25 10:25
// ***********************************************************************
//  <copyright file="LoadAndVerifySamlAnyResponseResult.cs" company="">
//   Copyright (c) RzR. All rights reserved.
//  </copyright>
// 
//  <summary>
//  </summary>
// ***********************************************************************

#region U S A G E S

using System;
using System.Xml;

// ReSharper disable ClassNeverInstantiated.Global

#endregion

namespace MPassHelperDotNet.Models.Internal.Result
{
    /// <summary>
    ///     Load and verify SAML response; response model
    /// </summary>
    internal class LoadAndVerifySamlAnyResponseResult
    {
        /// <summary>
        ///     XML document
        /// </summary>
        public XmlDocument XmlDocument { get; set; }

        /// <summary>
        ///     XML namespace manager
        /// </summary>
        public XmlNamespaceManager NamespaceManager { get; set; }

        /// <summary>
        ///     Response ID
        /// </summary>
        internal string ResponseId { get; set; }

        /// <summary>
        ///     Response IssueInstant (UTC)
        /// </summary>
        internal DateTimeOffset IssueInstantUtc { get; set; }
    }
}