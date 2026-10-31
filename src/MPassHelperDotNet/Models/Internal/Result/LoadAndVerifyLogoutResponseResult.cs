// ***********************************************************************
//  Assembly         : RzR.Shared.eGovMD.MPassHelperDotNet
//  Author           : RzR
//  Created On       : 2023-06-19 10:01
// 
//  Last Modified By : RzR
//  Last Modified On : 2026-09-22 08:37
// ***********************************************************************
//  <copyright file="LoadAndVerifyLogoutResponseResult.cs" company="">
//   Copyright (c) RzR. All rights reserved.
//  </copyright>
// 
//  <summary>
//  </summary>
// ***********************************************************************

#region U S A G E S

using System;
using System.Xml;

// ReSharper disable UnusedAutoPropertyAccessor.Global

#endregion

namespace MPassHelperDotNet.Models.Internal.Result
{
    /// <summary>
    ///     Load and verify logout response result
    /// </summary>
    public class LoadAndVerifyLogoutResponseResult
    {
        /// <summary>
        ///     XML namespace
        /// </summary>
        public XmlNamespaceManager XmlNamespace { get; set; }

        /// <summary>
        ///     Logout response ID
        /// </summary>
        internal string ResponseId { get; set; }

        /// <summary>
        ///     UTC instant until which the message ID must be kept by the replay cache
        /// </summary>
        internal DateTimeOffset ReplayExpiresAtUtc { get; set; }
    }
}