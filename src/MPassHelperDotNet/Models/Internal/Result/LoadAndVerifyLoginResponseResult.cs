// ***********************************************************************
//  Assembly         : RzR.Shared.eGovMD.MPassHelperDotNet
//  Author           : RzR
//  Created On       : 2023-06-18 02:04
// 
//  Last Modified By : RzR
//  Last Modified On : 2026-09-24 17:40
// ***********************************************************************
//  <copyright file="LoadAndVerifyLoginResponseResult.cs" company="">
//   Copyright (c) RzR. All rights reserved.
//  </copyright>
// 
//  <summary>
//  </summary>
// ***********************************************************************

#region U S A G E S

using System;
using System.Collections.Generic;

// ReSharper disable CollectionNeverQueried.Global
// ReSharper disable UnusedAutoPropertyAccessor.Global

#endregion

namespace MPassHelperDotNet.Models.Internal.Result
{
    /// <summary>
    ///     Load and verify LogIn SAML response (result data)
    /// </summary>
    public class LoadAndVerifyLoginResponseResult
    {
        /// <summary>
        ///     Session index
        /// </summary>
        public string SessionIndex { get; set; }

        /// <summary>
        ///     SAML response name id
        /// </summary>
        public string NameId { get; set; }

        /// <summary>
        ///     SAML response attributes
        /// </summary>
        public Dictionary<string, IList<string>> Attributes { get; set; }

        /// <summary>
        ///     Response InResponseTo (the auth request id)
        /// </summary>
        internal string InResponseTo { get; set; }

        /// <summary>
        ///     Authentication IP address (AuthnStatement/SubjectLocality/@Address)
        /// </summary>
        internal string AuthIp { get; set; }

        /// <summary>
        ///     Response ID
        /// </summary>
        internal string ResponseId { get; set; }

        /// <summary>
        ///     Assertion ID
        /// </summary>
        internal string AssertionId { get; set; }

        /// <summary>
        ///     UTC instant until which the message ID must be kept by the replay cache
        /// </summary>
        internal DateTimeOffset ReplayExpiresAtUtc { get; set; }
    }
}