// ***********************************************************************
//  Assembly         : RzR.Shared.eGovMD.MPassHelperDotNet
//  Author           : RzR
//  Created On       : 2023-06-18 02:04
// 
//  Last Modified By : RzR
//  Last Modified On : 2023-06-28 16:26
// ***********************************************************************
//  <copyright file="LoadAndVerifyLoginResponseResult.cs" company="">
//   Copyright (c) RzR. All rights reserved.
//  </copyright>
// 
//  <summary>
//  </summary>
// ***********************************************************************

#region U S A G E S

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
    }
}