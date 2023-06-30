// ***********************************************************************
//  Assembly         : RzR.Shared.eGovMD.MPassHelperDotNet
//  Author           : RzR
//  Created On       : 2023-06-19 17:57
// 
//  Last Modified By : RzR
//  Last Modified On : 2023-06-28 16:26
// ***********************************************************************
//  <copyright file="LoadAndVerifyLogoutRequestResult.cs" company="">
//   Copyright (c) RzR. All rights reserved.
//  </copyright>
// 
//  <summary>
//  </summary>
// ***********************************************************************

#region U S A G E S

using System.Xml;

#endregion

// ReSharper disable UnusedAutoPropertyAccessor.Global

namespace MPassHelperDotNet.Models.Internal.Result
{
    /// <summary>
    ///     Load and verify LOGOUT request(result data)
    /// </summary>
    public class LoadAndVerifyLogoutRequestResult
    {
        /// <summary>
        ///     XML document
        /// </summary>
        public XmlDocument XmlDocument { get; set; }

        /// <summary>
        ///     Logout request id
        /// </summary>
        public string RequestId { get; set; }
    }
}