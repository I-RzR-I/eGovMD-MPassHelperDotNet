// ***********************************************************************
//  Assembly         : RzR.Shared.eGovMD.MPassHelperDotNet
//  Author           : RzR
//  Created On       : 2023-06-15 19:14
// 
//  Last Modified By : RzR
//  Last Modified On : 2023-06-28 16:26
// ***********************************************************************
//  <copyright file="StringExtensions.cs" company="">
//   Copyright (c) RzR. All rights reserved.
//  </copyright>
// 
//  <summary>
//  </summary>
// ***********************************************************************

#region U S A G E S

using System;

#endregion

namespace MPassHelperDotNet.Extensions
{
    /// <summary>
    ///     Internal string extensions
    /// </summary>
    internal static class StringExtensions
    {
        /// <summary>
        ///     Generate new request id
        /// </summary>
        /// <returns>Return request id</returns>
        internal static string GenerateRequestId()
            => $"_{Guid.NewGuid()}".ToLower();
    }
}