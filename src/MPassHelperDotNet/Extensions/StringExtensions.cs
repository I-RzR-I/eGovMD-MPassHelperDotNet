// ***********************************************************************
//  Assembly         : RzR.Shared.eGovMD.MPassHelperDotNet
//  Author           : RzR
//  Created On       : 2023-06-15 19:14
// 
//  Last Modified By : RzR
//  Last Modified On : 2026-09-23 09:05
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
using System.Security.Cryptography;
using System.Text;
using MPassHelperDotNet.Helpers;
using RzR.Extensions.Domain.Text;

#endregion

namespace MPassHelperDotNet.Extensions
{
    /// <summary>
    ///     Internal string extensions
    /// </summary>
    internal static class StringExtensions
    {
        /// <summary>
        ///     Number of random bytes in a generated request id (128 bits)
        /// </summary>
        private const int RequestIdRandomBytes = 16;

        /// <summary>
        ///     Generate new request id.
        /// </summary>
        internal static string GenerateRequestId()
        {
            var randomBytes = new byte[RequestIdRandomBytes];
            using (var randomNumberGenerator = RandomNumberGenerator.Create())
                randomNumberGenerator.GetBytes(randomBytes);

            return "_" + BitConverter.ToString(randomBytes).Replace("-", string.Empty).ToLowerInvariant();
        }

        /// <summary>
        ///     Check that the RelayState fits the SAML binding limit (80 bytes, UTF-8).
        /// </summary>
        /// <remarks>
        ///     RelayState size check shared by the request builders and the authentication service;
        ///     the caller determines whether an empty RelayState is accepted.
        /// </remarks>
        /// <param name="relayState">RelayState value.</param>
        /// <returns>
        ///     Return true for null/empty or when the UTF-8 size is at most 80 bytes.
        /// </returns>
        internal static bool IsRelayStateWithinLimit(this string relayState)
            => relayState.IsMissing() || Encoding.UTF8.GetByteCount(relayState) <= DefaultStaticInfo.RelayStateMaxBytes;
    }
}