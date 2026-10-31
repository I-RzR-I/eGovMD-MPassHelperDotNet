// ***********************************************************************
//  Assembly         : RzR.Shared.eGovMD.MPassHelperDotNet
//  Author           : RzR
//  Created On       : 2026-09-25 19:03
// 
//  Last Modified By : RzR
//  Last Modified On : 2026-09-25 19:03
// ***********************************************************************
//  <copyright file="ISamlReplayCache.cs" company="">
//   Copyright (c) RzR. All rights reserved.
//  </copyright>
// 
//  <summary>
//  </summary>
// ***********************************************************************

#region U S I N G

using System;
using System.Threading;
using System.Threading.Tasks;

#endregion

namespace MPassHelperDotNet.Abstractions.Services.Replay
{
    /// <summary>
    ///     SAML message replay cache. Stores the IDs of already processed inbound SAML messages so
    ///     that every message is accepted only once.
    /// </summary>
    public interface ISamlReplayCache
    {
        /// <summary>
        ///     Try to register a processed message ID until the given expiration time.
        /// </summary>
        /// <param name="messageId">Required. Message key (message type prefix and message ID).</param>
        /// <param name="expiresAtUtc">
        ///     Required. UTC instant until which the message ID must be remembered.
        /// </param>
        /// <param name="cancellationToken">(Optional) Optional. The default value is default.</param>
        /// <returns>
        ///     <see langword="true" /> when the message ID was not seen before (or its previous entry
        ///     expired);
        ///     <see langword="false" /> when it is a replay or the cache cannot accept new entries.
        /// 
        /// </returns>
        Task<bool> TryAddAsync(string messageId, DateTimeOffset expiresAtUtc, CancellationToken cancellationToken = default);
    }
}