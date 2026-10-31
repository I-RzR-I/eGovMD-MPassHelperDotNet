// ***********************************************************************
//  Assembly         : RzR.Shared.eGovMD.MPassHelperDotNet
//  Author           : RzR
//  Created On       : 2026-09-25 09:29
// 
//  Last Modified By : RzR
//  Last Modified On : 2026-09-25 09:29
// ***********************************************************************
//  <copyright file="ExceptionLogHelper.cs" company="">
//   Copyright (c) RzR. All rights reserved.
//  </copyright>
// 
//  <summary>
//  </summary>
// ***********************************************************************

#region U S I N G

using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Logging.Abstractions;
using System;
using System.Security.Cryptography;
using System.Text;
using System.Threading;
using System.Xml;

#endregion

namespace MPassHelperDotNet.Helpers.Logging
{
    /// <summary>
    ///     Exception logging helper 
    /// </summary>
    internal static class ExceptionLogHelper
    {
        /// <summary>
        ///     Log a caught exception as a warning, without the message payload.
        /// </summary>
        /// <param name="logger">Logger (null means no logging)</param>
        /// <param name="exception">Caught exception.</param>
        /// <param name="operation">Operation name.</param>
        internal static void LogCaughtException(ILogger logger, Exception exception, string operation)
        {
            logger ??= NullLogger.Instance;

            if (exception is XmlException || exception is FormatException ||
                exception is CryptographicException || exception is DecoderFallbackException)
                logger.LogWarning("{Operation} failed: {ExceptionType}", operation, exception.GetType().Name);
            else
                logger.LogWarning(exception, "{Operation} failed", operation);
        }

        /// <summary>
        ///     Check whether the exception is a cancellation requested by the caller.
        /// </summary>
        /// <param name="exception">Caught exception.</param>
        /// <param name="cancellationToken">Caller cancellation token.</param>
        /// <returns>
        ///     <see langword="true" /> when the exception must be propagated as 
        ///                             <see cref="OperationCanceledException" />.
        /// </returns>
        internal static bool IsCallerCancellation(Exception exception, CancellationToken cancellationToken)
            => exception is OperationCanceledException && cancellationToken.IsCancellationRequested;
    }
}