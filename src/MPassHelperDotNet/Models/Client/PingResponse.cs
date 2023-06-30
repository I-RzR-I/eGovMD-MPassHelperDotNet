// ***********************************************************************
//  Assembly         : RzR.Shared.eGovMD.MPassHelperDotNet
//  Author           : RzR
//  Created On       : 2023-06-20 18:14
// 
//  Last Modified By : RzR
//  Last Modified On : 2023-06-28 16:26
// ***********************************************************************
//  <copyright file="PingResponse.cs" company="">
//   Copyright (c) RzR. All rights reserved.
//  </copyright>
// 
//  <summary>
//  </summary>
// ***********************************************************************

// ReSharper disable UnusedAutoPropertyAccessor.Global
namespace MPassHelperDotNet.Models.Client
{
    /// <summary>
    ///     Ping response result
    /// </summary>
    public class PingResponse
    {
        /// <summary>
        ///     Execution time
        /// </summary>
        public string Time { get; set; }

        /// <summary>
        ///     Ping response message
        /// </summary>
        public string Message { get; set; }

        /// <summary>
        ///     Ping success status
        /// </summary>
        public bool IsSuccess { get; set; }
    }
}