// ***********************************************************************
//  Assembly         : RzR.Shared.eGovMD.MPassHelperDotNet
//  Author           : RzR
//  Created On       : 2023-06-15 17:31
// 
//  Last Modified By : RzR
//  Last Modified On : 2023-06-28 16:26
// ***********************************************************************
//  <copyright file="AuthMPassUserInfo.cs" company="">
//   Copyright (c) RzR. All rights reserved.
//  </copyright>
// 
//  <summary>
//  </summary>
// ***********************************************************************

#region U S A G E S

using System;

// ReSharper disable ClassNeverInstantiated.Global
// ReSharper disable UnusedAutoPropertyAccessor.Global

#endregion

namespace MPassHelperDotNet.Models.Dto
{
    /// <summary>
    ///     Auth user information available from MPass
    /// </summary>
    public class AuthMPassUserInfo
    {
        /// <summary>
        ///     User identifier code / NameID
        /// </summary>
        public string NameIdentifier { get; set; }

        /// <summary>
        ///     Auth request id
        ///     Is equals with attribute 'InResponseTo' (In response to auth request identifier)
        /// </summary>
        public string RequestId { get; set; }

        /// <summary>
        ///     User identifier code / NameID
        /// </summary>
        public string Idnp { get; set; }

        /// <summary>
        ///     User firstname
        /// </summary>
        public string FirstName { get; set; }

        /// <summary>
        ///     User lastname
        /// </summary>
        public string LastName { get; set; }

        /// <summary>
        ///     User phone number
        /// </summary>
        public string PhoneNumber { get; set; }

        /// <summary>
        ///     User phone number
        /// </summary>
        public string MobilePhoneNumber { get; set; }

        /// <summary>
        ///     User email (used on auth)
        /// </summary>
        public string Email { get; set; }

        /// <summary>
        ///     User gender
        /// </summary>
        public string Gender { get; set; }

        /// <summary>
        ///     Birth date
        /// </summary>
        public DateTime? BirthDate { get; set; }

        /// <summary>
        ///     User auth language
        /// </summary>
        public string Language { get; set; }

        /// <summary>
        ///     User auth IP
        /// </summary>
        public string AuthIp { get; set; }
    }
}