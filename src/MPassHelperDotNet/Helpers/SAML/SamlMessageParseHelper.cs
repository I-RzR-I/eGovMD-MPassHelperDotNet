// ***********************************************************************
//  Assembly         : RzR.Shared.eGovMD.MPassHelperDotNet
//  Author           : RzR
//  Created On       : 2023-06-15 17:18
// 
//  Last Modified By : RzR
//  Last Modified On : 2026-09-25 12:28
// ***********************************************************************
//  <copyright file="SamlMessageParseHelper.cs" company="">
//   Copyright (c) RzR. All rights reserved.
//  </copyright>
// 
//  <summary>
//  </summary>
// ***********************************************************************

#region U S A G E S

using System;
using System.Globalization;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Logging.Abstractions;
using RzR.ResultMessage;
using RzR.ResultMessage.Abstractions;
using RzR.Extensions.Domain.Primitives;
using MPassHelperDotNet.Helpers.Logging;
using MPassHelperDotNet.Models.Dto;
using MPassHelperDotNet.Models.Internal.Result;
using MPassHelperDotNet.Helpers.Messages;

#endregion

namespace MPassHelperDotNet.Helpers.SAML
{
    /// <summary>
    ///     SAML message parse helper
    /// </summary>
    internal static class SamlMessageParseHelper
    {
        private const string BirthDateExactFormat = "yyyy-MM-dd";

        /// <summary>
        ///     Get auth user details from the verified login response.
        /// </summary>
        /// <param name="verified">
        ///     Verified login response data (result of the signature and protocol validation)
        /// </param>
        /// <param name="logger">
        ///     (Optional) Optional. Logger for caught exceptions. The default value is null (no logging).
        /// </param>
        /// <returns>
        ///     Return parsed user auth details.
        /// </returns>
        internal static IResult<AuthMPassUserInfo> GetAuthUserDetails(LoadAndVerifyLoginResponseResult verified, ILogger logger = null)
        {
            logger ??= NullLogger.Instance;

            if (verified.IsNull())
            {
                return Result<AuthMPassUserInfo>
                    .Failure(string.Format(DefaultMessages.ArgumentNullMessage, nameof(verified)));
            }

            try
            {
                if (verified.Attributes.IsNull())
                {
                    return Result<AuthMPassUserInfo>
                        .Failure(string.Format(DefaultMessages.NoChildInSaml2Attribute, "saml2:AttributeStatement"));
                }

                var userInfo = new AuthMPassUserInfo
                {
                    Idnp = verified.NameId,
                    RequestId = verified.InResponseTo,
                    AuthIp = verified.AuthIp
                };

                foreach (var attribute in verified.Attributes)
                {
                    var name = attribute.Key;
                    var value = attribute.Value.IsNull() ? string.Empty : string.Concat(attribute.Value);
                    switch (name.ToLowerInvariant())
                    {
                        case "nameidentifier":
                            userInfo.NameIdentifier = value;
                            break;
                        case "isresident":
                            if (bool.TryParse(value, out var isResident))
                                userInfo.IsResident = isResident;
                            break;
                        case "firstname":
                            userInfo.FirstName = value;
                            break;
                        case "lastname":
                            userInfo.LastName = value;
                            break;
                        case "birthdate":
                            if (TryParseBirthDate(value, out var birthDate))
                                userInfo.BirthDate = birthDate;
                            break;
                        case "gender":
                            userInfo.Gender = value;
                            break;
                        case "emailaddress":
                            userInfo.Email = value;
                            break;
                        case "mobilephone":
                            userInfo.MobilePhoneNumber = value;
                            break;
                        case "phone":
                            userInfo.PhoneNumber = value;
                            break;
                        case "homephone":
                            userInfo.HomePhone = value;
                            break;
                        case "language":
                            userInfo.Language = value;
                            break;
                        case "administeredlegalentity":
                            userInfo.AdministeredLegalEntity = value;
                            break;
                        case "idno":
                            userInfo.Idno = value;
                            break;
                        case "companyname":
                            userInfo.CompanyName = value;
                            break;
                    }
                }

                return Result<AuthMPassUserInfo>.Success(userInfo);
            }
            catch (Exception e)
            {
                ExceptionLogHelper.LogCaughtException(logger, e, nameof(GetAuthUserDetails));

                return Result<AuthMPassUserInfo>
                    .Failure(DefaultMessages.ErrorGetUserAuthDetailsFromSaml);
            }
        }

        /// <summary>
        ///     Try parse the birthdate attribute value with the invariant culture.
        /// </summary>
        /// <remarks>
        ///     A time and an offset, when present, are ignored: the date is taken in the offset of the
        ///     value itself (no conversion to UTC), so the calendar date never shifts.
        /// </remarks>
        /// <param name="value">Raw attribute value.</param>
        /// <param name="birthDate">
        ///     [out] Parsed birthdate when the method returns true: the calendar date as sent, at
        ///     midnight, with
        ///     <see cref="DateTimeKind.Utc" />
        /// </param>
        /// <returns>
        ///     Return true if the value is a valid date; otherwise false.
        /// </returns>
        private static bool TryParseBirthDate(string value, out DateTime birthDate)
        {
            const DateTimeStyles styles = DateTimeStyles.AssumeUniversal;

            birthDate = default;
            if (!DateTimeOffset.TryParse(value, CultureInfo.InvariantCulture, styles, out var parsedBirthDate)
                && !DateTimeOffset.TryParseExact(value, BirthDateExactFormat, CultureInfo.InvariantCulture,
                    styles | DateTimeStyles.AllowWhiteSpaces, out parsedBirthDate))
                return false;

            birthDate = DateTime.SpecifyKind(parsedBirthDate.Date, DateTimeKind.Utc);

            return true;
        }
    }
}