// ***********************************************************************
//  Assembly         : RzR.Shared.eGovMD.MPassHelperDotNet
//  Author           : RzR
//  Created On       : 2026-09-23 08:30
// 
//  Last Modified By : RzR
//  Last Modified On : 2026-09-23 12:51
// ***********************************************************************
//  <copyright file="SamlXmlLoadHelper.cs" company="">
//   Copyright (c) RzR. All rights reserved.
//  </copyright>
// 
//  <summary>
//  </summary>
// ***********************************************************************

#region U S A G E S

using System;
using System.IO;
using System.Text;
using System.Xml;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Logging.Abstractions;
using MPassHelperDotNet.Helpers.Messages;
using RzR.Extensions.Domain.Text;
using RzR.ResultMessage;
using RzR.ResultMessage.Abstractions;

#endregion

namespace MPassHelperDotNet.Helpers.SAML
{
    /// <summary>
    ///     SAML XML load helper.
    /// </summary>
    internal static class SamlXmlLoadHelper
    {
        /// <summary>
        ///     Strict UTF-8 decoder: no BOM emitted, throws on invalid byte sequences.
        /// </summary>
        private static readonly UTF8Encoding StrictUtf8 = new UTF8Encoding(false, true);

        /// <summary>
        ///     Maximum accepted element nesting depth (the root element is depth 1).
        /// </summary>
        internal const int MaxElementDepth = 64;

        /// <summary>
        ///     Load a SAML XML document from a Base64 encoded (HTTP-POST binding) message.
        /// </summary>
        /// <param name="base64">Required. Base64 encoded SAML message.</param>
        /// <param name="maxLength">
        ///     Required. Maximum accepted length (characters) of the Base64 text, checked before
        ///     decoding; the decoded document is bounded by the same number of characters. A value less than or
        ///     equal to zero means <see cref="DefaultStaticInfo.DefaultSamlMessageMaxLength" />.
        /// </param>
        /// <param name="logger">
        ///     (Optional) Optional. Logger for caught exceptions. The default value is null (no logging).
        /// </param>
        /// <returns>
        ///     Return the loaded XML document.
        /// </returns>
        internal static IResult<XmlDocument> LoadFromBase64(string base64, int maxLength, ILogger logger = null)
        {
            logger ??= NullLogger.Instance;

            if (base64.IsNullOrEmpty())
                return Result<XmlDocument>.Failure(string.Format(DefaultMessages.ArgumentNullMessage, nameof(base64)));

            if (maxLength <= 0)
                maxLength = DefaultStaticInfo.DefaultSamlMessageMaxLength;

            if (base64.Length > maxLength)
                return Result<XmlDocument>.Failure(SamlLoadValidationMessages.SamlMessageTooLarge);

            string xml;
            try
            {
                xml = StrictUtf8.GetString(Convert.FromBase64String(base64));
            }
            catch (Exception e) when (e is FormatException || e is DecoderFallbackException)
            {
                logger.LogWarning("{Operation} failed: {ExceptionType}", nameof(LoadFromBase64), e.GetType().Name);

                return Result<XmlDocument>.Failure(SamlLoadValidationMessages.SamlMessageEncodingInvalid);
            }
            catch (Exception e)
            {
                logger.LogWarning(e, "{Operation} failed", nameof(LoadFromBase64));

                return Result<XmlDocument>.Failure(SamlLoadValidationMessages.SamlMessageEncodingInvalid);
            }

            return LoadXml(xml, maxLength, nameof(LoadFromBase64), logger);
        }

        /// <summary>
        ///     Load a SAML XML document from an XML string.
        /// </summary>
        /// <remarks>
        ///     The document is bounded by <see cref="DefaultStaticInfo.DefaultSamlMessageMaxLength" />
        ///     characters.
        /// </remarks>
        /// <param name="xml">Required. XML string.</param>
        /// <param name="logger">
        ///     (Optional) Optional. Logger for caught exceptions. The default value is null (no logging).
        /// </param>
        /// <returns>
        ///     Return the loaded XML document.
        /// </returns>
        internal static IResult<XmlDocument> LoadFromXmlString(string xml, ILogger logger = null)
        {
            logger ??= NullLogger.Instance;

            if (xml.IsNullOrEmpty())
                return Result<XmlDocument>.Failure(string.Format(DefaultMessages.ArgumentNullMessage, nameof(xml)));

            if (xml.Length > DefaultStaticInfo.DefaultSamlMessageMaxLength)
                return Result<XmlDocument>.Failure(SamlLoadValidationMessages.SamlMessageTooLarge);

            return LoadXml(xml, DefaultStaticInfo.DefaultSamlMessageMaxLength, nameof(LoadFromXmlString), logger);
        }

        /// <summary>
        ///     Parse the XML with restricted reader settings (DTD processing prohibited, no XML resolver).
        /// </summary>
        /// <param name="xml">XML string.</param>
        /// <param name="maxLength">Maximum number of characters in the document.</param>
        /// <param name="operation">Calling operation name (for logging)</param>
        /// <param name="logger">Logger.</param>
        /// <returns>
        ///     Return the loaded XML document.
        /// </returns>
        private static IResult<XmlDocument> LoadXml(string xml, int maxLength, string operation, ILogger logger)
        {
            if (xml.Length > 0 && xml[0] == '\uFEFF')
                xml = xml.Substring(1);

            var settings = new XmlReaderSettings
            {
                DtdProcessing = DtdProcessing.Prohibit,
                XmlResolver = null,
                IgnoreComments = true,
                MaxCharactersInDocument = maxLength
            };

            try
            {
                var structureValidation = ValidateStructure(xml, settings);
                if (structureValidation.IsFailure)
                {
                    logger.LogWarning("{Operation} failed: rejected XML structure", operation);

                    return new Result<XmlDocument>
                    {
                        IsSuccess = false, 
                        Messages = structureValidation.Messages
                    };
                }

                var document = new XmlDocument
                {
                    PreserveWhitespace = true, 
                    XmlResolver = null
                };
                using (var stringReader = new StringReader(xml))
                using (var xmlReader = XmlReader.Create(stringReader, settings))
                {
                    document.Load(xmlReader);
                }

                return Result<XmlDocument>.Success(document);
            }
            catch (XmlException e)
            {
                logger.LogWarning("{Operation} failed: {ExceptionType}", operation, e.GetType().Name);

                return Result<XmlDocument>.Failure(SamlLoadValidationMessages.SamlXmlInvalid);
            }
            catch (Exception e)
            {
                logger.LogWarning(e, "{Operation} failed", operation);

                return Result<XmlDocument>.Failure(SamlLoadValidationMessages.SamlXmlInvalid);
            }
        }

        /// <summary>
        ///     Stream the XML once and reject processing instructions (the XML declaration is not one)
        ///     and elements nested deeper than <see cref="MaxElementDepth" />.
        /// </summary>
        /// <remarks>
        ///     Malformed XML throws <see cref="XmlException" />, handled by the caller.
        /// </remarks>
        /// <param name="xml">XML string.</param>
        /// <param name="settings">Reader settings.</param>
        /// <returns>
        ///     Return success if the structure is accepted.
        /// </returns>
        private static IResult ValidateStructure(string xml, XmlReaderSettings settings)
        {
            using (var stringReader = new StringReader(xml))
            using (var xmlReader = XmlReader.Create(stringReader, settings))
            {
                while (xmlReader.Read())
                {
                    if (xmlReader.NodeType == XmlNodeType.ProcessingInstruction)
                        return Result.Failure(SamlLoadValidationMessages.SamlProcessingInstructionNotAllowed);

                    if (xmlReader.NodeType == XmlNodeType.Element && xmlReader.Depth >= MaxElementDepth)
                        return Result.Failure(SamlLoadValidationMessages.SamlXmlInvalid);
                }
            }

            return Result.Success();
        }
    }
}
