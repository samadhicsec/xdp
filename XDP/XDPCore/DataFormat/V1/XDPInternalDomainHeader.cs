/*
 * Copyright 2011 David Soldera, Samadhic Security Ltd
 * <http://www.samadhicsecurity.com>
 * 
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 * 
 *     http://www.apache.org/licenses/LICENSE-2.0
 * 
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
using System;
using System.Collections.Generic;
using System.Security.Cryptography;
using System.Security.Principal;

namespace XDP.XDPCore.DataFormat.V1
{
    /// <remarks/>
    [System.SerializableAttribute()]
    [System.Xml.Serialization.XmlTypeAttribute(AnonymousType = true, Namespace = "urn:com.XDP.XDPData")]
    [System.Xml.Serialization.XmlRootAttribute(Namespace = "urn:com.XDP.XDPData", IsNullable = false)]
    public class XDPInternalDomainHeader
    {

        private string m_XDPDomainServerField;

        private string[] m_XDPAuthorizedIdentitiesField;

        private byte[] m_XDPEncryptedKeysField;

        /// <summary>
        /// Parameterless constructor used for Serialization
        /// </summary>
        public XDPInternalDomainHeader()
        {

        }

        internal XDPInternalDomainHeader(String Hostname, List<SecurityIdentifier> oAuthorizedIdentities, XDPKeys oXDPKeys)
        {
            m_XDPDomainServerField = Hostname;
            m_XDPAuthorizedIdentitiesField = new string[oAuthorizedIdentities.Count];
            for (int i = 0; i < oAuthorizedIdentities.Count; i++)
                m_XDPAuthorizedIdentitiesField[i] = oAuthorizedIdentities[i].ToString();

            // Encrypt using DPAPI
            m_XDPEncryptedKeysField = ProtectedData.Protect(XDPCommon.SerializeToXml(oXDPKeys, "urn:com.XDP.XDPMessages"), null, DataProtectionScope.CurrentUser); 
        }

        /// <summary>
        /// Validate the format and values of this XDPInternalDomainHeader
        /// </summary>
        internal void Validate()
        {
            if (String.IsNullOrEmpty(m_XDPDomainServerField))
                throw new XDPBadParameterException("XDPInternalDomainHeader.XDPDomainServer", "Value was null or empty");
            if (null == m_XDPAuthorizedIdentitiesField)
                throw new XDPBadParameterException("XDPInternalDomainHeader.XDPAuthorizedIdentities", "Parameter was null");
            if (0 == m_XDPAuthorizedIdentitiesField.Length)
                throw new XDPBadParameterException("XDPInternalDomainHeader.XDPAuthorizedIdentities", "Array was empty");
            if (null == m_XDPEncryptedKeysField)
                throw new XDPBadParameterException("XDPInternalDomainHeader.XDPEncryptedKeys", "Parameter was null");
            if (0 == m_XDPEncryptedKeysField.Length)
                throw new XDPBadParameterException("XDPInternalDomainHeader.XDPEncryptedKeys", "Array was empty");
        }

        /// <remarks/>
        public string XDPDomainServer
        {
            get
            {
                return this.m_XDPDomainServerField;
            }
            set
            {
                this.m_XDPDomainServerField = value;
            }
        }

        /// <remarks/>
        [System.Xml.Serialization.XmlArrayItemAttribute("Identity", IsNullable = false)]
        public string[] XDPAuthorizedIdentities
        {
            get
            {
                return this.m_XDPAuthorizedIdentitiesField;
            }
            set
            {
                this.m_XDPAuthorizedIdentitiesField = value;
            }
        }

        /// <remarks/>
        [System.Xml.Serialization.XmlElementAttribute(DataType = "hexBinary")]
        public byte[] XDPEncryptedKeys
        {
            get
            {
                return this.m_XDPEncryptedKeysField;
            }
            set
            {
                this.m_XDPEncryptedKeysField = value;
            }
        }

        /// <summary>
        /// Validates that the values of XDPInternalDomainHeader are not null or empty
        /// </summary>
        /// <param name="oXDPInternalCommonHeader"></param>
        /// <returns></returns>
        internal static bool Validate(XDPInternalDomainHeader oXDPInternalDomainHeader, XDP.XDPCore.Messages.XDPExceptionHelper oExceptionHelper)
        {
            if (null == oXDPInternalDomainHeader)
            {
                // Send back bad parameter
                oExceptionHelper.SendBadParameterException("XDPInternalDomainHeader", "Parameter was null");
                return false;
            }

            if (String.IsNullOrEmpty(oXDPInternalDomainHeader.XDPDomainServer))
            {
                // Send back bad parameter
                oExceptionHelper.SendBadParameterException("XDPInternalDomainHeader.XDPDomainServer", "Value was null or empty");
                return false;
            }

            if (null == oXDPInternalDomainHeader.XDPEncryptedKeys)
            {
                // Send back bad parameter
                oExceptionHelper.SendBadParameterException("XDPInternalDomainHeader.XDPEncryptedKeys", "Parameter was null");
                return false;
            }

            if (0 == oXDPInternalDomainHeader.XDPEncryptedKeys.Length)
            {
                // Send back bad parameter
                oExceptionHelper.SendBadParameterException("XDPInternalDomainHeader.XDPEncryptedKeys", "Array was empty");
                return false;
            }

            return true;
        }

        /// <summary>
        /// Validates that the XDPInternalHeaderDomainSignature is not nullor empty
        /// </summary>
        /// <param name="oXDPEncryptedKeys"></param>
        /// <returns></returns>
        internal static bool ValidateSignature(byte[] oXDPInternalHeaderDomainSignature, int SignatureKeyLength, XDP.XDPCore.Messages.XDPExceptionHelper oExceptionHelper)
        {
            if (null == oXDPInternalHeaderDomainSignature)
            {
                // Send back bad parameter
                oExceptionHelper.SendBadParameterException("XDPInternalHeaderDomainSignature", "Parameter was null");
                return false;
            }

            if (SignatureKeyLength != oXDPInternalHeaderDomainSignature.Length)
            {
                // Send back bad parameter
                oExceptionHelper.SendBadParameterException("XDPInternalHeaderDomainSignature", "Value is incorrect length for XDPSignatureAlgorithm");
                return false;
            }

            return true;
        }
    }
}
