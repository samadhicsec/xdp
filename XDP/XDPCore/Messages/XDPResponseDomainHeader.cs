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
using log4net;
using XDP.XDPCore.DataFormat.V1;
using XDP.XDPCore.Settings;

namespace XDP.XDPCore.Messages
{
    [System.SerializableAttribute()]
    [System.Xml.Serialization.XmlTypeAttribute(Namespace = "urn:com.XDP.XDPMessages")]
    [System.Xml.Serialization.XmlRootAttribute(Namespace = "urn:com.XDP.XDPMessages", IsNullable = false)]
    public class XDPResponseDomainHeader
    {
        private static readonly ILog log = LogManager.GetLogger(typeof(XDPResponseDomainHeader));
        private XDPInternalDomainHeader m_oXDPInternalDomainHeaderField;
        private byte[] m_oXDPInternalHeaderDomainSignatureField;

        [System.Xml.Serialization.XmlElementAttribute(Namespace = "urn:com.XDP.XDPData")]
        public XDPInternalDomainHeader XDPInternalDomainHeader
        {
            get
            {
                return m_oXDPInternalDomainHeaderField;
            }
            set
            {
                m_oXDPInternalDomainHeaderField = value;
            }
        }

        [System.Xml.Serialization.XmlElementAttribute(Namespace = "urn:com.XDP.XDPData", DataType = "hexBinary")]
        public byte[] XDPInternalHeaderDomainSignature
        {
            get
            {
                return m_oXDPInternalHeaderDomainSignatureField;
            }
            set
            {
                m_oXDPInternalHeaderDomainSignatureField = value;
            }
        }

        /// <summary>
        /// Populates this XDPResponseDomainHeader using the XDPRequestDomainHeader parameter.  Assumes that XDPRequestDomainHeader has been validated.
        /// </summary>
        /// <param name="oXDPRequestDomainHeader"></param>
        public void CreateResponse(XDPRequestDomainHeader oXDPRequestDomainHeader, List<SecurityIdentifier> oAuthorizedIdentities)
        {
            log.Debug("Entering " + System.Reflection.MethodInfo.GetCurrentMethod().Name);
            // Populate the XDPCryptoSettings
            XDPCryptoSettings oCryptoSettings = new XDPCryptoSettings(oXDPRequestDomainHeader.XDPInternalCommonHeader.XDPEncryptionAlgorithm,
                                                        (CipherMode)Enum.Parse(typeof(CipherMode), oXDPRequestDomainHeader.XDPInternalCommonHeader.XDPEncryptionMode),
                                                        oXDPRequestDomainHeader.XDPInternalCommonHeader.XDPSignatureAlgorithm);
            
            // Create the XDPSignatureHelper
            XDPSignatureHelper oSignatureHelper = new XDPSignatureHelper(oCryptoSettings, oXDPRequestDomainHeader.XDPKeys.XDPSignatureKey);

            // Set the XDPInternalDomainHeader
            log.Debug("Creating XDPInternalDomainHeader");
            m_oXDPInternalDomainHeaderField = new XDPInternalDomainHeader(Environment.MachineName, oAuthorizedIdentities, oXDPRequestDomainHeader.XDPKeys);

            // Set the XDPInternalDomainHeaderSignature
            log.Debug("Creating XDPInternalHeaderDomainSignature");
            m_oXDPInternalHeaderDomainSignatureField = CreateDomainHeaderSignature(oSignatureHelper, oXDPRequestDomainHeader.XDPInternalCommonHeader, m_oXDPInternalDomainHeaderField);

            log.Debug("Exiting " + System.Reflection.MethodInfo.GetCurrentMethod().Name);
        }

        internal byte[] CreateDomainHeaderSignature(XDPSignatureHelper oSignatureHelper, XDPInternalCommonHeader oInternalCommonHeader, XDPInternalDomainHeader oLocalInternalDomainHeader)
        {
            // Serialize oInternalCommonHeader
            byte[] SerializedInternalCommonHeader = XDPCommon.SerializeToXml(oInternalCommonHeader, "urn:com.XDP.XDPData");

            // Serialize the oLocalInternalDomainHeader
            byte[] SerializedLocalInternalDomainHeader = XDPCommon.SerializeToXml(oLocalInternalDomainHeader, "urn:com.XDP.XDPData");

            // Combine
            byte[] SerializedSignatureData = new byte[SerializedInternalCommonHeader.Length + SerializedLocalInternalDomainHeader.Length];
            Array.Copy(SerializedInternalCommonHeader, SerializedSignatureData, SerializedInternalCommonHeader.Length);
            Array.Copy(SerializedLocalInternalDomainHeader, 0, SerializedSignatureData, SerializedInternalCommonHeader.Length, SerializedLocalInternalDomainHeader.Length);

            // Sign the signature data
            return oSignatureHelper.Sign(SerializedSignatureData);
        }
    }
}
