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
using System.Security.Cryptography;
using log4net;
using XDP.XDPCore.DataFormat.V1;
using XDP.XDPCore.Settings;

namespace XDP.XDPCore.Messages
{
    [System.SerializableAttribute()]
    [System.Xml.Serialization.XmlTypeAttribute(Namespace = "urn:com.XDP.XDPMessages")]
    [System.Xml.Serialization.XmlRootAttribute(Namespace = "urn:com.XDP.XDPMessages", IsNullable = false)]
    public class XDPRequestDecryptionKey
    {
        private static readonly ILog log = LogManager.GetLogger(typeof(XDPRequestDecryptionKey));

        XDPInternalCommonHeader m_oXDPInternalCommonHeader;
        XDPInternalDomainHeader m_oXDPInternalDomainHeader;
        byte[] m_oXDPInternalHeaderDomainSignature;

        [System.Xml.Serialization.XmlElementAttribute(Namespace = "urn:com.XDP.XDPData")]
        public XDPInternalCommonHeader XDPInternalCommonHeader
        {
            get { return m_oXDPInternalCommonHeader; }
            set { m_oXDPInternalCommonHeader = value; }
        }

        [System.Xml.Serialization.XmlElementAttribute(Namespace = "urn:com.XDP.XDPData")]
        public XDPInternalDomainHeader XDPInternalDomainHeader
        {
            get { return m_oXDPInternalDomainHeader; }
            set { m_oXDPInternalDomainHeader = value; }
        }

        [System.Xml.Serialization.XmlElementAttribute(Namespace = "urn:com.XDP.XDPData", DataType = "hexBinary")]
        public byte[] XDPInternalHeaderDomainSignature
        {
            get { return m_oXDPInternalHeaderDomainSignature; }
            set { m_oXDPInternalHeaderDomainSignature = value; }
        }

        /// <summary>
        /// Verifies that the signature on the Domain Header is valid
        /// </summary>
        /// <param name="oXDPKeys"></param>
        /// <returns></returns>
        public bool VerifySignature(XDPKeys oXDPKeys)
        {
            log.Debug("Entering " + System.Reflection.MethodInfo.GetCurrentMethod().Name);
            // Populate the XDPCryptoSettings
            XDPCryptoSettings oCryptoSettings = new XDPCryptoSettings(XDPInternalCommonHeader.XDPEncryptionAlgorithm,
                                                        (CipherMode)Enum.Parse(typeof(CipherMode), XDPInternalCommonHeader.XDPEncryptionMode),
                                                        XDPInternalCommonHeader.XDPSignatureAlgorithm);

            // Create the XDPSignatureHelper
            XDPSignatureHelper oSignatureHelper = new XDPSignatureHelper(oCryptoSettings, oXDPKeys.XDPSignatureKey);

            // Calculate the signature
            XDPResponseDomainHeader oXDPResponseDomainHeader = new XDPResponseDomainHeader();
            byte[] DomainHeaderSig = oXDPResponseDomainHeader.CreateDomainHeaderSignature(oSignatureHelper, m_oXDPInternalCommonHeader, m_oXDPInternalDomainHeader);

            //Compare the signature
            bool bSigValid = false;
            if (DomainHeaderSig.Length == m_oXDPInternalHeaderDomainSignature.Length)
            {
                int i = 0;
                for (; i < DomainHeaderSig.Length; i++)
                {
                    if (DomainHeaderSig[i] != m_oXDPInternalHeaderDomainSignature[i])
                        break;
                }
                if (i == DomainHeaderSig.Length)
                    bSigValid = true;
            }
            log.Debug("Exiting " + System.Reflection.MethodInfo.GetCurrentMethod().Name);
            return bSigValid;
        }

        internal bool Validate(XDPExceptionHelper oExceptionHelper)
        {
            log.Debug("Entering " + System.Reflection.MethodInfo.GetCurrentMethod().Name);

            if (!XDPInternalDomainHeader.Validate(XDPInternalDomainHeader, oExceptionHelper))
                return false;

            if (!XDPInternalDomainHeader.XDPDomainServer.Equals(Environment.MachineName, StringComparison.InvariantCultureIgnoreCase))
            {
                // Send back bad parameter
                oExceptionHelper.SendBadParameterException("XDPInternalDomainHeader.XDPDomainServer", "Request sent to wrong machine");
                return false;
            }

            int EncryptionKeyLength = 0;
            int SignatureKeyLength = 0;
            if (!XDP.XDPCore.DataFormat.V1.XDPInternalCommonHeader.Validate(XDPInternalCommonHeader, oExceptionHelper, out EncryptionKeyLength, out SignatureKeyLength))
                return false;

            if (!XDPInternalDomainHeader.ValidateSignature(XDPInternalHeaderDomainSignature, SignatureKeyLength, oExceptionHelper))
                return false;

            log.Debug("Exiting " + System.Reflection.MethodInfo.GetCurrentMethod().Name);
            return true;
        }
    }
}
