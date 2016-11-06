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
using XDP.XDPCore.Settings;

namespace XDP.XDPCore.DataFormat.V1
{
    /// <remarks/>
    [System.SerializableAttribute()]
    [System.Xml.Serialization.XmlTypeAttribute(AnonymousType = true, Namespace = "urn:com.XDP.XDPData")]
    [System.Xml.Serialization.XmlRootAttribute(Namespace = "urn:com.XDP.XDPData", IsNullable = false)]
    public class XDPInternalCommonHeader
    {
        private static readonly ILog log = LogManager.GetLogger(typeof(XDPInternalCommonHeader));

        private string m_XDPEncryptionAlgorithmField;

        private string m_XDPEncryptionModeField;

        private byte[] m_XDPEncryptionIVField;

        private string m_XDPSignatureAlgorithmField;

        private byte[] m_XDPDataSignatureField;

        /// <summary>
        /// Parameterless constructor used for Serialization
        /// </summary>
        public XDPInternalCommonHeader()
        {

        }

        internal XDPInternalCommonHeader(IXDPCryptoSettings oCryptoSettings, XDPKeys oXDPKeys, byte[] DataSignature)
        {
            m_XDPDataSignatureField = new byte[DataSignature.Length];
            Array.Copy(DataSignature, m_XDPDataSignatureField, DataSignature.Length);
            m_XDPEncryptionAlgorithmField = oCryptoSettings.EncryptionAlgorithm;
            m_XDPEncryptionModeField = oCryptoSettings.EncryptionMode.ToString();
            m_XDPEncryptionIVField = new byte[oXDPKeys.XDPEncryptionIV.Length];
            
            //Array.Copy(oXDPKeys.XDPEncryptionIV, m_XDPEncryptionIVField, oXDPKeys.XDPEncryptionIV.Length);
            Buffer.BlockCopy(oXDPKeys.XDPEncryptionIV, 0, m_XDPEncryptionIVField, 0, oXDPKeys.XDPEncryptionIV.Length);
            m_XDPSignatureAlgorithmField = oCryptoSettings.SignatureAlgorithm;
        }

        internal IXDPCryptoSettings GetCryptoSettings()
        {
            XDPCryptoSettings oCryptoSettings = new XDPCryptoSettings(m_XDPEncryptionAlgorithmField, (CipherMode)Enum.Parse(typeof(CipherMode), m_XDPEncryptionModeField, true), m_XDPSignatureAlgorithmField);
            return oCryptoSettings;
        }

        /// <remarks/>
        public string XDPEncryptionAlgorithm
        {
            get
            {
                return this.m_XDPEncryptionAlgorithmField;
            }
            set
            {
                this.m_XDPEncryptionAlgorithmField = value;
            }
        }

        /// <remarks/>
        public string XDPEncryptionMode
        {
            get
            {
                return this.m_XDPEncryptionModeField;
            }
            set
            {
                this.m_XDPEncryptionModeField = value;
            }
        }

        /// <remarks/>
        [System.Xml.Serialization.XmlElementAttribute(DataType = "hexBinary")]
        public byte[] XDPEncryptionIV
        {
            get
            {
                return this.m_XDPEncryptionIVField;
            }
            set
            {
                this.m_XDPEncryptionIVField = value;
            }
        }

        /// <remarks/>
        public string XDPSignatureAlgorithm
        {
            get
            {
                return this.m_XDPSignatureAlgorithmField;
            }
            set
            {
                this.m_XDPSignatureAlgorithmField = value;
            }
        }

        /// <remarks/>
        [System.Xml.Serialization.XmlElementAttribute(DataType = "hexBinary")]
        public byte[] XDPDataSignature
        {
            get
            {
                return this.m_XDPDataSignatureField;
            }
            set
            {
                this.m_XDPDataSignatureField = value;
            }
        }

        /// <summary>
        /// Handles the situation when a bad parameter is found.  If an XDPExceptionHelper is available then we use it otherwise an exception is thrown.
        /// The XDPExceptionHelper should be available when validating a XDPRequestDomainHeader, otherwise when validating for deserializing then
        /// XDPExceptionHelper will be null.
        /// </summary>
        /// <param name="ParameterName"></param>
        /// <param name="ErrorMessage"></param>
        /// <param name="oExceptionHelper"></param>
        internal static void HandleBadParameter(String ParameterName, String ErrorMessage, XDP.XDPCore.Messages.XDPExceptionHelper oExceptionHelper)
        {
            if (null != oExceptionHelper)
                oExceptionHelper.SendBadParameterException(ParameterName, ErrorMessage);
            else
                throw new XDPBadParameterException(ParameterName, ErrorMessage);
        }

        /// <summary>
        /// Validates the values of XDPInternalCommonHeader
        /// </summary>
        /// <param name="oXDPInternalCommonHeader"></param>
        /// <returns></returns>
        internal static bool Validate(XDPInternalCommonHeader oXDPInternalCommonHeader, XDP.XDPCore.Messages.XDPExceptionHelper oExceptionHelper, out int EncryptionKeyLength, out int SignatureKeyLength)
        {
            log.Debug("Entering " + System.Reflection.MethodInfo.GetCurrentMethod().Name);
            EncryptionKeyLength = 0;
            SignatureKeyLength = 0;

            if (null == oXDPInternalCommonHeader)
            {
                // Send back bad parameter
                HandleBadParameter("XDPInternalCommonHeader", "Parameter was null", oExceptionHelper);
                return false;
            }

            if (String.IsNullOrEmpty(oXDPInternalCommonHeader.XDPEncryptionAlgorithm))
            {
                // Send back bad parameter
                HandleBadParameter("XDPInternalCommonHeader.XDPEncryptionAlgorithm", "Value was null or empty", oExceptionHelper);
                return false;
            }

            SymmetricAlgorithm EncAlg = XDPEncryptionHelper.CreateSymmetricAlgorithm(oXDPInternalCommonHeader.XDPEncryptionAlgorithm);
            if (null == EncAlg)
            {
                // Send back bad parameter
                HandleBadParameter("XDPInternalCommonHeader.XDPEncryptionAlgorithm", "Value was not a valid SymmetricAlgorithm", oExceptionHelper);
                return false;
            }
            EncryptionKeyLength = EncAlg.KeySize / 8;

            if (null == oXDPInternalCommonHeader.XDPEncryptionIV)
            {
                // Send back bad parameter
                HandleBadParameter("XDPInternalCommonHeader.XDPEncryptionIV", "Parameter was null", oExceptionHelper);
                return false;
            }

            if ((EncAlg.BlockSize / 8) != oXDPInternalCommonHeader.XDPEncryptionIV.Length)
            {
                // Send back bad parameter
                HandleBadParameter("XDPInternalCommonHeader.XDPEncryptionIV", "Value is incorrect length for XDPEncryptionAlgorithm", oExceptionHelper);
                return false;
            }

            if (String.IsNullOrEmpty(oXDPInternalCommonHeader.XDPEncryptionMode))
            {
                // Send back bad parameter
                HandleBadParameter("XDPInternalCommonHeader.XDPEncryptionMode", "Value was null or empty", oExceptionHelper);
                return false;
            }

            try
            {
                CipherMode eCipherMode = (CipherMode)Enum.Parse(typeof(CipherMode), oXDPInternalCommonHeader.XDPEncryptionMode, true);
            }
            catch (ArgumentException)
            {
                // Send back bad parameter
                HandleBadParameter("XDPInternalCommonHeader.XDPEncryptionMode", "Could not convert to valid System.Security.Cryptography.CipherMode enum", oExceptionHelper);
                return false;
            }

            if (String.IsNullOrEmpty(oXDPInternalCommonHeader.XDPSignatureAlgorithm))
            {
                // Send back bad parameter
                HandleBadParameter("XDPInternalCommonHeader.XDPSignatureAlgorithm", "Value was null or empty", oExceptionHelper);
                return false;
            }

            HMAC oHMAC = HMAC.Create(oXDPInternalCommonHeader.XDPSignatureAlgorithm);
            if (null == oHMAC)
            {
                // Send back bad parameter
                HandleBadParameter("XDPInternalCommonHeader.XDPSignatureAlgorithm", "Value was not a valid HMAC", oExceptionHelper);
                return false;
            }
            SignatureKeyLength = oHMAC.HashSize / 8;

            if (null == oXDPInternalCommonHeader.XDPDataSignature)
            {
                // Send back bad parameter
                HandleBadParameter("XDPInternalCommonHeader.XDPDataSignature", "Parameter was null", oExceptionHelper);
                return false;
            }

            if ((oHMAC.HashSize / 8) != oXDPInternalCommonHeader.XDPDataSignature.Length)
            {
                // Send back bad parameter
                HandleBadParameter("XDPInternalCommonHeader.XDPDataSignature", "Value is incorrect length for XDPSignatureAlgorithm", oExceptionHelper);
                return false;
            }

            log.Debug("Exiting " + System.Reflection.MethodInfo.GetCurrentMethod().Name);
            return true;
        }

        /// <summary>
        /// Validates that the oXDPInternalCommonHeader are equal to oCryptoSettings
        /// </summary>
        /// <param name="oXDPInternalCommonHeader"></param>
        /// <param name="oCryptoSettings"></param>
        /// <param name="oExceptionHelper"></param>
        /// <returns></returns>
        internal static bool ValidateCryptoSettings(XDPInternalCommonHeader oXDPInternalCommonHeader, IXDPCryptoSettings oCryptoSettings, XDP.XDPCore.Messages.XDPExceptionHelper oExceptionHelper)
        {
            log.Debug("Entering " + System.Reflection.MethodInfo.GetCurrentMethod().Name);
            // Check if the client XDPInternalCommonHeader matches the Domain Service settings
            if (!oCryptoSettings.EncryptionAlgorithm.Equals(oXDPInternalCommonHeader.XDPEncryptionAlgorithm) ||
                !oCryptoSettings.EncryptionMode.ToString().Equals(oXDPInternalCommonHeader.XDPEncryptionMode) ||
                !oCryptoSettings.SignatureAlgorithm.Equals(oXDPInternalCommonHeader.XDPSignatureAlgorithm))
            {
                // Something didn't match.  Send back an XDPUpdateCommonHeader exception response.
                oXDPInternalCommonHeader.XDPEncryptionAlgorithm = oCryptoSettings.EncryptionAlgorithm;
                oXDPInternalCommonHeader.XDPEncryptionMode = oCryptoSettings.EncryptionMode.ToString();
                oXDPInternalCommonHeader.XDPSignatureAlgorithm = oCryptoSettings.SignatureAlgorithm;
                XDP.XDPCore.Messages.XDPExceptionXDPUpdateCommonHeader oUpdateException = new XDP.XDPCore.Messages.XDPExceptionXDPUpdateCommonHeader();
                oUpdateException.XDPInternalCommonHeader = oXDPInternalCommonHeader;
                oExceptionHelper.SendException(oUpdateException, XDP.XDPCore.Messages.XDPExceptionType.XDPUpdateCommonHeader);
                return false;
            }
            log.Debug("Exiting " + System.Reflection.MethodInfo.GetCurrentMethod().Name);
            return true;
        }
    }
}
