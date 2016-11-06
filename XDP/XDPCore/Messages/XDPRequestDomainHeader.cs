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
using log4net;
using XDP.XDPCore.DataFormat.V1;
using XDP.XDPCore.Settings;

namespace XDP.XDPCore.Messages
{
    [System.SerializableAttribute()]
    [System.Xml.Serialization.XmlTypeAttribute(Namespace = "urn:com.XDP.XDPMessages")]
    [System.Xml.Serialization.XmlRootAttribute(Namespace = "urn:com.XDP.XDPMessages", IsNullable = false)]
    public class XDPRequestDomainHeader
    {
        private static readonly ILog log = LogManager.GetLogger(typeof(XDPRequestDomainHeader));

        XDPInternalCommonHeader m_oXDPInternalCommonHeader;
        XDPAuthorizedIdentities m_oXDPAuthorizedIdentities;
        XDPKeys m_oXDPKeys;

        [System.Xml.Serialization.XmlElementAttribute(Namespace = "urn:com.XDP.XDPData")]
        public XDPInternalCommonHeader XDPInternalCommonHeader
        {
            get { return m_oXDPInternalCommonHeader; }
            set { m_oXDPInternalCommonHeader = value; }
        }

        [System.Xml.Serialization.XmlElementAttribute(Namespace = "urn:com.XDP.XDPData")]
        public XDPAuthorizedIdentities XDPAuthorizedIdentities
        {
            get { return m_oXDPAuthorizedIdentities; }
            set { m_oXDPAuthorizedIdentities = value; }
        }

        public XDPKeys XDPKeys
        {
            get { return m_oXDPKeys; }
            set { m_oXDPKeys = value; }
        }

        /// <summary>
        /// Validates XDPRequestDomainHeader
        /// </summary>
        /// <param name="oXDPRequestDomainHeader"></param>
        /// <returns></returns>
        internal bool Validate(XDPRequestDomainHeader oXDPRequestDomainHeader, XDPExceptionHelper oExceptionHelper)
        {
            log.Debug("Entering " + System.Reflection.MethodInfo.GetCurrentMethod().Name);

            if (!XDPAuthorizedIdentities.Validate(oXDPRequestDomainHeader.XDPAuthorizedIdentities, oExceptionHelper))
                return false;

            int EncryptionKeyLength = 0;
            int SignatureKeyLength = 0;
            if (!XDPInternalCommonHeader.Validate(oXDPRequestDomainHeader.XDPInternalCommonHeader, oExceptionHelper, out EncryptionKeyLength, out SignatureKeyLength))
                return false;

            if (!XDPKeys.Validate(oXDPRequestDomainHeader.XDPKeys, oExceptionHelper, EncryptionKeyLength, SignatureKeyLength))
                return false;

            log.Debug("Exiting " + System.Reflection.MethodInfo.GetCurrentMethod().Name);
            return true;
        }

        internal bool ValidateCryptoSettings(IXDPCryptoSettings oCryptoSettings, XDPExceptionHelper oExceptionHelper)
        {
            return XDPInternalCommonHeader.ValidateCryptoSettings(XDPInternalCommonHeader, oCryptoSettings, oExceptionHelper);
        }
    }
}
