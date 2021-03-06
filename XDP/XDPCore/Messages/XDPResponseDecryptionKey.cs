﻿/*
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
using System.Security.Cryptography;
using XDP.XDPCore.DataFormat.V1;

namespace XDP.XDPCore.Messages
{
    [System.SerializableAttribute()]
    [System.Xml.Serialization.XmlTypeAttribute(Namespace = "urn:com.XDP.XDPMessages")]
    [System.Xml.Serialization.XmlRootAttribute(Namespace = "urn:com.XDP.XDPMessages", IsNullable = false)]
    public class XDPResponseDecryptionKey
    {
        XDPKeys m_oXDPKeys;

        public XDPKeys XDPKeys
        {
            get { return m_oXDPKeys; }
            set { m_oXDPKeys = value; }
        }

        public void CreateResponse(XDPRequestDecryptionKey oXDPRequestDecryptionKey)
        {
            m_oXDPKeys = XDPCommon.DeserializeFromXml<XDPKeys>(ProtectedData.Unprotect(oXDPRequestDecryptionKey.XDPInternalDomainHeader.XDPEncryptedKeys, null, DataProtectionScope.CurrentUser));
        }
    }
}
