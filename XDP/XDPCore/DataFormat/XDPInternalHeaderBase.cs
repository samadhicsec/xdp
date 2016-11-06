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

namespace XDP.XDPCore.DataFormat
{
    [System.SerializableAttribute()]
    [System.Xml.Serialization.XmlInclude(typeof(XDP.XDPCore.DataFormat.V1.XDPInternalHeaderV1))]
    public abstract class XDPInternalHeaderBase : IXDPInternalHeader
    {

        #region IXDPInternalHeader Members

        public abstract IXDPKeys KeyStore
        {
            get;
        }

        public abstract void Populate(byte[] DataSignature, XDP.XDPCore.Identity.MachineIdentityHelper oIdentityHelper);

        public abstract void GetDecryptionParameters(out XDP.XDPCore.Settings.IXDPCryptoSettings oCryptoSettings, out byte[] DataSignature);

        public abstract void Validate();

        #endregion
    }
}
