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

namespace XDP.XDPCore.DataFormat.V1
{
    [System.SerializableAttribute()]
    [System.Xml.Serialization.XmlTypeAttribute(AnonymousType = true, Namespace = "urn:com.XDP.XDPMessages")]
    [System.Xml.Serialization.XmlRootAttribute(Namespace = "urn:com.XDP.XDPMessages", IsNullable = false)]
    public class XDPKeys : XDP.XDPCore.DataFormat.IXDPKeys, IDisposable
    {

        private byte[] XDPEncryptionKeyField;
        private byte[] XDPEncryptionIVField;
        private byte[] XDPSignatureKeyField;

        /// <remarks/>
        [System.Xml.Serialization.XmlElementAttribute(DataType = "hexBinary")]
        public byte[] XDPEncryptionKey
        {
            get
            {
                return this.XDPEncryptionKeyField;
            }
            set
            {
                XDPEncryptionKeyField = new byte[value.Length];
                Array.Copy(value, XDPEncryptionKeyField, value.Length);
            }
        }

        /// <remarks/>
        [System.Xml.Serialization.XmlIgnore]
        public byte[] XDPEncryptionIV
        {
            get
            {
                return this.XDPEncryptionIVField;
            }
            set
            {
                XDPEncryptionIVField = new byte[value.Length];
                Array.Copy(value, XDPEncryptionIVField, value.Length);
            }
        }

        /// <remarks/>
        [System.Xml.Serialization.XmlElementAttribute(DataType = "hexBinary")]
        public byte[] XDPSignatureKey
        {
            get
            {
                return this.XDPSignatureKeyField;
            }
            set
            {
                XDPSignatureKeyField = new byte[value.Length];
                Array.Copy(value, XDPSignatureKeyField, value.Length); ;
            }
        }

        #region IDisposable Members

        public void Dispose()
        {
            if (null != XDPEncryptionKeyField)
            {
                // This is a token effort to zero out the encryption key.  It is not fixed so GC could have made multiply copies.
                // We make no guarantees about security on the machine that encrypts (largely because an admin attacker will always win).
                XDPCommon.Zero(XDPEncryptionKeyField);
            }
            if (null != XDPSignatureKeyField)
            {
                // This is a token effort to zero out the signature key.  It is not fixed so GC could have made multiply copies.
                // We make no guarantees about security on the machine that encrypts (largely because an admin attacker will always win).
                XDPCommon.Zero(XDPSignatureKeyField);
            }
        }

        #endregion

        /// <summary>
        /// Validates that the values of XDPKeys are not null or empty
        /// </summary>
        /// <param name="oXDPKeys"></param>
        /// <returns></returns>
        internal static bool Validate(IXDPKeys oXDPKeys, XDP.XDPCore.Messages.XDPExceptionHelper oExceptionHelper, int EncryptionKeyLength, int SignatureKeyLength)
        {
            if (null == oXDPKeys)
            {
                // Send back bad parameter
                oExceptionHelper.SendBadParameterException("XDPKeys", "Parameter was null");
                return false;
            }

            if (null == oXDPKeys.XDPEncryptionKey)
            {
                // Send back bad parameter
                oExceptionHelper.SendBadParameterException("XDPKeys.XDPEncryptionKey", "Parameter was null");
                return false;
            }

            if (EncryptionKeyLength != oXDPKeys.XDPEncryptionKey.Length)
            {
                // Send back bad parameter
                oExceptionHelper.SendBadParameterException("XDPKeys.XDPEncryptionKey", "Value is incorrect length for XDPEncryptionAlgorithm");
                return false;
            }

            if (null == oXDPKeys.XDPSignatureKey)
            {
                // Send back bad parameter
                oExceptionHelper.SendBadParameterException("XDPKeys.XDPSignatureKey", "Parameter was null");
                return false;
            }

            if (SignatureKeyLength != oXDPKeys.XDPSignatureKey.Length)
            {
                // Send back bad parameter
                oExceptionHelper.SendBadParameterException("XDPKeys.XDPSignatureKey", "Value is incorrect length for XDPSignatureAlgorithm");
                return false;
            }

            return true;
        }

    }
}
