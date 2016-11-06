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

namespace XDP.XDPCore.Settings
{
    public interface IXDPCryptoSettings
    {
        string EncryptionAlgorithm { get; set; }
        CipherMode EncryptionMode { get; set; }
        string SignatureAlgorithm { get; set; }
    }

    internal class XDPCryptoSettings : IXDPCryptoSettings
    {
        private const string DEFAULT_ENCRYPTION_ALGORITHM = "AesManaged";
        private const CipherMode DEFAULT_ENCRYPTION_MODE = CipherMode.CBC;
        private const string DEFAULT_SIGNATURE_ALGORITHM = "HMACSHA256";
        
        private SettingsStore m_oStore;
        private const string ENCRYPTION_ALGORITHM = "Encryption Algorithm";
        private const string ENCRYPTION_MODE = "Encryption Mode";
        private const string SIGNATURE_ALGORITHM = "Signature Algorithm";
        string m_EncryptionAlgorithm;
        CipherMode m_EncryptionMode;
        string m_SignatureAlgorithm;

        public XDPCryptoSettings()
        {
            m_oStore = new SettingsStore("XDP");
        }

        public XDPCryptoSettings(string EncryptionAlgorithm, CipherMode EncryptionMode, string SignatureAlgorithm) : this()
        {
            m_EncryptionAlgorithm = EncryptionAlgorithm;
            m_EncryptionMode = EncryptionMode;
            m_SignatureAlgorithm = SignatureAlgorithm;
        }

        /// <summary>
        /// The symmetric encryption algorithm used to encrypt data
        /// </summary>
        public string EncryptionAlgorithm
        {
            get { return m_oStore.GetStringValue(ENCRYPTION_ALGORITHM, DEFAULT_ENCRYPTION_ALGORITHM); }
            set
            {
                m_oStore.SetStringValue(ENCRYPTION_ALGORITHM, value);
            }
        }

        /// <summary>
        /// The mode the EncryptionAlgorithm
        /// </summary>
        public CipherMode EncryptionMode
        {
            get 
            {
                try
                {
                    return (CipherMode)Enum.Parse(typeof(CipherMode), m_oStore.GetStringValue(ENCRYPTION_MODE, DEFAULT_ENCRYPTION_MODE.ToString()));
                }
                catch { }
                return DEFAULT_ENCRYPTION_MODE;
            }
            set
            {
                m_oStore.SetStringValue(ENCRYPTION_MODE, value.ToString());
            }
        }

        /// <summary>
        /// The symmetric signature algorithmused to sign data
        /// </summary>
        public string SignatureAlgorithm
        {
            get { return m_oStore.GetStringValue(SIGNATURE_ALGORITHM, DEFAULT_SIGNATURE_ALGORITHM); }
            set
            {
                m_oStore.SetStringValue(SIGNATURE_ALGORITHM, value);
            }
        }

    }
}
