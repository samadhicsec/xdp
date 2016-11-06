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
using System.IO;
using System.Security.Cryptography;
using log4net;
using XDP.XDPCore.Settings;

namespace XDP.XDPCore
{
    /// <summary>
    /// The specified symmetric encryption algorithm could not be created
    /// </summary>
    internal class XDPBadEncryptionAlgorithmException : XDPException
    {
        public XDPBadEncryptionAlgorithmException(String message) : base(message) { }
    }

    /// <summary>
    /// Encrypts data using a randomly generated key and according to supplied XDPCryptoSettings
    /// </summary>
    internal class XDPEncryptionHelper : IDisposable
    {
        private static readonly ILog log = LogManager.GetLogger(typeof(XDPEncryptionHelper));
        private byte[] m_EncryptionKey;
        private byte[] m_IV;
        private SymmetricAlgorithm m_oSymmetricAlgorithm;

        /// <summary>
        /// Due to some wierdness in .Net, you cannot seem to create some symmetric ciphers using
        /// SymmetricAlgorithm.Create.  This method wraps that call to fix the problem
        /// </summary>
        /// <param name="AlgName"></param>
        /// <returns></returns>
        internal static SymmetricAlgorithm CreateSymmetricAlgorithm(string AlgName)
        {
            if (AlgName.Equals("AesManaged"))
            {
                return new AesManaged();
            }
            else if (AlgName.Equals("AesCryptoServiceProvider"))
            {
                return new AesCryptoServiceProvider();
            }
            return SymmetricAlgorithm.Create(AlgName);
        }

        internal XDPEncryptionHelper(IXDPCryptoSettings oCryptoSettings)
        {
            //m_oSymmetricAlgorithm = SymmetricAlgorithm.Create(oCryptoSettings.EncryptionAlgorithm);
            m_oSymmetricAlgorithm = XDPEncryptionHelper.CreateSymmetricAlgorithm(oCryptoSettings.EncryptionAlgorithm);
            //m_oSymmetricAlgorithm = SymmetricAlgorithm.Create();
            if (null == m_oSymmetricAlgorithm)
                throw new XDPBadEncryptionAlgorithmException("Could not create encryption algorithm '" + oCryptoSettings.EncryptionAlgorithm + "'");

            m_oSymmetricAlgorithm.Mode = oCryptoSettings.EncryptionMode;
            log.Debug("Using " + m_oSymmetricAlgorithm.GetType().Name + " in " + oCryptoSettings.EncryptionMode.ToString() + " mode");

            RNGCryptoServiceProvider oGen = new RNGCryptoServiceProvider();
            // Create random key for the encryption algorithm.
            m_EncryptionKey = new byte[m_oSymmetricAlgorithm.KeySize / 8];
            oGen.GetBytes(m_EncryptionKey);
            m_oSymmetricAlgorithm.Key = m_EncryptionKey;
            // Create a random IV
            m_IV = new byte[m_oSymmetricAlgorithm.BlockSize / 8];
            oGen.GetBytes(m_IV);
            m_oSymmetricAlgorithm.IV = m_IV;
        }

        internal XDPEncryptionHelper(IXDPCryptoSettings oCryptoSettings, byte[] EncryptionKey, byte[] EncryptionIV)
            : this(oCryptoSettings)
        {
            m_EncryptionKey = new byte[EncryptionKey.Length];
            Array.Copy(EncryptionKey, m_EncryptionKey, EncryptionKey.Length);
            m_IV = new byte[EncryptionIV.Length];
            Array.Copy(EncryptionIV, m_IV, EncryptionIV.Length);
            m_oSymmetricAlgorithm.Key = m_EncryptionKey;
            m_oSymmetricAlgorithm.IV = m_IV;
        }

        /// <summary>
        /// Encrypt DataIn using the randomly generated EncryptionKey
        /// </summary>
        /// <param name="DataIn"></param>
        /// <returns></returns>
        internal byte[] Encrypt(byte[] DataIn)
        {
            if (null == DataIn)
                throw new XDPNullArgumentException("The data to encrypt cannot be null");
            if (DataIn.Length == 0)
                throw new XDPZeroLengthArrayException("The data to encrypt cannot be empty");

            m_oSymmetricAlgorithm.Padding = PaddingMode.PKCS7;

            // Create the destination for the encrypted data
            MemoryStream DataOutStream = new MemoryStream();
            // Create the stream to write DataIn
            CryptoStream oCryptoStream = new CryptoStream(DataOutStream, m_oSymmetricAlgorithm.CreateEncryptor(), CryptoStreamMode.Write);
            try
            {
                // Encrypt
                oCryptoStream.Write(DataIn, 0, DataIn.Length);
            }
            finally
            {
                oCryptoStream.Close();
            }

            return DataOutStream.ToArray();
        }

        /// <summary>
        /// Decrypt DataIn using the current EncryptionKey
        /// </summary>
        /// <param name="DataIn"></param>
        /// <returns></returns>
        internal byte[] Decrypt(byte[] DataIn)
        {
            if (null == DataIn)
                throw new XDPNullArgumentException("The data to encrypt cannot be null");
            if (DataIn.Length == 0)
                throw new XDPZeroLengthArrayException("The data to encrypt cannot be empty");

            m_oSymmetricAlgorithm.Padding = PaddingMode.PKCS7;

            // Create the destination for the decrypted data
            MemoryStream DataOutStream = new MemoryStream();
            // Create the stream to write DataIn
            CryptoStream oCryptoStream = new CryptoStream(DataOutStream, m_oSymmetricAlgorithm.CreateDecryptor(), CryptoStreamMode.Write);
            try
            {
                // Decrypt
                oCryptoStream.Write(DataIn, 0, DataIn.Length);
            }
            finally
            {
                oCryptoStream.Close();
            }

            byte[] ret = DataOutStream.ToArray();
            XDPCommon.Zero(DataOutStream);
            return ret;
        }

        /// <summary>
        /// The key used for Encryption
        /// </summary>
        internal byte[] EncryptionKey
        {
            get { return m_EncryptionKey; }
        }

        /// <summary>
        /// The IV used for Encryption
        /// </summary>
        internal byte[] IV
        {
            get { return m_IV; }
        }

        #region IDisposable Members

        public void Dispose()
        {
            if (null != m_oSymmetricAlgorithm)
            {
                m_oSymmetricAlgorithm.Clear();
            }
            if (null != m_EncryptionKey)
            {
                // This is a token effort to zero out the encryption key.  It is not fixed so GC could have made multiply copies.
                // We make no guarantees about security on the machine that encrypts (largely because an admin attacker will always win).
                for (int i = 0; i < m_EncryptionKey.Length; i++)
                    m_EncryptionKey[i] = 0;
            }
        }

        #endregion
    }
}
