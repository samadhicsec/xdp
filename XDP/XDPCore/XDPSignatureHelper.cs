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
using XDP.XDPCore.Settings;

namespace XDP.XDPCore
{
    /// <summary>
    /// The specified signature algorithm could not be created
    /// </summary>
    internal class XDPBadSignatureAlgorithmException : XDPException 
    {
        public XDPBadSignatureAlgorithmException(String message) : base(message) { }
    }

    /// <summary>
    /// The specified signature key provided was the wrong size
    /// </summary>
    internal class XDPBadSignatureKeyException : XDPException
    {
        public XDPBadSignatureKeyException(String message) : base(message) { }
    }

    internal class XDPSignatureHelper : IDisposable
    {
        private byte[] m_SignatureKey;
        private HMAC m_oHMAC;

        /// <summary>
        /// Signs data using a randomly generated key and according to supplied XDPCryptoSettings
        /// </summary>
        internal XDPSignatureHelper(IXDPCryptoSettings oCryptoSettings)
        {
            // Check we can create signature algorithm
            m_oHMAC = HMAC.Create(oCryptoSettings.SignatureAlgorithm);
            if (null == m_oHMAC)
                throw new XDPBadSignatureAlgorithmException("Could not create signture algorithm '" + oCryptoSettings.SignatureAlgorithm + "'");

            // Create random key for the signature algorithm.  The key should be the same size as the block size of the underlying hash function
            RNGCryptoServiceProvider oGen = new RNGCryptoServiceProvider();
            m_SignatureKey = new byte[m_oHMAC.HashSize / 8];
            oGen.GetBytes(m_SignatureKey);
            m_oHMAC.Key = m_SignatureKey;
        }

        /// <summary>
        /// Signs data using the provided key and according to supplied XDPCryptoSettings
        /// </summary>
        internal XDPSignatureHelper(IXDPCryptoSettings oCryptoSettings, byte[] SignatureKey)
            : this(oCryptoSettings)
        {
            // Check the key is the right size
            if (SignatureKey.Length != m_SignatureKey.Length)
                throw new XDPBadSignatureKeyException("The signature key was the wrong size, it was " + SignatureKey.Length + " bytes instead of " + m_SignatureKey.Length);

            Array.Copy(SignatureKey, m_SignatureKey, SignatureKey.Length);
            m_oHMAC.Key = m_SignatureKey;
        }

        /// <summary>
        /// Sign DataIn using the randomly generated SignatureKey
        /// </summary>
        /// <param name="DataIn">The data to be signed</param>
        /// <returns>The signature</returns>
        internal byte[] Sign(byte[] DataIn)
        {
            if (null == DataIn)
                throw new XDPNullArgumentException("The data to sign cannot be null");
            if (DataIn.Length == 0)
                throw new XDPZeroLengthArrayException("The data to sign cannot be empty");

            m_oHMAC.Initialize();
            byte[] ret = m_oHMAC.ComputeHash(DataIn);
            m_oHMAC.Clear();
            return ret;
        }

        /// <summary>
        /// Signs DataIn and compares the signature to the Signature value parameter
        /// </summary>
        /// <param name="DataIn">The data to sign</param>
        /// <param name="Signature">The signature to compare to</param>
        /// <returns>True if the signture verifies, false otherwise</returns>
        internal bool Verify(byte[] DataIn, byte[] Signature)
        {
            byte[] ComputedSignature = Sign(DataIn);
            if (ComputedSignature.Length != Signature.Length)
                return false;
            for (int i = 0; i < Signature.Length; i++)
            {
                if (ComputedSignature[i] != Signature[i])
                    return false;
            }
            return true;
        }

        /// <summary>
        /// The key used to Sign
        /// </summary>
        internal byte[] SignatureKey
        {
            get { return m_SignatureKey; }
        }

        #region IDisposable Members

        public void Dispose()
        {
            if (m_oHMAC != null)
            {
                m_oHMAC.Clear();
                m_oHMAC = null;
            }
            if (null != m_SignatureKey)
            {
                // This is a token effort to zero out the signature key.  It is not fixed so GC could have made multiply copies.
                // We make no guarantees about security on the machine that encrypts (largely because an admin attacker will always win).
                for (int i = 0; i < m_SignatureKey.Length; i++)
                    m_SignatureKey[i] = 0;
            }
        }

        #endregion
    }
}
