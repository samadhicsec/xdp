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
using System.Text;
using System.Threading;
using log4net;
using XDP.XDPCore.Identity;
using XDP.XDPCore.Settings;

namespace XDP.XDPCore.DataFormat
{
    internal class XDPInvalidFormatExcepton : XDPException
    {
        public XDPInvalidFormatExcepton(string message) : base(message) {}
    }

    internal class XDPData
    {
        private static readonly ILog log = LogManager.GetLogger(typeof(XDPData));
        private enum State
        {
            Unpopulated,
            Populated
        };

        private enum eFlags
        {
            None = 0x00,
            DataCompression = 0x01,
            HeaderCompression = 0x02,
        }

        private IDataFormatFactory m_oDFFactory;
        private State m_State = State.Unpopulated;
        private byte[] m_DataIn;
        private eFlags m_Flags;
        private string[] m_AuthorizedIdentities;
        private IXDPMachineSettings m_oSettings;
        private XDPHeader m_oHeader;
        byte[] m_oCiphertext = null;

        public XDPData(IDataFormatFactory oDFFactory)
        {
            m_oDFFactory = oDFFactory;
            m_State = State.Unpopulated;
        }

        protected virtual IXDPMachineSettings CreateMachineSettings()
        {
            return new XDPMachineSettings();
        }

        /// <summary>
        /// Encrypt DataIn so only the users or groups listed in AuthorizedIdentiiesareable to decrypt
        /// </summary>
        /// <param name="DataIn">The data to encrypt</param>
        /// <param name="AuthorizedIdentiies">The local machine or domain users or groups authorized to decrypt.  Duplicates are allowed and will be removed.</param>
        public void Encrypt(byte[] DataIn, string[] AuthorizedIdentities)
        {
            log.Debug("Entering " + System.Reflection.MethodInfo.GetCurrentMethod().Name);
            m_State = State.Unpopulated;
            m_Flags = eFlags.None;

            // Throw exception if DataIn or AuthorizedIdentities is null
            if (null == DataIn)
                throw new XDPNullArgumentException("DataIn cannot be null");
            if (null == AuthorizedIdentities)
                throw new XDPNullArgumentException("AuthorizedIdentiies cannot be null");
            if(0 == AuthorizedIdentities.Length)
                throw new XDPZeroLengthArrayException("AuthorizedIdentiies cannot be empty");

            m_DataIn = new byte[DataIn.Length];
            Array.Copy(DataIn, m_DataIn, DataIn.Length);

            m_AuthorizedIdentities = new string[AuthorizedIdentities.Length];
            Array.Copy(AuthorizedIdentities, m_AuthorizedIdentities, AuthorizedIdentities.Length);

            // Get the XDP Settings
            m_oSettings = CreateMachineSettings();

            // Bucket AuthorizedIdentities according to hostname
            MachineIdentityHelper oIdentityHelper = new MachineIdentityHelper();
            oIdentityHelper.AddIdentites(m_AuthorizedIdentities);

            // Get current user
            System.Security.Principal.SecurityIdentifier oCurrentUserSid = null;
            string CurrentUserDomainName = String.Empty;
            string CurrentUserMachineName = String.Empty;
            IdentityHelper.GetCurrentUser(out oCurrentUserSid, out CurrentUserDomainName, out CurrentUserMachineName);
            log.DebugFormat("Current User - Sid = {0}, Domain Name = {1}, Machine Name = {2}", oCurrentUserSid, CurrentUserDomainName, CurrentUserMachineName);

            // Specifically we are not going to add the caller to the list of AuthorizedIdentities or make this a setting.  This is a high level decision for the caller
            // to make, and it's easy for them to add.

            // TEST  A local user cannot encrypt to domain identites.  If the XDPMachineService is running as a LocalUser and so is the caller, then we cannot
            // create a Kerberos connection to the XDPDomainService.
            if (!String.IsNullOrEmpty(CurrentUserMachineName) && (oIdentityHelper.DomainIdentities.Count > 0))
                throw new XDPException("Local Users cannot encrypt to Domain accounts.  A local user is unable to create a secure connection to the XDP Domain Service.");

            int SettingsUpdatedCount = 0;
            // We may need to repeat these actions if the XDP Domain Service updates the crypto settings
            do
            {
                try
                {
                    // Create XDPHeader
                    m_oHeader = new XDPHeader();
                    // Create the XDPInternalHeader
                    m_oHeader.XDPInternalHeader = (XDPInternalHeaderBase)m_oDFFactory.CreateInternalHeader(m_oSettings);

                    // To avoid even the possibility of an infinite loop, limit the number of times we loop due to crypto settings being updated
                    if (SettingsUpdatedCount > 5)
                        throw new XDPException("XDP Domain Service asked for certain settings to be updated 5 times in a row.  Please restart the XDP Domain Sevice or seek support.");

                    #region Create Signature
                    log.Debug("Initiating signature creation");
                    AutoResetEvent signatureWaitHandle = new AutoResetEvent(false);
                    Exception SigException = null;
                    
                    byte[] oSignature = null;
                    //Perform signature in a worker thread
                    ThreadPool.QueueUserWorkItem(new WaitCallback(
                        delegate(object o)
                        {
                            try
                            {
                                // Generate the Signature key and sign DataIn
                                using (XDPSignatureHelper oXDPSignatureHelper = new XDPSignatureHelper(m_oSettings.CryptoSettings))
                                {
                                    oSignature = oXDPSignatureHelper.Sign(m_DataIn);
                                    m_oHeader.XDPInternalHeader.KeyStore.XDPSignatureKey = oXDPSignatureHelper.SignatureKey;
                                }
                            }
                            catch (Exception ex)
                            {
                                SigException = ex;
                            }
                            signatureWaitHandle.Set();
                        }
                    ));
                    #endregion

                    #region Create Ciphertext
                    log.Debug("Initiating ciphertext creation");
                    AutoResetEvent encryptionWaitHandle = new AutoResetEvent(false);
                    Exception EncException = null;
                    // Perform the compression and encryption in a worker thread
                    ThreadPool.QueueUserWorkItem(new WaitCallback(
                        delegate(object o)
                        {
                            try
                            {
                                // Generate the Encryption key and encrypt DataIn
                                using (XDPEncryptionHelper oXDPEncryptionHelper = new XDPEncryptionHelper(m_oSettings.CryptoSettings))
                                {
                                    // We cannot create XDPHeader until we have set oXDPKeys.XDPEncryptionKey and oXDPKeys.XDPEncryptionIV, so do this ASAP
                                    m_oHeader.XDPInternalHeader.KeyStore.XDPEncryptionKey = oXDPEncryptionHelper.EncryptionKey;
                                    m_oHeader.XDPInternalHeader.KeyStore.XDPEncryptionIV = oXDPEncryptionHelper.IV;

                                    byte[] DataToEncrypt = m_DataIn;
                                    // Compress data if its longer than a sensible length
                                    if (DataToEncrypt.Length > 200)
                                    {
                                        log.Debug("Compressing data before encrypting");
                                        m_Flags = m_Flags | eFlags.DataCompression;
                                        DataToEncrypt = XDPCommon.Compress(DataToEncrypt, true);
                                    }

                                    // TEST creating XDPHeader requires EncryptionIV to exist, currently it is being referenced before this thread creates it
                                    m_oCiphertext = oXDPEncryptionHelper.Encrypt(DataToEncrypt);
                                    
                                }
                            }
                            catch (Exception ex)
                            {
                                EncException = ex;
                            }
                            encryptionWaitHandle.Set();
                        }
                    ));
                    #endregion

                    // We need the signature to have finished before we can finish creating the header
                    signatureWaitHandle.WaitOne();
                    // Rethrow any exception that occurred during signature generation
                    if (null != SigException)
                        throw SigException;
                    log.Debug("Signature created successfully");

                    // We need to wait for the XDPEncryptionKey and XDPEncryptionIV to finish being generated (in the encryption thread) before we can create the header
                    int GenerateEncParamsTimeoutCount = 0;
                    const int GenerateEncParamsSleepTimeMilliSecs = 10;
                    const int GenerateEncParamsTimeoutCountMax = 30000 / GenerateEncParamsSleepTimeMilliSecs;   // Timeout after 30 seconds
                    while (((null == m_oHeader.XDPInternalHeader.KeyStore.XDPEncryptionKey) || (null == m_oHeader.XDPInternalHeader.KeyStore.XDPEncryptionIV)) && 
                        (GenerateEncParamsTimeoutCount < GenerateEncParamsTimeoutCountMax))
                    {
                        Thread.Sleep(GenerateEncParamsSleepTimeMilliSecs);
                        // If an exception was thrown during encryption, we might loop forever
                        if (null != EncException)
                            throw EncException;
                        GenerateEncParamsTimeoutCount++;
                    }
                    if (GenerateEncParamsTimeoutCount > GenerateEncParamsTimeoutCountMax)
                        throw new XDPException("Either the encryption key or IV could not be created in a timely fashion");
                    
                    // Now that we have the signature value and all the keys created, populate the rest of the version specific internal header
                    m_oHeader.XDPInternalHeader.Populate(oSignature, oIdentityHelper);

                    // Wait on the encryption to finish
                    encryptionWaitHandle.WaitOne();
                    // Rethrow any exception that occurred during encryption
                    if (null != EncException)
                        throw EncException;
                    log.Debug("Ciphertext created successfully");
                
                }
                catch (XDPUpdatedSettingsException)
                {
                    log.Info("XDP settings were updated, retrying encryption");
                    // Keep track of how many times the XDP Domain Service is telling us to update out settings
                    SettingsUpdatedCount++;
                    // Start again
                    continue;
                }
            }
            while (false);

            m_State = State.Populated;
            log.Debug("Exiting " + System.Reflection.MethodInfo.GetCurrentMethod().Name);
        }

        /// <summary>
        /// Serialise XDPData to a byte array
        /// </summary>
        /// <returns></returns>
        public byte[] Serialize()
        {
            log.Debug("Entering " + System.Reflection.MethodInfo.GetCurrentMethod().Name);
            // If not in state Populated throw an error
            if (m_State != State.Populated)
                throw new XDPBadStateException("Encrypt must be called before Serialise");

            // Serialise the magic bytes            
            byte[] MagicBytes = ASCIIEncoding.ASCII.GetBytes("XDP");
            // Serialise the XDPHeader
            byte[] SerialisedXDPHeader = XDPCommon.SerializeToXml(m_oHeader, "urn:com.XDP.XDPData");
            // If SerialisedXDPHeader.Length > 200 bytes (200 was determined experimentally), then we should compress it
            if (SerialisedXDPHeader.Length > 200)
            {
                m_Flags |= eFlags.HeaderCompression;
                SerialisedXDPHeader = XDPCommon.Compress(SerialisedXDPHeader, false);
            }
            // Serialise the XDPHeader length
            byte[] SerialisedXDPHeaderLength = BitConverter.GetBytes(SerialisedXDPHeader.Length);

            int offset = 0;
            byte[] SerialisedData = new byte[MagicBytes.Length + 1 + SerialisedXDPHeaderLength.Length + SerialisedXDPHeader.Length + m_oCiphertext.Length];
            // Copy serialised data to an XDPData blob
            Buffer.BlockCopy(MagicBytes, 0, SerialisedData, offset, MagicBytes.Length);
            offset += MagicBytes.Length;
            SerialisedData[offset++] = ((byte)m_Flags);
            Buffer.BlockCopy(SerialisedXDPHeaderLength, 0, SerialisedData, offset, SerialisedXDPHeaderLength.Length);
            offset += SerialisedXDPHeaderLength.Length;
            Buffer.BlockCopy(SerialisedXDPHeader, 0, SerialisedData, offset, SerialisedXDPHeader.Length);
            offset += SerialisedXDPHeader.Length;
            Buffer.BlockCopy(m_oCiphertext, 0, SerialisedData, offset, m_oCiphertext.Length);

            log.Debug("Exiting " + System.Reflection.MethodInfo.GetCurrentMethod().Name);
            return SerialisedData;
        }

        /// <summary>
        /// Deserializes a block of XDPData so that the message inside can be decrypted
        /// </summary>
        /// <param name="DataOut"></param>
        public void Deserialize(byte[] DataOut)
        {
            log.Debug("Entering " + System.Reflection.MethodInfo.GetCurrentMethod().Name);
            m_oCiphertext = null;
            m_Flags = (byte)eFlags.None;
            m_oHeader = null;
            m_State = State.Unpopulated;

            // Validate the input buffer
            if (null == DataOut)
                throw new XDPNullArgumentException("DataOut cannot be null");
            if (0 == DataOut.Length)
                throw new XDPZeroLengthArrayException("DataOut cannot have zero length");
            // We need more than 8, but it is a minimum to read the SerialisedHeader Length
            if (DataOut.Length < 8)
                throw new XDPInvalidFormatExcepton("DataOut must be at least 8 bytes");
            // Check the magic bytes
            byte[] MagicBytes = ASCIIEncoding.ASCII.GetBytes("XDP");
            if ((MagicBytes[0] != DataOut[0]) || (MagicBytes[1] != DataOut[1]) || (MagicBytes[2] != DataOut[2]))
                throw new XDPInvalidFormatExcepton("DataOut did not start with byte sequence 'XDP'");
            // Read the flags
            m_Flags = (eFlags)DataOut[3];
            // Read the header length
            uint SerializedXDPHeaderLength = BitConverter.ToUInt32(DataOut, 4);
            // Check we have enough bytes remaining
            uint DataOutBytesRemaining = (uint)(DataOut.Length - 8);
            if (DataOutBytesRemaining < SerializedXDPHeaderLength)
                throw new XDPInvalidFormatExcepton("The serialized header length is " + SerializedXDPHeaderLength + " but there are only " + DataOutBytesRemaining + " available");
            byte[] SerializedXDPHeader = new byte[SerializedXDPHeaderLength];
            Buffer.BlockCopy(DataOut, 8, SerializedXDPHeader, 0, (int)SerializedXDPHeaderLength);
            // Check the encrypted data is at least 1 byte in length
            DataOutBytesRemaining -= SerializedXDPHeaderLength;
            if(0 == DataOutBytesRemaining)
                throw new XDPZeroLengthArrayException("The length of the encrypted data must be at least 1 byte");

            // Decompress the XDPHeader if it's compressed
            if ((m_Flags & eFlags.HeaderCompression) == eFlags.HeaderCompression)
            {
                SerializedXDPHeader = XDPCommon.Decompress(SerializedXDPHeader, false);
            }

            // Create a copy the ciphertext
            m_oCiphertext = new byte[DataOutBytesRemaining];
            Buffer.BlockCopy(DataOut, (int)(DataOut.Length - DataOutBytesRemaining), m_oCiphertext, 0, (int)DataOutBytesRemaining);

            // Now we are ready to deserialize
            m_oHeader = XDPCommon.DeserializeFromXml<XDPHeader>(SerializedXDPHeader);
            m_oHeader.Validate();

            m_State = State.Populated;
            log.Debug("Exiting " + System.Reflection.MethodInfo.GetCurrentMethod().Name);
        }

        /// <summary>
        /// Attempts to decrypt the ciphertext in XDPData using the privilege of the caller.  If the caller does not have the necessary privilege
        /// an exception is thrown.
        /// </summary>
        /// <returns>The decrypted message</returns>
        public byte[] Decrypt()
        {
            log.Debug("Entering " + System.Reflection.MethodInfo.GetCurrentMethod().Name);
            // If not in state Populated throw an error
            if (m_State != State.Populated)
                throw new XDPBadStateException("Deserialize must be called before Decrypt");

            // Check that we are impersonating a user
            if (null == System.Security.Principal.WindowsIdentity.GetCurrent(true))
                throw new XDPException("Decrypt was called without the current thread impersonating another user.  Decrypt should only be called whilst impersonating the user who can decrypt");

            IXDPCryptoSettings oCryptoSettings = null;
            byte[] DataSignature = null;
            
            m_oHeader.XDPInternalHeader.GetDecryptionParameters(out oCryptoSettings, out DataSignature);

            byte[] DecryptedData = null;
            try
            {
                // If we get here, then the current user is authorised to decrypt and our headers have passed their signature check
                // Decrypt the data
                using (XDPEncryptionHelper oXDPEncryptionHelper = new XDPEncryptionHelper(oCryptoSettings, m_oHeader.XDPInternalHeader.KeyStore.XDPEncryptionKey, m_oHeader.XDPInternalHeader.KeyStore.XDPEncryptionIV))
                {
                    DecryptedData = oXDPEncryptionHelper.Decrypt(m_oCiphertext);
                }
                // Decompress data if Flags indicate compression
                if ((m_Flags & eFlags.DataCompression) == eFlags.DataCompression)
                {
                    byte[] temp = DecryptedData;
                    DecryptedData = XDPCommon.Decompress(DecryptedData, true);
                    XDPCommon.Zero(temp);
                }

                // Verify the signature
                XDPSignatureHelper oSignatureHelper = new XDPSignatureHelper(oCryptoSettings, m_oHeader.XDPInternalHeader.KeyStore.XDPSignatureKey);
                try
                {
                    if (!oSignatureHelper.Verify(DecryptedData, DataSignature))
                    {
                        XDPCommon.Zero(DecryptedData);
                        throw new XDPSignatureVerificationException("The data signature did not verify");
                    }
                }
                finally
                {
                    oSignatureHelper.Dispose();
                }
            }
            finally
            {
                if(null != m_oHeader.XDPInternalHeader.KeyStore)
                    m_oHeader.XDPInternalHeader.KeyStore.Dispose();
            }

            log.Debug("Exiting " + System.Reflection.MethodInfo.GetCurrentMethod().Name);
            return DecryptedData;
        }

    }
}
