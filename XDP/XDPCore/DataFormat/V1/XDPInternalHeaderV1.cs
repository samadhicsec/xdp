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
using System.Collections.Generic;
using System.Security.Principal;
using log4net;
using XDP.XDPCore.Identity;
using XDP.XDPCore.Messages;
using XDP.XDPCore.Messaging;
using XDP.XDPCore.Settings;

namespace XDP.XDPCore.DataFormat.V1
{
    /// <remarks/>
    [System.SerializableAttribute()]
    [System.Xml.Serialization.XmlTypeAttribute(Namespace = "urn:com.XDP.XDPData")]
    public class XDPInternalHeaderV1 : XDP.XDPCore.DataFormat.XDPInternalHeaderBase
    {
        private static readonly ILog log = LogManager.GetLogger(typeof(XDPInternalHeaderV1));
        XDP.XDPCore.Settings.XDPMachineSettings m_oSettings;
        private XDPInternalCommonHeader m_XDPInternalCommonHeaderField;
        private XDPInternalMachineHeader[] m_XDPInternalMachineHeaderField;
        private XDPInternalDomainHeader m_XDPInternalDomainHeaderField;
        private byte[] m_DomainHeaderSignature;
        private XDPInternalHeaderSignatures m_XDPInternalHeaderSignaturesField;

        private Dictionary<Type, MessageProcessorCallback> m_oRequestDomainHeaderResponses;
        private Dictionary<Type, MessageProcessorCallback> m_oRequestDecryptionResponses;
        private XDPKeys m_oXDPKeys;      // Will hold the XDPKeys returned by an XDPResponseDecryptionKeys message

        /// <summary>
        /// Parameterless constructor used for Serialization
        /// </summary>
        public XDPInternalHeaderV1()
        {
            // These dictionaries contain the methods to invoke based on the type of message returned from the server.
            m_oRequestDomainHeaderResponses = new Dictionary<Type, XDP.XDPCore.Messaging.MessageProcessorCallback>() 
            { 
                { typeof(XDPResponseDomainHeader), ProcessXDPResponseDomainHeader },
                { typeof(XDPExceptionResponse), ProcessXDPExceptionResponse }
            };

            m_oRequestDecryptionResponses = new Dictionary<Type, XDP.XDPCore.Messaging.MessageProcessorCallback>() 
            { 
                { typeof(XDPResponseDecryptionKey), ProcessXDPResponseDecryptionKey},
                { typeof(XDPExceptionResponse), ProcessXDPExceptionResponse }
            };
        }

        internal XDPInternalHeaderV1(XDP.XDPCore.Settings.XDPMachineSettings oSettings)
            : this()
        {
            m_oSettings = oSettings;
            m_oXDPKeys = new XDPKeys();
        }

        [System.Xml.Serialization.XmlIgnore()]
        public override IXDPKeys KeyStore
        {
            get
            {
                return m_oXDPKeys;
            }
        }

        public override void Validate()
        {
            log.Debug("Entering " + System.Reflection.MethodInfo.GetCurrentMethod().Name);
            // Check for XDPInternalCommonHeader
            if (null == m_XDPInternalCommonHeaderField)
                throw new XDPInvalidFormatExcepton("No XDPInternalCommonHeader was present");
            int EncryptionKeyLength, SignatureKeyLength;
            XDPInternalCommonHeader.Validate(m_XDPInternalCommonHeaderField, null, out EncryptionKeyLength, out SignatureKeyLength);

            // Check for XDPInternalMachineHeader
            bool bXDPInternalMachineHeaderPresent = false;
            if ((null != m_XDPInternalMachineHeaderField) && (0 != m_XDPInternalMachineHeaderField.Length))
            {
                bXDPInternalMachineHeaderPresent = true;
                if (1 != m_XDPInternalMachineHeaderField.Length)
                    throw new XDPInvalidFormatExcepton("Only 1 XDPInternalMachineHeader is currently allowed");
                m_XDPInternalMachineHeaderField[0].Validate();
            }

            // Check for XDPInternalDomainHeader
            if (null == m_XDPInternalDomainHeaderField)
            {
                // One of XDPInternalMachineHeader or XDPInternalDomainHeader must be present
                if (!bXDPInternalMachineHeaderPresent)
                    throw new XDPInvalidFormatExcepton("Neither XDPInternalMachineHeader nor XDPInternalDomainHeader was present");
            }
            else
            {
                m_XDPInternalDomainHeaderField.Validate();
            }

            // Check for XDPInternalHeaderSignatures
            if (null == m_XDPInternalHeaderSignaturesField)
                throw new XDPInvalidFormatExcepton("No XDPInternalHeaderSignatures was present");
            m_XDPInternalHeaderSignaturesField.Validate(m_XDPInternalMachineHeaderField, m_XDPInternalDomainHeaderField);

            log.Debug("Exiting " + System.Reflection.MethodInfo.GetCurrentMethod().Name);
        }

        public override void Populate(byte[] DataSignature, XDP.XDPCore.Identity.MachineIdentityHelper oIdentityHelper)
        {
            log.Debug("Entering " + System.Reflection.MethodInfo.GetCurrentMethod().Name);
            // Create the InternalCommonHeader
            m_XDPInternalCommonHeaderField = new XDPInternalCommonHeader(m_oSettings.CryptoSettings, m_oXDPKeys, DataSignature);

            // Create the InternalDomainHeader.  This will call out to the XDP Domain Service and return with XDPInternalDomainHeader and XDPInternalHeaderDomainSignature
            if (oIdentityHelper.DomainIdentities.Count > 0)
            {
                // Create XDPRequestDomainHeader
                XDPRequestDomainHeader oXDPRequestDomainHeader = new XDPRequestDomainHeader();
                XDPAuthorizedIdentities oAuthorizedDomainIdentities = new XDPAuthorizedIdentities();
                oAuthorizedDomainIdentities.Identity = oIdentityHelper.DomainIdentities.ToArray();
                oXDPRequestDomainHeader.XDPAuthorizedIdentities = oAuthorizedDomainIdentities;
                oXDPRequestDomainHeader.XDPKeys = m_oXDPKeys;
                oXDPRequestDomainHeader.XDPInternalCommonHeader = m_XDPInternalCommonHeaderField;

                // Make request to XDP Domain Service
                NegotiateClient oNegotiateClient = new NegotiateClient(m_oSettings);
                XDP.XDPCore.Messaging.MessageSender oMessageSender = new XDP.XDPCore.Messaging.MessageSender(oNegotiateClient, oNegotiateClient.Client, oNegotiateClient.Stream);
                byte[] ResponseBytes = oMessageSender.Send(oXDPRequestDomainHeader);
                XDP.XDPCore.Messaging.MessageProcessor oMessageProcessor = new XDP.XDPCore.Messaging.MessageProcessor(m_oRequestDomainHeaderResponses, oMessageSender);
                // All things going well this will call ProcessXDPResponseDomainHeader
                oMessageProcessor.Process(ResponseBytes);
            }

            // We need to create the InternalMachineHeaders as the XDP Machine Service account
            NativeWin32Functions.RevertToSelf();

            // Create the InternalMachineHeaders.  For each host, create a XDPInternalMachineHeader passing in the Authorized Identities.
            List<XDPInternalMachineHeader> oInternalMachineHeaders = new List<XDPInternalMachineHeader>();
            List<XDPInternalHeaderMachineSignature> oRemoteInternalHeaderMachineSignatures = new List<XDPInternalHeaderMachineSignature>();
            XDPInternalMachineHeader oXDPLocalInternalMachineHeader = null;
            foreach(KeyValuePair<string, List<SecurityIdentifier>> oKeyPair in oIdentityHelper.LocalIdentitiesDictionary)
            {
                // Check the Local Identites are for this machine and that there are some Identities in the list
                if (oKeyPair.Key.Equals(Environment.MachineName, StringComparison.InvariantCultureIgnoreCase))
                {
                    if (oKeyPair.Value.Count > 0)
                        oXDPLocalInternalMachineHeader = new XDPInternalMachineHeader(oKeyPair.Key, oKeyPair.Value, m_oXDPKeys);
                    else
                        break;
                }
                else
                {
                    // This is where we would make a call to an XDP Local Service on another machine to generate XDPInternalMachineHeader and XDPInternalHeaderMachineSignature
                    // for that machine
                    throw new XDPException("Can only encrypt to local machine identites currently");
                }

                if (null != oXDPLocalInternalMachineHeader)
                    oInternalMachineHeaders.Add(oXDPLocalInternalMachineHeader);
                else
                    throw new XDPException("Error creating XDPInternalMachineHeader for '" + oKeyPair.Key + "'");
            }

            // Create the InternalHeaderSignatures.
            m_XDPInternalHeaderSignaturesField = new XDPInternalHeaderSignatures(oRemoteInternalHeaderMachineSignatures, m_DomainHeaderSignature);

            if(oInternalMachineHeaders.Count > 0)
            {
                m_XDPInternalMachineHeaderField = oInternalMachineHeaders.ToArray();

                XDPSignatureHelper oSignatureHelper = new XDPSignatureHelper(m_oSettings.CryptoSettings, m_oXDPKeys.XDPSignatureKey);
                // Add the local machine header signture
                m_XDPInternalHeaderSignaturesField.AddLocalMachineHeaderSignature(oSignatureHelper, m_XDPInternalCommonHeaderField, oXDPLocalInternalMachineHeader);
            }
            log.Debug("Exiting " + System.Reflection.MethodInfo.GetCurrentMethod().Name);
        }

        /// <summary>
        /// Process an XDPResponseDomainHeader message from the XDP Domain Service
        /// </summary>
        /// <param name="Message"></param>
        private void ProcessXDPResponseDomainHeader(object Message, MessageSender oMsgSender)
        {
            log.Debug("Entering " + System.Reflection.MethodInfo.GetCurrentMethod().Name);
            XDPResponseDomainHeader oXDPResponseDomainHeader = (XDPResponseDomainHeader)Message;

            m_XDPInternalDomainHeaderField = oXDPResponseDomainHeader.XDPInternalDomainHeader;
            m_DomainHeaderSignature = oXDPResponseDomainHeader.XDPInternalHeaderDomainSignature;
            log.Debug("Exiting " + System.Reflection.MethodInfo.GetCurrentMethod().Name);
        }

        /// <summary>
        /// Verifies the XDPHeader and that the current user has decryption rights, if so it sets XDPCryptoSettings and the XDPKeys.
        /// </summary>
        public override void GetDecryptionParameters(out IXDPCryptoSettings oCryptoSettings, out byte[] DataSignature)
        {
            log.Debug("Entering " + System.Reflection.MethodInfo.GetCurrentMethod().Name);
            String Domainname = String.Empty;
            String Machinename = String.Empty;
            SecurityIdentifier oUser = null;
            oCryptoSettings = null;

            // Get the identity of the caller so we know how to recover the XDPKeys
            IdentityHelper.GetCurrentUser(out oUser, out Domainname, out Machinename);
            log.DebugFormat("Current User - Sid = {0}, Domain Name = {1}, Machine Name = {2}", oUser, Domainname, Machinename);

            if (!String.IsNullOrEmpty(Domainname))
            {
                // Why don't we check if the user is amongst the AuthorizedIdentities before making a network request?
                // The AuthorizedIdentities can include Groups, so we would need to do a group check, and at that stage
                // we are repeating the check the XDPDomainService is going to be doing.

                #region remove
                //// For the sake of efficency, check if the user is amongst the AuthorizedIdentities before makig a network request
                //// Even though the current user is a domain user, that doesn't mean the XDPInternalHeader has a XDPInternalDomainHeader!
                //bool SIDPresent = false;
                //for (int i = 0; (null != m_XDPInternalDomainHeaderField) && (i < m_XDPInternalDomainHeaderField.XDPAuthorizedIdentities.Length); i++)
                //{
                //    string AuthorizedSID = m_XDPInternalDomainHeaderField.XDPAuthorizedIdentities[i];
                //    log.Debug(AuthorizedSID);
                //    if (oUser.ToString().Equals(AuthorizedSID, StringComparison.InvariantCultureIgnoreCase))
                //    {
                //        // User is listed
                //        SIDPresent = true;
                //        break;
                //    }
                //}
                //if (!SIDPresent)
                //{
                //    log.Debug("User is not on list of AuthorizedIdentities");
                //    throw new XDPAuthorizationException("User '" + WindowsIdentity.GetCurrent().Name + "' is not authorized to decrypt");
                //}
                //else
                //    log.Debug("User is on list of AuthorizedIdentities");
                #endregion

                // Create the XDPRequestDecryptionKeys message for the XDP Domain Service
                XDPRequestDecryptionKey oRequestDecryptionKey = new XDPRequestDecryptionKey();
                oRequestDecryptionKey.XDPInternalCommonHeader = m_XDPInternalCommonHeaderField;
                oRequestDecryptionKey.XDPInternalDomainHeader = m_XDPInternalDomainHeaderField;
                oRequestDecryptionKey.XDPInternalHeaderDomainSignature = m_XDPInternalHeaderSignaturesField.XDPInternalHeaderDomainSignature;

                NegotiateClient oNegotiateClient = new NegotiateClient(new XDPMachineSettings());
                XDP.XDPCore.Messaging.MessageSender oRequest = new XDP.XDPCore.Messaging.MessageSender(oNegotiateClient, oNegotiateClient.Client, oNegotiateClient.Stream);
                log.Debug("Sending XDPRequestDecryptionKey to XDPDomainService");
                byte[] oResponse = oRequest.Send(oRequestDecryptionKey);
                XDP.XDPCore.Messaging.MessageProcessor oMessageProcessor = new XDP.XDPCore.Messaging.MessageProcessor(m_oRequestDecryptionResponses, oRequest);
                oMessageProcessor.Process(oResponse);
                
                // Get the CryptoSettings
                oCryptoSettings = m_XDPInternalCommonHeaderField.GetCryptoSettings();

                // The XDPEncryptionIV is not part of the serialized XDPKeys returned from the XDP Domain Service, so set it here with the value in the common header
                m_oXDPKeys.XDPEncryptionIV = m_XDPInternalCommonHeaderField.XDPEncryptionIV;
            }
            else
            {
                XDPKeys oXDPKeys = null;   // Use a local variable so no caller can recover the keys before the signature verification (below) has succeeded
                XDPInternalMachineHeader oMachineHeader = null;
                // Find the machine header for this users machine
                for (int i = 0; (null != m_XDPInternalMachineHeaderField) && (i < m_XDPInternalMachineHeaderField.Length); i++)
                {
                    if (Machinename.Equals(m_XDPInternalMachineHeaderField[i].Hostname, StringComparison.InvariantCultureIgnoreCase))
                    {
                        oMachineHeader = m_XDPInternalMachineHeaderField[i];
                        oXDPKeys = oMachineHeader.GetXDPKeys(oUser);
                        if (null == oXDPKeys)
                            throw new XDPAuthorizationException("Local user with SID '" + oUser.ToString() + "' is not authorized to decrypt");
                        // The XDPEncryptionIV is not part of the serialized XDPKeys, so set it here with the value in the common header
                        oXDPKeys.XDPEncryptionIV = m_XDPInternalCommonHeaderField.XDPEncryptionIV;
                        break;
                    }
                }
                if (null == oMachineHeader)
                    throw new XDPAuthorizationException("No users of this machine ('" + Machinename + "') are authorized to decrypt");
                
                // Get the CryptoSettings
                oCryptoSettings = m_XDPInternalCommonHeaderField.GetCryptoSettings();

                // We have the keys, so verify all the signatures
                XDPSignatureHelper oSignatureHelper = new XDPSignatureHelper(oCryptoSettings, oXDPKeys.XDPSignatureKey);
                byte[] CalcSignature = m_XDPInternalHeaderSignaturesField.CreateLocalMachineHeaderSignature(oSignatureHelper, m_XDPInternalCommonHeaderField, oMachineHeader);
                XDPInternalHeaderMachineSignature oStoredSignature = m_XDPInternalHeaderSignaturesField.GetMachineSigature(Machinename);
                if (null == oStoredSignature)
                    throw new XDPSignatureVerificationException("No signature for hostname '" + Machinename + "' was found");
                if (CalcSignature.Length != oStoredSignature.Value.Length)
                    throw new XDPSignatureVerificationException("Calculated signature and stored signature were of different lengths for hostname '" + Machinename + "'");
                for (int i = 0; i < CalcSignature.Length; i++)
                {
                    if (CalcSignature[i] != oStoredSignature.Value[i])
                        throw new XDPSignatureVerificationException("Header signature verification failed for hostname '" + Machinename + "'");
                }
            
                // Our signature verification passed
                m_oXDPKeys = oXDPKeys;
            }

            DataSignature = m_XDPInternalCommonHeaderField.XDPDataSignature;
            log.Debug("Exiting " + System.Reflection.MethodInfo.GetCurrentMethod().Name);
        }

        /// <summary>
        /// Process an XDPResponseDecryptionKey message from the XDP Domain Service
        /// </summary>
        /// <param name="Message"></param>
        private void ProcessXDPResponseDecryptionKey(object Message, MessageSender oMsgSender)
        {
            log.Debug("Entering " + System.Reflection.MethodInfo.GetCurrentMethod().Name);
            XDPResponseDecryptionKey oXDPResponseDecryptionKey = (XDPResponseDecryptionKey)Message;

            m_oXDPKeys = oXDPResponseDecryptionKey.XDPKeys;
            log.Debug("Exiting " + System.Reflection.MethodInfo.GetCurrentMethod().Name);
        }

        /// <summary>
        /// Process an XDPExceptionResponse message from the XDP Domain Service
        /// </summary>
        /// <param name="Message"></param>
        private void ProcessXDPExceptionResponse(object Message, MessageSender oMsgSender)
        {
            log.Debug("Entering " + System.Reflection.MethodInfo.GetCurrentMethod().Name);
            XDPExceptionResponse oXDPExceptionResponse = (XDPExceptionResponse)Message;

            try
            {
                // Convert the exception messages into actual exceptions
                switch (oXDPExceptionResponse.ItemElementName)
                {
                    case XDPExceptionType.XDPBadParameter:
                    {
                        log.Debug("XDPBadParameter was received");
                        throw new XDPBadParameterException(((XDPExceptionXDPBadParameter)oXDPExceptionResponse.Item).Parameter, ((XDPExceptionXDPBadParameter)oXDPExceptionResponse.Item).Reason);
                    }
                    case XDPExceptionType.XDPBadSignature:
                    {
                        log.Debug("XDPBadSignature was received");
                        throw new XDPSignatureVerificationException((String)oXDPExceptionResponse.Item);
                    }
                    case XDPExceptionType.XDPNotAuthorized:
                    {
                        log.Debug("XDPNotAuthorized was received");
                        throw new XDPAuthorizationException((String)oXDPExceptionResponse.Item);
                    }
                    case XDPExceptionType.XDPUnknownIdentity:
                    {
                        log.Debug("XDPUnknownIdentity was received");
                        throw new XDPInvalidIdentityException((String)oXDPExceptionResponse.Item);
                    }
                    case XDPExceptionType.XDPUpdateCommonHeader:
                    {
                        log.Debug("XDPUpdateCommonHeader was received");
                        UpdateCryptoSettings(((XDPExceptionXDPUpdateCommonHeader)oXDPExceptionResponse.Item).XDPInternalCommonHeader);
                        throw new XDPUpdatedSettingsException();
                    }
                    case XDPExceptionType.XDPGeneralException:
                    {
                        log.Debug("XDPGeneralException was received");
                        throw new XDPException((String)oXDPExceptionResponse.Item);
                    }
                    default:
                    {
                        log.Debug("An unknown exception was received");
                        throw new XDPException("The XDP Domain Service returned an unknown exception");
                    }
                }
            }
            catch (InvalidCastException)
            {
                // Looks like the type of XDPExceptionResponse.Item does not match XDPExceptionResponse.ItemElementName
                throw new XDPException("The XDP Domain Service returned a badly formatted exception");
            }
        }

        /// <summary>
        /// In response to an XDPUpdateCommonHeader exception, update the crypto settings
        /// </summary>
        /// <param name="oXDPInternalCommonHeader"></param>
        private void UpdateCryptoSettings(XDPInternalCommonHeader oXDPInternalCommonHeader)
        {
            log.Debug("Entering " + System.Reflection.MethodInfo.GetCurrentMethod().Name);
            // Update the settings
            m_oSettings.CryptoSettings.EncryptionAlgorithm = oXDPInternalCommonHeader.XDPEncryptionAlgorithm;
            try
            {
                m_oSettings.CryptoSettings.EncryptionMode = (System.Security.Cryptography.CipherMode)Enum.Parse(typeof(System.Security.Cryptography.CipherMode), oXDPInternalCommonHeader.XDPEncryptionMode);
            }
            catch { }
            m_oSettings.CryptoSettings.SignatureAlgorithm = oXDPInternalCommonHeader.XDPSignatureAlgorithm;
            log.Debug("Exiting " + System.Reflection.MethodInfo.GetCurrentMethod().Name);
        }

        /// <remarks/>
        public XDPInternalCommonHeader XDPInternalCommonHeader
        {
            get
            {
                return this.m_XDPInternalCommonHeaderField;
            }
            set
            {
                this.m_XDPInternalCommonHeaderField = value;
            }
        }

        /// <remarks/>
        [System.Xml.Serialization.XmlElementAttribute("XDPInternalMachineHeader")]
        public XDPInternalMachineHeader[] XDPInternalMachineHeader
        {
            get
            {
                return this.m_XDPInternalMachineHeaderField;
            }
            set
            {
                this.m_XDPInternalMachineHeaderField = value;
            }
        }

        /// <remarks/>
        public XDPInternalDomainHeader XDPInternalDomainHeader
        {
            get
            {
                return this.m_XDPInternalDomainHeaderField;
            }
            set
            {
                this.m_XDPInternalDomainHeaderField = value;
            }
        }

        /// <remarks/>
        [System.Xml.Serialization.XmlElement(IsNullable=false)]
        public XDPInternalHeaderSignatures XDPInternalHeaderSignatures
        {
            get
            {
                return this.m_XDPInternalHeaderSignaturesField;
            }
            set
            {
                this.m_XDPInternalHeaderSignaturesField = value;
            }
        }
    }
}
