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
using System.Security.Cryptography;
using System.Security.Principal;
using log4net;
using XDP.XDPCore;
using XDP.XDPCore.Messages;
using XDP.XDPCore.Messaging;

namespace XDP.DomainService
{
    /// <summary>
    /// Processes an incoming request to the XDP Domain Service
    /// </summary>
    class DomainRequestProcessor
    {
        private static readonly ILog log = LogManager.GetLogger(typeof(DomainRequestProcessor));

        private MessageSender m_oMessageSender;

        public readonly Dictionary<Type, MessageProcessorCallback> DomainRequests;

        public DomainRequestProcessor()
        {
            DomainRequests = new Dictionary<Type, XDP.XDPCore.Messaging.MessageProcessorCallback>() 
            { 
                { typeof(XDPRequestDomainHeader), ProcessXDPRequestDomainHeader},
                { typeof(XDPRequestDecryptionKey), ProcessXDPRequestDecryptionKey }
            };
        }

        /// <summary>
        /// Process the XDPRequestDomainHeadermessage
        /// </summary>
        /// <param name="oRequest"></param>
        public void ProcessXDPRequestDomainHeader(object oRequest, MessageSender oMsgSender)
        {
            log.Debug("Entering " + System.Reflection.MethodInfo.GetCurrentMethod().Name);

            m_oMessageSender = oMsgSender;
            XDPExceptionHelper oExceptionHelper = new XDPExceptionHelper(m_oMessageSender);

            try
            {
                XDPRequestDomainHeader oXDPRequestDomainHeader = (XDPRequestDomainHeader)oRequest;

                if (null == oXDPRequestDomainHeader)
                {
                    // Send back bad parameter
                    oExceptionHelper.SendBadParameterException("XDPRequestDomainHeader", "Parameter was null");
                    return;
                }
                // Validate the request
                if (!oXDPRequestDomainHeader.Validate(oXDPRequestDomainHeader, oExceptionHelper))
                    return;

                // Check the received XDPInternalCommonHeader matches the Domain XDPInternalCommonHeader
                // Check if the settings dictate that clients with XDPInternalCommonHeader values that differ from the Domain Service values should be updated
                if (XDPDomainSettings.UpdateClientCommonHeader)
                {
                    if (!oXDPRequestDomainHeader.ValidateCryptoSettings(XDPDomainSettings.Settings.CryptoSettings, oExceptionHelper))
                        return;
                }
                
                // Check each XDPAuthorizedIdentity is a known Domain account.  A XDPInvalidIdentityException exception will be thrown if there is a problem resolving an identity
                List<SecurityIdentifier> oAuthorizedIdentities = new List<SecurityIdentifier>();
                XDPDomainIdentityHelper oDomainIdentityHelper = new XDPDomainIdentityHelper();
                oDomainIdentityHelper.VerifyIdentities(oXDPRequestDomainHeader.XDPAuthorizedIdentities.Identity, oAuthorizedIdentities);

                // Create XDPResponseDomainHeader
                XDPResponseDomainHeader oXDPResponseDomainHeader = new XDPResponseDomainHeader();
                oXDPResponseDomainHeader.CreateResponse(oXDPRequestDomainHeader, oAuthorizedIdentities);

                // Send Response
                //XDP.XDPCore.Messaging.MessageSender oMessageSender = new XDP.XDPCore.Messaging.MessageSender(m_oClient, m_oKerb);
                m_oMessageSender.SendWithNoResponseExpected(oXDPResponseDomainHeader);
            }
            catch (XDPInvalidIdentityException iie)
            {
                oExceptionHelper.SendUnknownIdentityException(iie.Message);
            }
            finally
            {
                log.Debug("Exiting " + System.Reflection.MethodInfo.GetCurrentMethod().Name);
            }
        }

        /// <summary>
        /// Process the XDPRequestDomainHeadermessage
        /// </summary>
        /// <param name="oRequest"></param>
        public void ProcessXDPRequestDecryptionKey(object oRequest, MessageSender oMsgSender)
        {
            log.Debug("Entering " + System.Reflection.MethodInfo.GetCurrentMethod().Name);

            m_oMessageSender = oMsgSender;
            XDPExceptionHelper oExceptionHelper = new XDPExceptionHelper(m_oMessageSender);

            try
            {
                XDPRequestDecryptionKey oXDPRequestDecryptionKey = (XDPRequestDecryptionKey)oRequest;

                if (null == oXDPRequestDecryptionKey)
                {
                    // Send back bad parameter
                    oExceptionHelper.SendBadParameterException("XDPRequestDecryptionKey", "Parameter was null");
                    return;
                }

                // Validate the request
                if (!oXDPRequestDecryptionKey.Validate(oExceptionHelper))
                    return;

                // Get the identity of the caller
                WindowsIdentity oCaller = (WindowsIdentity)((IServerIPC)m_oMessageSender.Server).ClientIdentity;
                log.Debug("The identity requesting decryption is " + oCaller.Name);

                // Check that the caller is allowed to decrypt.  This isn't trusted until the signature on the header verifies
                bool bCallerIsListed = false;
                for (int i = 0; i < oXDPRequestDecryptionKey.XDPInternalDomainHeader.XDPAuthorizedIdentities.Length; i++)
                {
                    string AuthorizedSID = oXDPRequestDecryptionKey.XDPInternalDomainHeader.XDPAuthorizedIdentities[i];
                    if (oCaller.User.ToString().Equals(AuthorizedSID, StringComparison.InvariantCultureIgnoreCase))
                    {
                        bCallerIsListed = true;
                        break;
                    }
                }
                if (!bCallerIsListed)
                {
                    // Check if the caller is a member of a AuthorizedIdentity that represents a group
                    XDPDomainIdentityHelper oDomainIdentityHelper = new XDPDomainIdentityHelper();
                    if (!oDomainIdentityHelper.IsAMemberOfAuthorizedGroup(oCaller, oXDPRequestDecryptionKey.XDPInternalDomainHeader.XDPAuthorizedIdentities))
                    {
                        oExceptionHelper.SendNotAutorizedException("User '" + oCaller.Name + "' was not authorized to decrypt the message");
                        return;
                    }
                }
                log.Debug("Requestor is allowed to decrypt");

                // Recover XDPKeys so we can check the signature
                XDPResponseDecryptionKey oXDPResponseDecryptionKey = new XDPResponseDecryptionKey();
                try
                {
                    oXDPResponseDecryptionKey.CreateResponse(oXDPRequestDecryptionKey);
                }
                catch (CryptographicException ce)
                {
                    log.Debug("ProtectData.Unprotect failed", ce);
                    // ProtectData.Unprotect failed.  Send back bad parameter.
                    oExceptionHelper.SendBadParameterException("XDPEncryptedKeys", "Either not encrypted on this server or not by XDP Domain Service account");
                    return;
                }

                // Verify the signature on the XDPInternalDomainHeader
                if (oXDPRequestDecryptionKey.VerifySignature(oXDPResponseDecryptionKey.XDPKeys))
                {
                    log.Debug("Signature in XDPRequestDecryptionKey verifies, responding with key");
                    // Send Response
                    m_oMessageSender.SendWithNoResponseExpected(oXDPResponseDecryptionKey);
                }
                else
                {
                    // Send back bad signature exception
                    oExceptionHelper.SendBadSignatureException("The Domain Header had an invalid signature");
                }
            }
            catch (Exception e)
            {
                log.Debug("", e);
                oExceptionHelper.SendGeneralExceptionException("An unknown error occurred");
            }
            finally
            {
                log.Debug("Exiting " + System.Reflection.MethodInfo.GetCurrentMethod().Name);
            }
        }
    }
}
