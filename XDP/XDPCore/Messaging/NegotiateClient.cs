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
using System.Net;
using System.Net.Security;
using System.Net.Sockets;
using System.Security.Principal;
using log4net;
using XDP.XDPCore.Settings;

namespace XDP.XDPCore.Messaging
{
    /// <summary>
    /// An implmentation of the generic IPC functinality via Windows Negotiate
    /// </summary>
    internal class NegotiateClient : IIPC
    {
        private static readonly ILog log = LogManager.GetLogger(typeof(NegotiateClient));
        private TcpClient m_oClient;
        private NegotiateStream m_oStream;
        uint m_NetworkTimeout;

        internal object Client
        {
            get { return m_oClient; }
        }

        internal Stream Stream
        {
            get { return m_oStream; }
        }

        /// <summary>
        /// Create a MessageSender using the connection parameters in XDPSettings
        /// </summary>
        /// <param name="oClient"></param>
        internal NegotiateClient(XDPMachineSettings oXDPSettings)
        {
            log.Debug("Entering NegotiateClient " + System.Reflection.MethodInfo.GetCurrentMethod().Name);
            log.Debug("Network timeout set at " + oXDPSettings.NetworkTimout);
            m_NetworkTimeout = oXDPSettings.NetworkTimout;
            m_oClient = new TcpClient();
            m_oClient.ReceiveTimeout = (int)m_NetworkTimeout;
            m_oClient.SendTimeout = (int)m_NetworkTimeout;

            int ConnectionRetries = 0;
            do
            {
                try
                {
                    log.Debug("Connecting to " + oXDPSettings.DomainHostname + ":" + oXDPSettings.DomainPort);
                    m_oClient.Connect(oXDPSettings.DomainHostname, oXDPSettings.DomainPort);
                    break;
                }
                catch (SocketException se)
                {
                    // Retry this connection if it times out
                    if (se.ErrorCode == 10060) //WSAETIMEDOUT
                    {
                        log.Debug("Connection timed out");
                        if (ConnectionRetries < 3)
                        {
                            ConnectionRetries++;
                            continue;
                        }
                        else
                            log.Debug("Retry limit reached", se);
                    }
                    throw new XDPException(se.Message);
                }
            }
            while (ConnectionRetries < 3);

            XDP.XDPCore.Identity.ContextHelper oContextHelper = new XDP.XDPCore.Identity.ContextHelper(oXDPSettings.XDPDSAccount);

            NetworkStream oStream = m_oClient.GetStream();
            m_oStream = new NegotiateStream(oStream, false);
            try
            {
                log.Debug("Authenticating as " + WindowsIdentity.GetCurrent().Name);
                m_oStream.AuthenticateAsClient(CredentialCache.DefaultNetworkCredentials, XDPCommon.GetDomainName() + "\\" + oContextHelper.User, ProtectionLevel.EncryptAndSign, TokenImpersonationLevel.Identification);
            }
            catch (Exception e)
            {
                // Log failure
                log.Debug("Failed to authenticate to server", e);
            }
            log.Debug("Connected to account " + m_oStream.RemoteIdentity.Name + " at " + oXDPSettings.DomainHostname + ":" + oXDPSettings.DomainPort);

            // Check that the connection is appropriately secured
            if (!m_oStream.IsEncrypted)
            {
                m_oClient.Close();
                throw new XDPCommunicationsException("Unable to create an encrypted connection to the server");
            }
            if (!m_oStream.IsAuthenticated)
            {
                m_oClient.Close();
                throw new XDPCommunicationsException("Unable to create an authenticated connection to the server");
            }
            if ((oXDPSettings.CommunicationSecurity == CommunicationSecurityLevel.Kerberos) &&
                !m_oStream.IsMutuallyAuthenticated)
            {
                m_oClient.Close();
                throw new XDPCommunicationsException("Unable to create a Kerberos connection to the server");
            }
            log.Debug("Exiting NegotiateClient " + System.Reflection.MethodInfo.GetCurrentMethod().Name);
        }

        #region IIPC Members

        public bool DataAvailable(object oClient)
        {
            TcpClient client = oClient as TcpClient;
            return client.Connected && (client.Available > 0);
        }

        public int Timeout()
        {
            return (int)m_NetworkTimeout;
        }

        public void CloseClient(object oClient)
        {
            if (null != oClient)
                ((TcpClient)oClient).Close();
        }

        #endregion
    }
}
