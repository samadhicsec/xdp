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
using System.Security.Authentication;
using System.Security.Principal;
using log4net;

namespace XDP.XDPCore.Messaging
{
    /// <summary>
    /// An implemenation of the Server IPC functionality via Windows Negotiate
    /// </summary>
    public class NegotiateServer : IServerIPC
    {
        private static readonly ILog log = LogManager.GetLogger(typeof(NegotiateServer));
        ushort m_ListenPort;
        uint m_NetworkTimeout;
        WindowsIdentity m_ClientIdentity;

        public NegotiateServer(ushort listenPort, uint NetworkTimeout)
        {
            m_ClientIdentity = null;
            m_ListenPort = listenPort;
            m_NetworkTimeout = NetworkTimeout;
        }

        #region IServerIPC Members

        public object CreateServerListener()
        {
            TcpListener listener = new TcpListener(IPAddress.Any, (int)m_ListenPort);
            listener.Start();
            return listener;
        }

        public IAsyncResult BeginWaitForClient(AsyncCallback callback, object state)
        {
            return ((TcpListener)state).BeginAcceptTcpClient(callback, state);
        }

        public object EndWaitForClient(IAsyncResult asyncResult)
        {
            TcpListener listener = (TcpListener)asyncResult.AsyncState;
            TcpClient client = listener.EndAcceptTcpClient(asyncResult);
            return client;
        }

        public Stream GetClientStream(object oClient)
        {
            NetworkStream AvailableBytes = ((TcpClient)oClient).GetStream();
            NegotiateStream oKerb = new NegotiateStream(AvailableBytes, false);

            try
            {
                log.Debug("Calling AuthenticateAsServer");
                oKerb.AuthenticateAsServer(CredentialCache.DefaultNetworkCredentials, ProtectionLevel.EncryptAndSign, TokenImpersonationLevel.Identification);
                log.Debug("AuthenticateAsServer called");
            }
            catch (InvalidCredentialException ice)
            {
                // This exception indicates that the underlying stream is not in a valid state and you cannot retry the authentication using the NegotiateStream or SslStream instance. 
                // If you can retry the authentication, an AuthenticationException is thrown instead of the InvalidCredentialException.
                log.Warn("InvalidCredentialException: Authentication failed for an incoming connection", ice);
                throw;
            }
            catch (AuthenticationException ae)
            {
                log.Warn("AuthenticationException: Authentication failed for an incoming connection", ae);
                throw;
            }
            catch (Exception e)
            {
                log.Debug("An incoming connection could not be established securely", e);
                throw;
            }
            // TODO Research if there is any such thing as a cipher downgrade attack against Kerberos
            // There is no point checking for mutual auth on a server as server always authn's the client and that is all we care about on the server,
            // and it's pointless for server to verify that client is using mutual auth, because if the client connects to a rogue server then our 
            // server code is not even running.
            m_ClientIdentity = (WindowsIdentity)oKerb.RemoteIdentity;
            log.Debug("The client " + oKerb.RemoteIdentity.Name + " connected");

            return oKerb;
        }

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
            m_ClientIdentity = null;
            if (null != oClient)
                ((TcpClient)oClient).Close();
        }

        public object ClientIdentity
        {
            get { return m_ClientIdentity; }
        }

        #endregion
    }
}
