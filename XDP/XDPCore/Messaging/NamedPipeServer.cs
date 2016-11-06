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
using System.IO.Pipes;
using System.Security.Principal;

namespace XDP.XDPCore.Messaging
{
    /// <summary>
    /// An implementation of the Server IPC functionaliy via Named Pipes
    /// </summary>
    public class NamedPipeServer : IServerIPC
    {
        // If this parameter is PIPE_UNLIMITED_INSTANCES (-1), the number of pipe instances that can be created is limited only by the availability of system resources.
        const int MAX_SERVER_INSTANCES = -1;
        string m_PipeName;
        string m_ClientIdentity;

        public NamedPipeServer(string PipeName)
        {
            m_PipeName = PipeName;
            m_ClientIdentity = null;
        }

        #region IServerIPC Members

        public object CreateServerListener()
        {
            // We don't create the pipe here as in Listener this call is before the loop that handles connecting clients, and we need to create a new NamedPipeServerStream for each client.
            // It is possible for another client to try to connect in between accepting a client and creating a new pipe server, that's OK as the client will wait for the server.
            // See http://msdn.microsoft.com/en-us/library/aa365588(v=vs.85).aspx
            return null;
        }

        public IAsyncResult BeginWaitForClient(AsyncCallback callback, object state)
        {
            // Create the named pipe server.  By default only admins will be able to write to it.
            NamedPipeServerStream oServer = new NamedPipeServerStream(m_PipeName, PipeDirection.InOut, MAX_SERVER_INSTANCES, PipeTransmissionMode.Message, PipeOptions.Asynchronous, 8192, 8192, null, 0, PipeAccessRights.ChangePermissions);
            
            // Create an access rule to allow anyone to read from or write to the pipe
            PipeAccessRule pipeAccessRule = new PipeAccessRule(new SecurityIdentifier(WellKnownSidType.WorldSid, null), PipeAccessRights.Write | PipeAccessRights.Read, System.Security.AccessControl.AccessControlType.Allow);
            // Add this access rule to the default ACL on the pipe
            PipeSecurity pipeSecurity = oServer.GetAccessControl();
            pipeSecurity.AddAccessRule(pipeAccessRule);
            oServer.SetAccessControl(pipeSecurity);

            // Async wait for client
            IAsyncResult res = oServer.BeginWaitForConnection(callback, oServer);
            return res;
        }

        public object EndWaitForClient(IAsyncResult asyncResult)
        {
            NamedPipeServerStream listener = (NamedPipeServerStream)asyncResult.AsyncState;
            listener.EndWaitForConnection(asyncResult);
            return listener;
        }

        public Stream GetClientStream(object oClient)
        {
            NamedPipeServerStream oPipeClient = oClient as NamedPipeServerStream;
            m_ClientIdentity = oPipeClient.GetImpersonationUserName();
            return oPipeClient;
        }

        public bool DataAvailable(object oClient)
        {
            NamedPipeServerStream client = oClient as NamedPipeServerStream;
            return client.IsConnected && !client.IsMessageComplete;
        }

        public int Timeout()
        {
            return -1;  // The pipeserver will wait indefinitely for the client to finish communicating
        }

        public void CloseClient(object oClient)
        {
            m_ClientIdentity = null;
            if(null != oClient)
                (oClient as NamedPipeServerStream).Close();
        }

        public object ClientIdentity 
        {
            get { return m_ClientIdentity; }
        }

        #endregion
    }
}
