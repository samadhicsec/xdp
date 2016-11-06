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
using System.IO;
using System.Threading;
using log4net;
using XDP.XDPCore.Settings;

namespace XDP.XDPCore.Messaging
{
    /// <summary>
    /// Generic code to handle listening for connections via the provided IPC mechanism and passing off the requests made for processing
    /// </summary>
    internal class Listener
    {
        private static readonly ILog log = LogManager.GetLogger(typeof(Listener));
        private IServerIPC m_ServerIPC;
        private Dictionary<Type, MessageProcessorCallback> m_oMessageCallbacks;
        private bool bStopListening = false;
        private AutoResetEvent connectionWaitHandle = new AutoResetEvent(false);

        static Listener()
        {
            int workerthreads = 0;
            int iocompthreads = 0;
            ThreadPool.GetMinThreads(out workerthreads, out iocompthreads);

            XDPSettings oXDPSettings = new XDPSettings();
            // Probably should do more research into what are appropriate values here.  By default the minimum thread pool is equal to the number of processors. 
            // It seems to make sense to increase this as we want to easily support many requests, however not a truly high volume.
            if ((int)oXDPSettings.ThreadPoolSize > iocompthreads)
                iocompthreads = (int)oXDPSettings.ThreadPoolSize;

            // Set the minimum number of threads for the Thread Pool
            log.Info("Worker Threads = " + workerthreads + ", IO Completion Threads = " + iocompthreads);
            ThreadPool.SetMinThreads(workerthreads, iocompthreads);
        }

        public Listener(IServerIPC oServerIPC, Dictionary<Type, MessageProcessorCallback> oMessageCallbacks)
        {
            m_ServerIPC = oServerIPC;
            m_oMessageCallbacks = oMessageCallbacks;
        }

        /// <summary>
        /// Listen for incoming requests and handle a new request on a seperate thread
        /// </summary>
        public void Listen(object state)
        {
            log.Debug("Entering " + System.Reflection.MethodInfo.GetCurrentMethod().Name);

            object listener = m_ServerIPC.CreateServerListener();
            
            while (true)
            {
                try
                {
                    m_ServerIPC.BeginWaitForClient(HandleAsyncConnection, listener);
                    connectionWaitHandle.WaitOne(); //Wait until a client has begun handling an event 

                    // Check if we are supposed to stop listening
                    if (bStopListening)
                        break;
                }
                catch (Exception e)
                {
                    log.Debug("", e);
                }
            }

            log.Debug("Exiting " + System.Reflection.MethodInfo.GetCurrentMethod().Name);
        }

        public void StopListening()
        {
            bStopListening = true;
            connectionWaitHandle.Set();
        }

        /// <summary>
        /// Handle the new incoming connection
        /// </summary>
        /// <param name="result"></param>
        private void HandleAsyncConnection(IAsyncResult result)
        {
            log.Debug("Entering " + System.Reflection.MethodInfo.GetCurrentMethod().Name);

            object client = null;
            try
            {
                client = m_ServerIPC.EndWaitForClient(result);
                connectionWaitHandle.Set(); //Inform the main thread this connection is now handled 

                // Allocate space to read message
                MemoryStream MessageStream = new MemoryStream();
                byte[] ReadBuffer = new byte[4096];

                AutoResetEvent oWait = new AutoResetEvent(false);
                Stream oClientStream = m_ServerIPC.GetClientStream(client);
                
                // BeginRead will wait until there is data to be read or an error occurs
                oClientStream.BeginRead(ReadBuffer, 0, ReadBuffer.Length,
                    delegate(IAsyncResult target)
                    {
                        try
                        {
                            int bytesRead = oClientStream.EndRead(target);
                            MessageStream.Write(ReadBuffer, 0, bytesRead);

                            while (m_ServerIPC.DataAvailable(client))
                            {
                                bytesRead = oClientStream.Read(ReadBuffer, 0, ReadBuffer.Length);
                                MessageStream.Write(ReadBuffer, 0, bytesRead);
                            }
                        }
                        catch (Exception se)
                        {
                            // If there is an exception then when we process the received bytes (if any), RequestProcessor will attempt to send back an 
                            // XDPUnknownMessage, if the connection is still open
                            log.Debug("Error reading from client connection" + Environment.NewLine + se.Message);
                            m_ServerIPC.CloseClient(client);
                        }
                        oWait.Set();
                    }, null);

                // Wait for the asynchronous read callback to finish reading or for a timeout to occur
                if (!oWait.WaitOne(m_ServerIPC.Timeout()))
                {
                    m_ServerIPC.CloseClient(client);
                    log.Warn("A network timeout occurred");
                    return;
                }

                log.Debug("Received a total of " + MessageStream.Length + " bytes");

                // Process the received request
                MessageSender oMsgSender = new MessageSender(m_ServerIPC, client, oClientStream);
                RequestProcessor oRequestProcessor = new RequestProcessor(oMsgSender, m_oMessageCallbacks);
                oRequestProcessor.Process(MessageStream);

                m_ServerIPC.CloseClient(client);
            }
            catch (Exception ex)
            {
                // This is the exception handler of last resort.  If we had a meaningful exception we would have written it to the Event Log already, so just log this
                // exception to what ever log might be in operation
                log.Debug("", ex);
                // Try to close the client to free up any unmanaged resources
                try
                {
                    m_ServerIPC.CloseClient(client);
                }
                catch { }
            }
            finally
            {
                log.Debug("Exiting " + System.Reflection.MethodInfo.GetCurrentMethod().Name);
            }
        }

    }
}
