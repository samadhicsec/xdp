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
using System.Threading;
using log4net;

namespace XDP.XDPCore.Messaging
{
    /// <summary>
    /// Sends and receives messages using the specified IPC mechanism
    /// </summary>
    public class MessageSender
    {
        private static readonly ILog log = LogManager.GetLogger(typeof(MessageSender));
        IIPC m_oIPC;
        protected object m_oClient;
        protected Stream m_oStream;

        /// <summary>
        /// Create a MessageSender using an established connection
        /// </summary>
        /// <param name="oClient"></param>
        public MessageSender(IIPC oIPC, object oClient, Stream oStream)
        {
            m_oIPC = oIPC;
            m_oClient = oClient;
            m_oStream = oStream;
        }

        public IIPC Server
        {
            get { return m_oIPC; }
        }

        public object Client
        {
            get { return m_oClient; }
        }

        public byte[] Send(object SerializableObject)
        {
            //Serialise the object
            byte[] SerializedObject = XDPCommon.SerializeToXml(SerializableObject, "urn:com.XDP.XDPMessages");
            
            // Send the message
            SendBytes(SerializedObject);

            // Get the response
            return GetResponse();
        }

        /// <summary>
        /// Sends an object that can be serialized to XML.  No response is expected from the message.
        /// </summary>
        /// <param name="SerializableObject">The message to send</param>
        public void SendWithNoResponseExpected(object SerializableObject)
        {
            //Serialise the object
            byte[] SerializedObject = XDPCommon.SerializeToXml(SerializableObject, "urn:com.XDP.XDPMessages");

            // Send the message
            SendBytes(SerializedObject);
        }

        /// <summary>
        /// Sends a message
        /// </summary>
        /// <param name="MessageBytes"></param>
        private void SendBytes(byte[] MessageBytes)
        {
            //if (m_oClient.Connected)
            //{
                log.Debug("Sending " + MessageBytes.Length + " bytes");
                try
                {
                    m_oStream.Write(MessageBytes, 0, MessageBytes.Length);
                }
                catch (Exception e)
                {
                    log.Error("An error occurred sending" + Environment.NewLine + e.Message);
                }
            //}
        }

        private byte[] GetResponse()
        {
            // Read in the available bytes
            MemoryStream MessageStream = new MemoryStream();
            byte[] ReadBuffer = new byte[4096];

            AutoResetEvent oWait = new AutoResetEvent(false);

            // BeginRead will wait until there is data to be read or an error occurs
            m_oStream.BeginRead(ReadBuffer, 0, ReadBuffer.Length,
                delegate(IAsyncResult target)
                {
                    try
                    {
                        int bytesRead = m_oStream.EndRead(target);
                        //log.Debug("Read " + bytesRead + " bytes");
                        MessageStream.Write(ReadBuffer, 0, bytesRead);

                        while (m_oIPC.DataAvailable(m_oClient))
                        {
                            bytesRead = m_oStream.Read(ReadBuffer, 0, ReadBuffer.Length);
                            MessageStream.Write(ReadBuffer, 0, bytesRead);
                            //log.Debug("Read " + bytesRead + " bytes");
                        }
                    }
                    catch (Exception se)
                    {
                        log.Error("Error reading from client connection" + Environment.NewLine + se.Message);
                    }
                    oWait.Set();
                }, null);

            // Wait for the asynchronous read callback to finish reading or for a timeout to occur
            if (!oWait.WaitOne(m_oIPC.Timeout()))
            {
                m_oIPC.CloseClient(m_oClient);
                throw new XDPCommunicationsException("Network timeout occurred (" + m_oIPC.Timeout() + " ms).");
            }

            m_oIPC.CloseClient(m_oClient);

            log.Debug("Received a total of " + MessageStream.Length + " bytes");

            return MessageStream.ToArray();
        }
    }
}
