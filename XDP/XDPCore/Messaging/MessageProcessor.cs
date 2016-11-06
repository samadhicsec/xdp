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
using System.Xml.Serialization;
using log4net;

namespace XDP.XDPCore.Messaging
{
    internal class XDPUnknownMessageException : XDPException
    {
        public XDPUnknownMessageException()
            : base("")
        {

        }
    }

    internal delegate void MessageProcessorCallback(object Message, MessageSender oMsgSender);

    /// <summary>
    /// Processes a message by deserializing it and invoking the appropriately configured delegate
    /// </summary>
    internal class MessageProcessor
    {
        private static readonly ILog log = LogManager.GetLogger(typeof(MessageProcessor));
        Dictionary<Type, MessageProcessorCallback> m_MessageTypes;
        MessageSender m_oMsgSender;

        public MessageProcessor(Dictionary<Type, MessageProcessorCallback> MessageTypes, MessageSender oMsgSender)
        {
            m_MessageTypes = MessageTypes;
            m_oMsgSender = oMsgSender;
        }

        public void Process(byte[] Message)
        {
            log.Debug("Entering " + System.Reflection.MethodInfo.GetCurrentMethod().Name);
            MemoryStream SerializedMessageStream = new MemoryStream(Message);
            object oMessage = null;

            foreach (KeyValuePair<Type, MessageProcessorCallback> oKVP in m_MessageTypes)
            {
                oMessage = DeserializeMessage(SerializedMessageStream, oKVP.Key);
                if (null != oMessage)
                {
                    oKVP.Value(oMessage, m_oMsgSender);
                    log.Debug("Exiting " + System.Reflection.MethodInfo.GetCurrentMethod().Name);
                    return;
                }
            }

            log.Debug("Failed to deserialise message");
            throw new XDPUnknownMessageException();
        }

        /// <summary>
        /// Attempts to deserialize the message in the stream according to the Type parameter
        /// </summary>
        /// <param name="SerializedMessageStream">The stream containing the message</param>
        /// <param name="MessageType">The Type of message</param>
        /// <returns>The deserialized message or null if derserialization failed</returns>
        private object DeserializeMessage(MemoryStream SerializedMessageStream, Type MessageType)
        {
            object oMessage = null;
            SerializedMessageStream.Seek(0, SeekOrigin.Begin);

            // Try to deserialize the message.  We expect this to fail if the Message is not the MessageType
            try
            {
                XmlSerializer oSerializer = new XmlSerializer(MessageType);
                oMessage = oSerializer.Deserialize(SerializedMessageStream);
            }
            catch
            {
                return null;
            }
            log.Debug("Deserialised message of type " + MessageType.FullName);
            return oMessage;
        }
    }
}
