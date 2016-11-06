using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.IO;
using System.Xml.Serialization;
using System.Net.Sockets;

namespace XDP.XDPCore.Messages
{
    public class XDPUnknownMessageException : XDPException
    {
        public XDPUnknownMessageException()
            : base("")
        {

        }
    }

    public delegate void MessageProcessorCallback(object Message);

    public class MessageProcessor
    {
        Dictionary<Type, MessageProcessorCallback> m_MessageTypes;

        public MessageProcessor(Dictionary<Type, MessageProcessorCallback> MessageTypes)
        {
            m_MessageTypes = MessageTypes;
        }

        public void Process(byte[] Message)
        {
            MemoryStream SerializedMessageStream = new MemoryStream(Message);
            object oMessage = null;

            foreach(KeyValuePair<Type, MessageProcessorCallback> oKVP in m_MessageTypes)
            {
                oMessage = DeserializeMessage(SerializedMessageStream, oKVP.Key);
                if (null != oMessage)
                {
                    oKVP.Value(oMessage);
                    return;
                }
            }

            throw new XDPUnknownMessageException();
        }

        /// <summary>
        /// Attempts to deserialize the message in the stream according to the Type parameter
        /// </summary>
        /// <param name="SerializedMessageStream">The stream containing the message</param>
        /// <param name="MessageType">The Type ofmessage</param>
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
            return oMessage;
        }
    }
}
