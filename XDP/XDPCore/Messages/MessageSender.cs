using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.IO;
using System.Xml.Serialization;
using System.Net.Sockets;
using System.Net;
using System.Net.Security;
using System.Security.Principal;
using System.Threading;
using XDP.XDPCore;
using XDP.XDPCore.Settings;

namespace XDP.XDPCore.Messages
{
    public class MessageSender
    {
        private XDPSettings m_oSettings;
        private TcpClient m_oClient;
        NegotiateStream m_oKerb;

        /// <summary>
        /// Create a MessageSender using an established connection
        /// </summary>
        /// <param name="oClient"></param>
        public MessageSender(TcpClient oClient, NegotiateStream oKerb)
        {
            m_oClient = oClient;
            m_oKerb = oKerb;
        }

        /// <summary>
        /// Create a MessageSender using the connection parameters in XDPSettings
        /// </summary>
        /// <param name="oClient"></param>
        internal MessageSender(XDPMachineSettings oXDPSettings)
        {
            m_oSettings = oXDPSettings;
            m_oClient = new TcpClient();

            int ConnectionRetries = 0;
            do
            {
                try
                {
                    m_oClient.Connect(oXDPSettings.DomainHostname, oXDPSettings.DomainPort);
                    break;
                }
                catch (SocketException se)
                {
                    // Retry this connection if it times out
                    if (se.ErrorCode == 10060) //WSAETIMEDOUT
                    {
                        ConnectionRetries++;
                        continue;
                    }
                    // TODO Convert this to a meaningful error message
                    throw new XDPException(se.Message);
                }
            }
            while (ConnectionRetries < 3);

            XDP.XDPCore.Identity.ContextHelper oContextHelper = new XDP.XDPCore.Identity.ContextHelper(oXDPSettings.XDPDSAccount);

            NetworkStream oStream = m_oClient.GetStream();
            m_oKerb = new NegotiateStream(oStream, false);
            try
            {
                m_oKerb.AuthenticateAsClient(CredentialCache.DefaultNetworkCredentials, XDPCommon.GetDomainName() + "\\" + oContextHelper.User, ProtectionLevel.EncryptAndSign, TokenImpersonationLevel.Identification);
            }
            catch (Exception e)
            {
                // TODO Throw exception to tell user they could not auth
                // Log failure
                XDPLogging.Log("Failed to authenticate to server" + Environment.NewLine + e.Message);
            }
            XDPLogging.Log("Connected to server " + m_oKerb.RemoteIdentity.Name);

            // Check that the connection is appropriately secured
            if (!m_oKerb.IsEncrypted)
            {
                m_oClient.Close();
                throw new XDPCommunicationsException("Unable to create an encrypted connection to the server");
            }
            if (!m_oKerb.IsAuthenticated)
            {
                m_oClient.Close();
                throw new XDPCommunicationsException("Unable to create an authenticated connection to the server");
            }
            if ((m_oSettings.CommunicationSecurity == XDPSettings.CommunicationSecurityLevel.Kerberos) &&
                !m_oKerb.IsMutuallyAuthenticated)
            {
                m_oClient.Close();
                throw new XDPCommunicationsException("Unable to create a Kerberos connection to the server");
            }
        }

        public byte[] Send(object SerializableObject)
        {
            //Serialise the object
            byte[] SerializedObject = SerializeToXml(SerializableObject, "urn:com.XDP.XDPMessages");

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
            byte[] SerializedObject = SerializeToXml(SerializableObject, "urn:com.XDP.XDPMessages");

            // Send the message
            SendBytes(SerializedObject);
        }

        /// <summary>
        /// Sends a message
        /// </summary>
        /// <param name="MessageBytes"></param>
        private void SendBytes(byte[] MessageBytes)
        {
            if (m_oClient.Connected)
            {
                XDPLogging.Log("Sending " + MessageBytes.Length + " bytes");
                try
                {
                    m_oKerb.Write(MessageBytes, 0, MessageBytes.Length);
                }
                catch(Exception e)
                {
                    XDPLogging.Log("An error occurred sending" + Environment.NewLine + e.Message);
                }
            }
        }

        private byte[] GetResponse()
        {
            // Read in the available bytes
            MemoryStream MessageStream = new MemoryStream();
            byte[] ReadBuffer = new byte[4096];
            
            AutoResetEvent oWait = new AutoResetEvent(false);

            // BeginRead will wait until there is data to be read or an error occurs
            m_oKerb.BeginRead(ReadBuffer, 0, ReadBuffer.Length, 
                delegate(IAsyncResult target)
                {
                    try
                    {
                        int bytesRead = m_oKerb.EndRead(target);
                        //XDPLogging.Log("Read " + bytesRead + " bytes");
                        MessageStream.Write(ReadBuffer, 0, bytesRead);

                        while ((m_oClient.Connected) && (m_oClient.Available > 0))
                        {
                            bytesRead = m_oKerb.Read(ReadBuffer, 0, ReadBuffer.Length);
                            MessageStream.Write(ReadBuffer, 0, bytesRead);
                            //XDPLogging.Log("Read " + bytesRead + " bytes");
                        }
                    }
                    catch (Exception se)
                    {
                        XDPLogging.Log("Error reading from client connection" + Environment.NewLine + se.Message);
                    }
                    oWait.Set();
                }, null);

            // Wait for the asynchronous read callback to finish reading or for a timeout to occur
            if (!oWait.WaitOne((int)m_oSettings.NetworkTimout))
            {
                m_oClient.Close();
                throw new XDPCommunicationsException("Network timeout occurred.");
            }

            m_oClient.Close();

            XDPLogging.Log("Received a total of " + MessageStream.Length + " bytes");

            return MessageStream.ToArray();
        }

        /// <summary>
        /// Serializes an object to XML
        /// </summary>
        /// <param name="ObjectToSerialize">The object to serialize</param>
        /// <param name="Namespace">The XML namespace</param>
        /// <returns>The serialized object</returns>
        private byte[] SerializeToXml(object ObjectToSerialize, string Namespace)
        {
            // Serialise Object
            MemoryStream oSerializedObject = new MemoryStream();
            try
            {
                XmlSerializer oSerializer = new XmlSerializer(ObjectToSerialize.GetType(), Namespace);
                oSerializer.Serialize(oSerializedObject, ObjectToSerialize);
            }
            catch (InvalidOperationException ioe)
            {
                throw new XDPException(ioe.InnerException.Message);
            }
            return oSerializedObject.ToArray();
        }
    }
}
