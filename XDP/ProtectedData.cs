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
using System.IO.Pipes;
using System.Text;
using System.Threading;
using XDP.MachineService.Messages;

namespace XDP
{
    public class ProtectedData
    {
        const int CLIENT_CONNECT_TIMEOUT = 5000;
        const int CLIENT_RECEIVE_TIMEOUT = 30000;

        /// <summary>
        /// Protects the data passed in by encrypting it so only the provided list of authorized users can decrypt the data.
        /// </summary>
        /// <param name="userData">The data to encrypt</param>
        /// <param name="authorizedUsers">The list of users who can decrypt the data</param>
        /// <exception cref="System.ArgumentNullException">The userData parameter is null</exception>
        /// <exception cref="System.ArgumentException">The userData parameter is empty</exception>
        /// <exception cref="XDP.XDPBadParameterException">A bad parameter was encountered</exception>
        /// <exception cref="XDP.XDPInvalidIdentityException">An invalid identity was encountered</exception>
        /// <exception cref="XDP.XDPException">A generic exception occurred</exception>
        /// <returns>The encrypted data</returns>
        public static byte[] Protect(byte[] userData, List<String> authorizedUsers)
        {
            // Validate the input parameters
            if (userData == null)
                throw new ArgumentNullException("userData", "The userData parameter is null");
            if(0 == userData.Length)
                throw new ArgumentException("userData", "The userData parameter is empty");
            if (authorizedUsers == null)
                authorizedUsers = new List<string>();
            
            // Create the request to encrypt the data
            XDPRequestProtectData oRequest = new XDPRequestProtectData();
            oRequest.XDPAuthorizedIdentities = authorizedUsers.ToArray();
            oRequest.UserData = userData;

            byte[] oRequestBytes = SerializeToXml(oRequest, "urn:XDP.XDPMachineService.Messages");

            // Create connection to XDP Machine Service
            NamedPipeClientStream oPipeClient = new NamedPipeClientStream(".", "\\\\.\\pipe\\XDPProtectData", PipeDirection.InOut, PipeOptions.Asynchronous, System.Security.Principal.TokenImpersonationLevel.Impersonation);
            oPipeClient.Connect(CLIENT_CONNECT_TIMEOUT);
            oPipeClient.ReadMode = PipeTransmissionMode.Message;

            if (!oPipeClient.IsConnected)
            {
                throw new XDPException("Could not connect to the XDP Machine Service within the timeout period");
            }

            // Make request and receive response
            byte[] oResponseBytes = PipeSendAndReceive(oPipeClient, oRequestBytes);

            // Try to deserialise response
            XDPResponseProtectData oResponse = DeserializeFromXml<XDPResponseProtectData>(oResponseBytes);
            if (null == oResponse)
            {
                // Try to deserialise the error message
                XDP.MachineService.Messages.XDPExceptionResponse oResponseError = DeserializeFromXml<XDP.MachineService.Messages.XDPExceptionResponse>(oResponseBytes);
                if (null != oResponseError)
                    ProcessXDPExceptionResponse(oResponseError);
                else
                    throw new XDPException("An unknown message was returned from the XDP Machine Service" + Environment.NewLine + ASCIIEncoding.ASCII.GetString(oResponseBytes));
            }
            
            return oResponse.ProtectedData;
        }

        /// <summary>
        /// Unprotects data protected with ProtectData if the caller is in the list of authorizedUsers.
        /// </summary>
        /// <param name="encryptedData">The data to decrypt</param>
        /// <exception cref="System.ArgumentNullException">The encryptedData parameter is null</exception>
        /// <exception cref="System.ArgumentException">The encryptedData parameter is empty</exception>
        /// <exception cref="XDP.XDPBadParameterException">The encryptedData parameter contained a bad parameter</exception>
        /// <exception cref="XDP.XDPSignatureVerificationException">The encryptedData parameter did not have a valid signature</exception>
        /// <exception cref="XDP.XDPAuthorizationException">The caller was not authorized to unprotect the data</exception>
        /// <exception cref="XDP.XDPInvalidIdentityException">An invalid identity was encountered</exception>
        /// <exception cref="XDP.XDPException">A generic exception occurred</exception>
        /// <returns></returns>
        public static byte[] Unprotect(byte[] encryptedData)
        {
            // Validate the input parameters
            if (encryptedData == null)
                throw new ArgumentNullException("encryptedData", "The encryptedData parameter is null");
            if (0 == encryptedData.Length)
                throw new ArgumentException("encryptedData", "The encryptedData parameter is empty");

            // Create the request to decrypt the data
            XDPRequestUnprotectData oRequest = new XDPRequestUnprotectData();
            oRequest.encryptedData = encryptedData;

            byte[] oRequestBytes = SerializeToXml(oRequest, "urn:XDP.XDPMachineService.Messages");

            // Create connection to XDP Machine Service
            NamedPipeClientStream oPipeClient = new NamedPipeClientStream(".", "\\\\.\\pipe\\XDPUnprotectData", PipeDirection.InOut, PipeOptions.Asynchronous, System.Security.Principal.TokenImpersonationLevel.Impersonation);
            oPipeClient.Connect(CLIENT_CONNECT_TIMEOUT);
            oPipeClient.ReadMode = PipeTransmissionMode.Message;

            if (!oPipeClient.IsConnected)
            {
                throw new XDPException("Could not connect to the XDP Machine Service within the timeout period");
            }

            // Make request and receive response
            byte[] oResponseBytes = PipeSendAndReceive(oPipeClient, oRequestBytes);

            // Try to deserialise response
            XDPResponseUnprotectData oResponse = DeserializeFromXml<XDPResponseUnprotectData>(oResponseBytes);
            if (null == oResponse)
            {
                // Try to deserialise the error message
                XDP.MachineService.Messages.XDPExceptionResponse oResponseError = DeserializeFromXml<XDP.MachineService.Messages.XDPExceptionResponse>(oResponseBytes);
                if (null != oResponseError)
                    ProcessXDPExceptionResponse(oResponseError);
                else
                    throw new XDPException("An unknown message was returned from the XDP Machine Service" + Environment.NewLine + ASCIIEncoding.ASCII.GetString(oResponseBytes));
            }

            return oResponse.UnprotectedData;
        }

        private static byte[] PipeSendAndReceive(NamedPipeClientStream oClientPipe, byte[] Message)
        {
            // Write request to pipe
            oClientPipe.Write(Message, 0, Message.Length);            

            string errormessage = string.Empty;
            MemoryStream MessageStream = new MemoryStream();
            byte[] ResponseBuffer = new byte[4096];
            AutoResetEvent oWait = new AutoResetEvent(false);

            oClientPipe.BeginRead(ResponseBuffer, 0, ResponseBuffer.Length,
                delegate(IAsyncResult target)
                {
                    // Read response
                    try
                    {
                        int bytesRead = oClientPipe.EndRead(target);
                        MessageStream.Write(ResponseBuffer, 0, bytesRead);

                        while (!oClientPipe.IsMessageComplete)
                        {
                            // Keep reading
                            bytesRead = oClientPipe.Read(ResponseBuffer, 0, ResponseBuffer.Length);
                            MessageStream.Write(ResponseBuffer, 0, bytesRead);
                        }
                    }
                    catch (Exception se)
                    {
                        errormessage = "Error reading from pipe" + Environment.NewLine + se.Message;
                    }
                    oWait.Set();
                }, null);
            
            // Wait for the asynchronous read callback to finish reading or for a timeout to occur
            //if (!oWait.WaitOne(CLIENT_RECEIVE_TIMEOUT))
            if (!oWait.WaitOne())
            {
                errormessage = "A timeout occurred waiting for the XDP Machine Service to respond";
            }

            if (String.IsNullOrEmpty(errormessage))
            {
                // Return message
                return MessageStream.ToArray();
            }

            throw new XDPException(errormessage);
        }

        /// <summary>
        /// Process an XDPExceptionResponse message from the XDP Machine Service
        /// </summary>
        /// <param name="Message"></param>
        private static void ProcessXDPExceptionResponse(object Message)
        {
            XDPExceptionResponse oXDPExceptionResponse = (XDPExceptionResponse)Message;

            try
            {
                // Convert the exception messages into actual exceptions
                switch (oXDPExceptionResponse.ItemElementName)
                {
                    case ItemChoiceType.XDPBadParameter:
                        {
                            throw new XDPBadParameterException(((XDPExceptionResponseXDPBadParameter)oXDPExceptionResponse.Item).Parameter, ((XDPExceptionResponseXDPBadParameter)oXDPExceptionResponse.Item).Reason);
                        }
                    case ItemChoiceType.XDPBadSignature:
                        {
                            throw new XDPSignatureVerificationException((String)oXDPExceptionResponse.Item);
                        }
                    case ItemChoiceType.XDPNotAuthorized:
                        {
                            throw new XDPAuthorizationException((String)oXDPExceptionResponse.Item);
                        }
                    case ItemChoiceType.XDPUnknownIdentity:
                        {
                            throw new XDPInvalidIdentityException((String)oXDPExceptionResponse.Item);
                        }
                    case ItemChoiceType.XDPGeneralException:
                        {
                            throw new XDPException((String)oXDPExceptionResponse.Item);
                        }
                    default:
                        {
                            throw new XDPException("The XDP Machine Service returned an unknown XDPExceptionResponse");
                        }
                }
            }
            catch (InvalidCastException)
            {
                // Looks like the type of XDPExceptionResponse.Item does not match XDPExceptionResponse.ItemElementName
                throw new XDPException("The XDP Machine Service returned a badly formatted XDPExceptionResponse");
            }
        }

        /// <summary>
        /// Serializes an object to XML
        /// </summary>
        /// <param name="ObjectToSerialize">The object to serialize</param>
        /// <param name="Namespace">The XML namespace</param>
        /// <returns>The serialized object</returns>
        private static byte[] SerializeToXml(object ObjectToSerialize, string Namespace)
        {
            // Serialise Object
            MemoryStream oSerializedObject = new MemoryStream();
            try
            {
                System.Xml.Serialization.XmlSerializer oSerializer = new System.Xml.Serialization.XmlSerializer(ObjectToSerialize.GetType(), Namespace);
                oSerializer.Serialize(oSerializedObject, ObjectToSerialize);
            }
            catch (InvalidOperationException ioe)
            {
                throw new XDPException(ioe.Message);
            }
            return oSerializedObject.ToArray();
        }

        private static T DeserializeFromXml<T>(byte[] SerializedObject)
        {
            T DeserializedObject = default(T);
            MemoryStream SerializedObjectStream = new MemoryStream(SerializedObject);
            SerializedObjectStream.Seek(0, SeekOrigin.Begin);

            try
            {
                System.Xml.Serialization.XmlSerializer oSerializer = new System.Xml.Serialization.XmlSerializer(typeof(T));
                DeserializedObject = (T)oSerializer.Deserialize(SerializedObjectStream);
            }
            catch (Exception)
            {
                return default(T);
            }
            
            return DeserializedObject;
        }
    }
}
