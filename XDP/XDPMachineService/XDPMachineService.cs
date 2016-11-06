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
using System.ServiceProcess;
using System.Threading;
using log4net;
using log4net.Config;
using XDP.MachineService.Messages;
using XDP.XDPCore;
using XDP.XDPCore.DataFormat;
using XDP.XDPCore.Messaging;

namespace XDP.MachineService
{
    public partial class XDPMachineService : ServiceBase
    {
        private static readonly ILog log = LogManager.GetLogger(typeof(XDPMachineService));

        Listener m_oProtectDataListener;
        Listener m_oUnprotectDataListener;

        public XDPMachineService()
        {
            // We load the log4net configuration programmatically as using an attribute in AssemblyInfo.cs is diffcult because we are loaded
            // as a service and hence the current directory is windows/system32.  Hence load using full path.
            XmlConfigurator.ConfigureAndWatch(new System.IO.FileInfo(System.Reflection.Assembly.GetCallingAssembly().Location + ".log4net"));

            InitializeComponent();

            this.ServiceName = "XDPMachineService";
            this.CanStop = true;
            this.CanPauseAndContinue = false;
            this.AutoLog = true;
        }

        protected override void OnStart(string[] args)
        {
            log.Info("Starting XDPMachineService service");

            // Are there more privileges we could drop?  We should be running as a local User that can logon as a service.
            // We have no more special privileges than any other local User, in fact less as we are not even a member of the Users group.

            StartProtectDataThread();
            StartUnprotectDataThread();
        }

        protected override void OnStop()
        {
            log.Info("Stopping XDPMachineService service");
            m_oProtectDataListener.StopListening();
        }

        private void StartProtectDataThread()
        {
            log.Debug("Entering " + System.Reflection.MethodInfo.GetCurrentMethod().Name);
            // Create Callback Dictionary for received messages
            Dictionary<Type, MessageProcessorCallback> oProtectDataRequests = new Dictionary<Type, MessageProcessorCallback>() 
            { 
                { typeof(XDPRequestProtectData), ProcessProtectData},
            };

            // Create Server
            NamedPipeServer oNamedPipeServer = new NamedPipeServer("\\\\.\\pipe\\XDPProtectData");

            // Start server listener thread
            m_oProtectDataListener = new Listener(oNamedPipeServer, oProtectDataRequests);
            ThreadPool.QueueUserWorkItem(new WaitCallback(m_oProtectDataListener.Listen));

            log.Debug("Exiting " + System.Reflection.MethodInfo.GetCurrentMethod().Name);
        }

        public void ProcessProtectData(object Message, MessageSender oMsgSender)
        {
            log.Debug("Entering " + System.Reflection.MethodInfo.GetCurrentMethod().Name);
            
            // Variable to store any exception that occurs in delegate
            Exception exXDPException = null;

            XDPRequestProtectData oRequestProtectData = (XDPRequestProtectData)Message;
            
            XDPData oXDPData = new XDPData(new XDP.XDPCore.DataFormat.V1.V1DataFormatFactory());

            NamedPipeServer oNamedPipeServer = oMsgSender.Server as NamedPipeServer;
            System.IO.Pipes.NamedPipeServerStream oNamedPipeServerStream = oNamedPipeServer.GetClientStream(oMsgSender.Client) as System.IO.Pipes.NamedPipeServerStream;

            // Encrypt using XDP
            oNamedPipeServerStream.RunAsClient(
                delegate()
                {
                    try
                    {
                        // Encrypt using XDP
                        oXDPData.Encrypt(oRequestProtectData.UserData, oRequestProtectData.XDPAuthorizedIdentities);
                    }
                    catch (Exception e)
                    {
                        exXDPException = e;
                    }
                }
            );

            if (null != exXDPException)  // Process exception
            {
                log.Debug("An error occurred during encryption", exXDPException);
                log.Warn(exXDPException.Message);
                // Turn Exception into a message to send to the client
                XDPExceptionResponse oXDPExceptionResponse = CreateXDPExceptionResponse(exXDPException);
                oMsgSender.SendWithNoResponseExpected(oXDPExceptionResponse);
            }
            else    // Send back ciphertext
            {
                byte[] ciphertext = oXDPData.Serialize();

                // Create response
                XDPResponseProtectData oResponseProtectData = new XDPResponseProtectData();
                oResponseProtectData.ProtectedData = ciphertext;

                // Respond
                oMsgSender.SendWithNoResponseExpected(oResponseProtectData);
            }

            log.Debug("Exiting " + System.Reflection.MethodInfo.GetCurrentMethod().Name);
        }

        private void StartUnprotectDataThread()
        {
            log.Debug("Entering " + System.Reflection.MethodInfo.GetCurrentMethod().Name);
            // Create Callback Dictionary for received messages
            Dictionary<Type, MessageProcessorCallback> oUnprotectDataRequests = new Dictionary<Type, MessageProcessorCallback>() 
            { 
                { typeof(XDPRequestUnprotectData), ProcessUnprotectData},
            };

            // Create Server
            NamedPipeServer oNamedPipeServer = new NamedPipeServer("\\\\.\\pipe\\XDPUnprotectData");

            // Start server listener thread
            m_oUnprotectDataListener = new Listener(oNamedPipeServer, oUnprotectDataRequests);
            ThreadPool.QueueUserWorkItem(new WaitCallback(m_oUnprotectDataListener.Listen));

            log.Debug("Exiting " + System.Reflection.MethodInfo.GetCurrentMethod().Name);
        }

        public void ProcessUnprotectData(object Message, MessageSender oMsgSender)
        {
            log.Debug("Entering " + System.Reflection.MethodInfo.GetCurrentMethod().Name);
            
            // Variable to store any exception that occurs in delegate
            Exception exXDPException = null;

            XDPRequestUnprotectData oRequestUnprotectData = (XDPRequestUnprotectData)Message;

            XDPData oXDPData = new XDPData(new XDP.XDPCore.DataFormat.V1.V1DataFormatFactory());
            oXDPData.Deserialize(oRequestUnprotectData.encryptedData);
            byte[] plaintext = null;

            // TEST Allow XDPData to impersonate caller
            NamedPipeServer oNamedPipeServer = oMsgSender.Server as NamedPipeServer;
            System.IO.Pipes.NamedPipeServerStream oNamedPipeServerStream = oNamedPipeServer.GetClientStream(oMsgSender.Client) as System.IO.Pipes.NamedPipeServerStream;
            oNamedPipeServerStream.RunAsClient(
                delegate()
                {
                    try
                    {
                        // Decrypt using XDP
                        plaintext = oXDPData.Decrypt();
                    }
                    catch (Exception e)
                    {
                        exXDPException = e;
                    }
                }
            );

            if (null != exXDPException)  // Process exception
            {
                // Turn Exception into a message to send to the client
                XDPExceptionResponse oXDPExceptionResponse = CreateXDPExceptionResponse(exXDPException);
                oMsgSender.SendWithNoResponseExpected(oXDPExceptionResponse);
            }
            else    // Send back plaintext
            {
                // Create response
                XDPResponseUnprotectData oResponseUnprotectData = new XDPResponseUnprotectData();
                oResponseUnprotectData.UnprotectedData = plaintext;

                // Respond
                oMsgSender.SendWithNoResponseExpected(oResponseUnprotectData);
            }

            log.Debug("Exiting " + System.Reflection.MethodInfo.GetCurrentMethod().Name);
        }

        /// <summary>
        /// Convert an exception into an XDPExceptionResponse object that can be serialized and sent to the client.
        /// </summary>
        /// <param name="ex"></param>
        /// <returns></returns>
        private XDPExceptionResponse CreateXDPExceptionResponse(Exception ex)
        {
            log.Debug("Entering " + System.Reflection.MethodInfo.GetCurrentMethod().Name);
            XDPExceptionResponse oXDPExceptionResponse = new XDPExceptionResponse();

            if (ex is XDPBadParameterException)
            {
                oXDPExceptionResponse.ItemElementName = ItemChoiceType.XDPBadParameter;
                XDPExceptionResponseXDPBadParameter oXDPExceptionResponseXDPBadParameter = new XDPExceptionResponseXDPBadParameter();
                oXDPExceptionResponseXDPBadParameter.Parameter = (ex as XDPBadParameterException).Parameter;
                oXDPExceptionResponseXDPBadParameter.Reason = (ex as XDPBadParameterException).Reason;
                oXDPExceptionResponse.Item = oXDPExceptionResponseXDPBadParameter;
            }
            else if (ex is XDPAuthorizationException)
            {
                oXDPExceptionResponse.ItemElementName = ItemChoiceType.XDPNotAuthorized;
                oXDPExceptionResponse.Item = (ex as XDPAuthorizationException).Message;
            }
            else if (ex is XDPSignatureVerificationException)
            {
                oXDPExceptionResponse.ItemElementName = ItemChoiceType.XDPBadSignature;
                oXDPExceptionResponse.Item = (ex as XDPSignatureVerificationException).Message;
            }
            else if (ex is XDPInvalidIdentityException)
            {
                oXDPExceptionResponse.ItemElementName = ItemChoiceType.XDPUnknownIdentity;
                oXDPExceptionResponse.Item = (ex as XDPInvalidIdentityException).Message;
            }
            else if (ex is XDPException)
            {
                oXDPExceptionResponse.ItemElementName = ItemChoiceType.XDPGeneralException;
                oXDPExceptionResponse.Item = (ex as XDPException).Message;
            }
            else
            {
                oXDPExceptionResponse.ItemElementName = ItemChoiceType.XDPGeneralException;
                oXDPExceptionResponse.Item = typeof(Exception).Name + ":" + ex.Message;
            }

            log.Debug("Exiting " + System.Reflection.MethodInfo.GetCurrentMethod().Name);
            return oXDPExceptionResponse;
        }
    }
}
