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
using System.ServiceProcess;
using System.Threading;
using log4net;
using log4net.Config;
using XDP.XDPCore.Messaging;

namespace XDP.DomainService
{
    public partial class XDPDomainService : ServiceBase
    {
        private static readonly ILog log = LogManager.GetLogger(typeof(XDPDomainService));

        XDP.XDPCore.Messaging.Listener m_oListener;

        public XDPDomainService()
        {
            // We load the log4net configuration programmatically as using an attribute in AssemblyInfo.cs is diffcult because we are loaded
            // as a service and hence the current directory is windows/system32.  Hence load using full path.
            XmlConfigurator.ConfigureAndWatch(new System.IO.FileInfo(System.Reflection.Assembly.GetCallingAssembly().Location + ".log4net"));

            InitializeComponent();

            this.ServiceName = "XDPDomainService";
            this.CanStop = true;
            this.CanPauseAndContinue = false;
            this.AutoLog = true;
        }

        protected override void OnStart(string[] args)
        {
            log.Info("Starting XDPDomainService service");
            
            // TODO Are there more privileges we could drop?  We should be running as a Domain User that can logon as a service.
            // We have no more special privileges than any other Domain User.  Can a non-Domain User even connect to us?  Assume probably.

            // Create a KerberosServer to accept incoming client connections
            NegotiateServer oKerberosServer = new NegotiateServer(XDPDomainSettings.Settings.DomainPort, XDPDomainSettings.Settings.NetworkTimout);
            // Create a DomainRequestProcessor to process requests from the client
            DomainRequestProcessor oDomainRequestProcessor = new DomainRequestProcessor();

            // Start the listener
            m_oListener = new XDP.XDPCore.Messaging.Listener(oKerberosServer, oDomainRequestProcessor.DomainRequests);
            ThreadPool.QueueUserWorkItem(new WaitCallback(m_oListener.Listen));
        }

        protected override void OnStop()
        {
            log.Info("Stopping XDPDomainService service");
            // Stop the listener
            m_oListener.StopListening();
        }
    }
}
