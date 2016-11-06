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

namespace XDP.XDPCore.Settings
{
    internal class XDPMachineSettings : XDPSettings, IXDPMachineSettings
    {
        private const string DEFAULT_DOMAIN_HOSTNAME = "";
        private const string DEFAULT_XDP_DS_ACCOUNT = "XDPDSAccount";
        private const string DOMAIN_HOSTNAME = "Domain Hostname";
        
        private const string XDP_DS_ACCOUNT = "XDP Domain Service Account";
        
        public XDPMachineSettings()
            : base()
        {
        }

        /// <summary>
        /// The hostname of the machine running the XDP Domain Service
        /// </summary>
        public string DomainHostname
        {
            get { return m_oStore.GetStringValue(DOMAIN_HOSTNAME, DEFAULT_DOMAIN_HOSTNAME); }
        }

        /// <summary>
        /// The account the XDP Domain Service is running as
        /// </summary>
        public string XDPDSAccount
        {
            get { return m_oStore.GetStringValue(XDP_DS_ACCOUNT, DEFAULT_XDP_DS_ACCOUNT); }
        }
    }
}
