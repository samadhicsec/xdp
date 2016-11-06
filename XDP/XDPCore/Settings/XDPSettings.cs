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

namespace XDP.XDPCore.Settings
{
    /// <summary>
    /// Allows access to all the XDP configurable settings.  Settings are read directly from the store everytime, so no need to monitor the store
    /// to determine if it has been updated.
    /// </summary>
    internal class XDPSettings : IXDPSettings
    {
        private const ushort DEFAULT_DOMAIN_PORT = 3483;
        private const int DEFAULT_NETWORK_TIMEOUT = 60000;
        private const CommunicationSecurityLevel DEFAULT_COMMS_SECURITY = CommunicationSecurityLevel.Kerberos;
        private const int DEFAULT_SERVICE_MIN_THREAD_POOL_SIZE = 5;

        protected SettingsStore m_oStore;
        private const string DOMAIN_PORT = "Domain Port";
        private const string NETWORK_TIMEOUT = "Network Timeout";
        private const string COMMS_SECURITY_LEVEL = "Communications Security";
        private const string SERVICE_MIN_THREAD_POOL_SIZE = "Service Min Thread Pool Size";
        private IXDPCryptoSettings m_oXDPCryptoSettings;        

        //public enum CommunicationSecurityLevel
        //{
        //    Kerberos,
        //    KerberosOrNtlm
        //}

        public XDPSettings()
        {
            m_oStore = new SettingsStore("XDP");

            m_oXDPCryptoSettings = new XDPCryptoSettings();
        }

        /// <summary>
        /// The port the XDP Domain Service is listening on
        /// </summary>
        public ushort DomainPort
        {
            get { return (ushort)m_oStore.GetUIntValue(DOMAIN_PORT, DEFAULT_DOMAIN_PORT); }
        }

        /// <summary>
        /// The Crypto settings from the settings store
        /// </summary>
        public IXDPCryptoSettings CryptoSettings
        {
            get { return m_oXDPCryptoSettings; }
        }

        public uint NetworkTimout
        {
            get { return m_oStore.GetUIntValue(NETWORK_TIMEOUT, DEFAULT_NETWORK_TIMEOUT); }
        }

        /// <summary>
        /// Returns the configured level of security for client/server communications
        /// </summary>
        public CommunicationSecurityLevel CommunicationSecurity
        {
            get 
            {
                try
                {
                    return (CommunicationSecurityLevel)Enum.Parse(typeof(CommunicationSecurityLevel), m_oStore.GetStringValue(COMMS_SECURITY_LEVEL, DEFAULT_COMMS_SECURITY.ToString()));
                }
                catch { }
                return DEFAULT_COMMS_SECURITY;
            }
        }

        /// <summary>
        /// The maximum number of threads for the Thread Pool.  Only relevant when the service is started.
        /// </summary>
        public uint ThreadPoolSize
        {
            get
            {
                uint size = m_oStore.GetUIntValue(SERVICE_MIN_THREAD_POOL_SIZE, DEFAULT_SERVICE_MIN_THREAD_POOL_SIZE);
                // Enforce a maximum
                if (size > 20)
                    size = 20;
                // Enforce a minimum
                if (size < DEFAULT_SERVICE_MIN_THREAD_POOL_SIZE)
                    size = DEFAULT_SERVICE_MIN_THREAD_POOL_SIZE;
                return size;
            }
        }
    }
}
