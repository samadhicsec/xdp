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
using XDP.XDPCore;
using XDP.XDPCore.Settings;

namespace XDP.DomainService
{
    static class XDPDomainSettings
    {
        private const string DEFAULT_UPDATE_CLIENT_CRYPTO = "true";
        private const string DEFAULT_DATA_RECOVERY_GROUP_NAME = "";
        
        private static SettingsStore m_oStore;
        private const string UPDATE_CLIENT_CRYPTO = "Update Client Crypto";
        private const string DATA_RECOVERY_GROUP_NAME = "Data Recovery Group Name";
        public static XDPSettings Settings;
        private static string m_DomainName;

        static XDPDomainSettings()
        {
            m_oStore = new SettingsStore("XDP");
            Settings = new XDPSettings();
        }

        public static string DomainName
        {
            get
            {
                if (String.IsNullOrEmpty(m_DomainName))
                {
                    m_DomainName = XDPCommon.GetDomainName();
                    // If we could not find the Domain name (or if this is not installed on a domain machine), then m_DomainName will be empty and nothing should work
                }
                return m_DomainName;
            }
        }

        /// <summary>
        /// Whether or not the Domain Service should try to update the client if the client crypto does not match that set on the server
        /// </summary>
        public static bool UpdateClientCommonHeader
        {
            // Unless it is explicity set to false, we want this setting to return true
            get { return !(m_oStore.GetStringValue(UPDATE_CLIENT_CRYPTO, DEFAULT_UPDATE_CLIENT_CRYPTO).Equals("false", StringComparison.InvariantCultureIgnoreCase)) ; }
        }

        /// <summary>
        /// The Domain group name to add to the list of authorized identites that can decrypt messages
        /// </summary>
        public static string DataRecoveryGroupName
        {
            get { return m_oStore.GetStringValue(DATA_RECOVERY_GROUP_NAME, DEFAULT_DATA_RECOVERY_GROUP_NAME); }
        }
    }
}
