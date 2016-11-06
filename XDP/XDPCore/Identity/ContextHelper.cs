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
using System.Linq;
using System.Security.Principal;

namespace XDP.XDPCore.Identity
{
    /// <summary>
    /// Gets the context and user from a Windows username of the form context\user, user@context or user (context defaults to hostname).
    /// </summary>
    internal class ContextHelper
    {
        private string m_Context;
        private string m_User;
        private string m_Identity;

        // Variations on the names of the well known service accounts
        private static String[] WellKnownServiceAccounts = new String[] { "LocalSystem", "System", "NetworkService", "Network", "LocalService", "Local" };
        // Corresponding well known service account SIDs
        private static SecurityIdentifier[] WellKnownServiceAccountsSids = new SecurityIdentifier[] 
            { 
                new SecurityIdentifier(WellKnownSidType.LocalSystemSid, null), 
                new SecurityIdentifier(WellKnownSidType.LocalSystemSid, null),
                new SecurityIdentifier(WellKnownSidType.NetworkServiceSid, null),
                new SecurityIdentifier(WellKnownSidType.NetworkServiceSid, null),
                new SecurityIdentifier(WellKnownSidType.LocalServiceSid, null),
                new SecurityIdentifier(WellKnownSidType.LocalServiceSid, null)
            };

        public ContextHelper(String Identity)
        {
            // See if it is a SecurityIdentifier
            bool bIsSid = false;
            try
            {
                SecurityIdentifier oSID = new SecurityIdentifier(Identity);
                Identity = oSID.Value;
                bIsSid = true;
            }
            catch { }

            if(!bIsSid)
                Identity = CheckForWellKnownName(Identity, out bIsSid);

            if (Identity.Contains('\\'))
            {
                m_Context = Identity.Substring(0, Identity.IndexOf('\\'));
                m_User = Identity.Substring(Identity.IndexOf('\\') + 1, Identity.Length - (Identity.IndexOf('\\') + 1));
            }
            else if (Identity.Contains('@'))
            {
                m_User = Identity.Substring(0, Identity.IndexOf('@'));
                m_Context = Identity.Substring(Identity.IndexOf('@') + 1, Identity.Length - (Identity.IndexOf('@') + 1));
            }
            else
            {
                m_User = Identity;
            }
            // This catches scenarios like 'user@', '\user' and 'user'; in each case assume local machine
            if (String.IsNullOrEmpty(m_Context))
                m_Context = Environment.MachineName;

            if (!bIsSid)
                m_Identity = m_Context + "\\" + m_User;
            else
                m_Identity = m_User;
        }

        /// <summary>
        /// The method we use for resolving Identities to Principals does not recognise certain well known accounts, so
        /// we also support an Identity that is a SID, and an Identity that is one of the well known service accounts
        /// e.g. LocalSystem, NetworkService, LocalService
        /// </summary>
        private String CheckForWellKnownName(String Identity, out bool bIsSid)
        {
            bIsSid = false;
            // Compare the Identity to well-known service account names (and variations), if found, replace with SID
            String bareIdentity = Identity.Replace(" ", String.Empty);    // Remove all spaces

            for (int i = 0; i < WellKnownServiceAccounts.Length; i++)
            {
                if (bareIdentity.Equals(WellKnownServiceAccounts[i], StringComparison.InvariantCultureIgnoreCase) ||
                    bareIdentity.Equals("NTAUTHORITY\\" + WellKnownServiceAccounts[i], StringComparison.InvariantCultureIgnoreCase) ||
                    bareIdentity.Equals(Environment.MachineName + "\\" + WellKnownServiceAccounts[i], StringComparison.InvariantCultureIgnoreCase)
                    )
                {
                    bIsSid = true;
                    return WellKnownServiceAccountsSids[i].Value;
                }
            }

            return Identity;
        }

        public string Context
        {
            get { return m_Context; }
        }
        public string User
        {
            get { return m_User; }
        }

        public string Identity
        {
            get { return m_Identity; }
        }
    }
}
