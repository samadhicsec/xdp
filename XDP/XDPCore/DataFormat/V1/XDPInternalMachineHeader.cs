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
using System.DirectoryServices.AccountManagement;
using System.Security.Cryptography;
using System.Security.Principal;
using System.Threading;
using log4net;

namespace XDP.XDPCore.DataFormat.V1
{
    /// <remarks/>
    [System.SerializableAttribute()]
    [System.Xml.Serialization.XmlTypeAttribute(AnonymousType = true, Namespace = "urn:com.XDP.XDPData")]
    [System.Xml.Serialization.XmlRootAttribute(Namespace = "urn:com.XDP.XDPData", IsNullable = false)]
    public class XDPInternalMachineHeader
    {
        private static readonly ILog log = LogManager.GetLogger(typeof(V1DataFormatFactory));
        private string m_HostnameField;

        private string[] m_XDPAuthorizedIdentitiesField;

        private byte[] m_XDPEncryptedKeysField;

        /// <summary>
        /// Parameterless constructor used for Serialization
        /// </summary>
        public XDPInternalMachineHeader()
        {

        }

        internal XDPInternalMachineHeader(String Hostname, List<SecurityIdentifier> oAuthorizedIdentities, XDPKeys oXDPKeys)
        {
            m_HostnameField = Hostname;
            m_XDPAuthorizedIdentitiesField = new string[oAuthorizedIdentities.Count];
            for (int i = 0; i < oAuthorizedIdentities.Count; i++)
                m_XDPAuthorizedIdentitiesField[i] = oAuthorizedIdentities[i].ToString();

            // Encrypt using DPAPI
            m_XDPEncryptedKeysField = ProtectedData.Protect(XDPCommon.SerializeToXml(oXDPKeys, "urn:com.XDP.XDPMessages"), null, DataProtectionScope.CurrentUser); 
        }

        /// <summary>
        /// Validate the format and values of this XDPInternalMachineHeader
        /// </summary>
        internal void Validate()
        {
            if (String.IsNullOrEmpty(m_HostnameField))
                throw new XDPBadParameterException("XDPInternalMachineHeader.Hostname", "Value was null or empty");
            if(null == m_XDPAuthorizedIdentitiesField)
                throw new XDPBadParameterException("XDPInternalMachineHeader.XDPAuthorizedIdentities", "Parameter was null");
            if (0 == m_XDPAuthorizedIdentitiesField.Length)
                throw new XDPBadParameterException("XDPInternalMachineHeader.XDPAuthorizedIdentities", "Array was empty");
            if (null == m_XDPEncryptedKeysField)
                throw new XDPBadParameterException("XDPInternalMachineHeader.XDPEncryptedKeys", "Parameter was null");
            if (0 == m_XDPEncryptedKeysField.Length)
                throw new XDPBadParameterException("XDPInternalMachineHeader.XDPEncryptedKeys", "Array was empty");
        }

        /// <summary>
        /// Checks if oSecurityIdentifier is amongst the list of authorized identities, if it is then XDPKeys is recovered
        /// </summary>
        /// <param name="oSecurityIdentifier">The identity to check for decryption rights</param>
        /// <returns>The decrypted XDPKeys, or null if the user is not authorized to decrypt</returns>
        internal XDPKeys GetXDPKeys(SecurityIdentifier oSecurityIdentifier)
        {
            bool bAuthorized = false;

            if (null == oSecurityIdentifier)
                return null;
            if (null == m_XDPAuthorizedIdentitiesField)
                return null;

            // Check to see if the SID matches any listed
            for (int i = 0; i < m_XDPAuthorizedIdentitiesField.Length; i++)
            {
                if (m_XDPAuthorizedIdentitiesField[i].Equals(oSecurityIdentifier.ToString(), StringComparison.InvariantCultureIgnoreCase))
                {
                    log.Debug("Current user is explicitly listed as an AuthorisedIdentity");
                    bAuthorized = true;
                    break;
                }
            }
            if (!bAuthorized)
            {
                // No match, but some SIDs might be groups, so check for membership in groups
                PrincipalContext oPrincipalContext = new PrincipalContext(ContextType.Machine);
                // Get UserPrinciple
                UserPrincipal oUserPrincipal = null;
                try
                {
                    oUserPrincipal = UserPrincipal.FindByIdentity(oPrincipalContext, oSecurityIdentifier.ToString());
                }
                catch (MultipleMatchesException)
                {
                    throw new XDPInvalidIdentityException("There were multiple matches for the identity '" + oSecurityIdentifier.ToString() + "'");
                }
                if (null == oUserPrincipal)
                    return null;
                // Check each SID to see if it is a group
                for (int i = 0; i < m_XDPAuthorizedIdentitiesField.Length; i++)
                {
                    GroupPrincipal oGroupPrincipal = null;
                    try
                    {
                        oGroupPrincipal = GroupPrincipal.FindByIdentity(oPrincipalContext, m_XDPAuthorizedIdentitiesField[i]);
                    }
                    catch (MultipleMatchesException)
                    {
                        throw new XDPInvalidIdentityException("There were multiple matches for the identity '" + m_XDPAuthorizedIdentitiesField[i] + "'");
                    }
                    catch (PrincipalOperationException e)
                    {
                        if (!(e.InnerException is System.Runtime.InteropServices.COMException))
                            throw e;
                    }
                    if (null == oGroupPrincipal)
                        continue;
                    // Check to see if user is a member of the group
                    if (oUserPrincipal.IsMemberOf(oGroupPrincipal))
                    {
                        log.Debug("Current user is a member of a group listed as an AuthorisedIdentity");
                        bAuthorized = true;
                        break;
                    }
                }
            }

            if (!bAuthorized)
                return null;

            // In order to decrypt and get XDPKeys we need to be running in our non-impersonated context.  To make this tidy, we start a new thread, which
            // we can RevertToSelf in, and thus the current thread remains as the impersonated user
            XDPKeys oXDPKeys = null;
            Exception InternalException = null;
            Thread DecryptThread = new Thread(delegate()
            {
                try
                {
                    // Revert to self
                    NativeWin32Functions.RevertToSelf();

                    byte[] SerialisedXDPKeys = ProtectedData.Unprotect(m_XDPEncryptedKeysField, null, DataProtectionScope.CurrentUser);
                    oXDPKeys = (XDPKeys)XDPCommon.DeserializeFromXml<XDPKeys>(SerialisedXDPKeys);
                }
                catch (Exception e)
                {
                    InternalException = e;
                }
            });
            DecryptThread.Start();
            if (!DecryptThread.Join(10000))
            {
                // Something bad happened in our decrypt thread
                DecryptThread.Abort();
                throw new XDPException("Thread to unprotect the decryption key timed out");
            }
            if (InternalException != null)
                throw new XDPException("An error occured unprotecting the data: " + InternalException.Message);

            return oXDPKeys;
        }

        /// <remarks/>
        public string Hostname
        {
            get
            {
                return this.m_HostnameField;
            }
            set
            {
                this.m_HostnameField = value;
            }
        }

        /// <remarks/>
        [System.Xml.Serialization.XmlArrayItemAttribute("Identity", IsNullable = false)]
        public string[] XDPAuthorizedIdentities
        {
            get
            {
                return this.m_XDPAuthorizedIdentitiesField;
            }
            set
            {
                this.m_XDPAuthorizedIdentitiesField = value;
            }
        }

        /// <remarks/>
        [System.Xml.Serialization.XmlElementAttribute(DataType = "hexBinary")]
        public byte[] XDPEncryptedKeys
        {
            get
            {
                return this.m_XDPEncryptedKeysField;
            }
            set
            {
                this.m_XDPEncryptedKeysField = value;
            }
        }
    }
}
