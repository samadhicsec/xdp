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
using System.Security.Principal;

namespace XDP.XDPCore.Identity
{
    internal class SidEqualityComparer : IEqualityComparer<SecurityIdentifier>
    {
        #region IEqualityComparer<SecurityIdentifier> Members

        public bool Equals(SecurityIdentifier x, SecurityIdentifier y)
        {
            if ((null == x) && (null == y))
                return true;
            if ((null == x) || (null == y))
                return false;
            if (x.Value.Equals(y.Value))
                return true;
            return false;
        }

        public int GetHashCode(SecurityIdentifier obj)
        {
            if(null == obj)
                return 0;
            return obj.Value.GetHashCode();
        }

        #endregion
    }


    /// <summary>
    /// Buckets a list of Identities into those from the domain and those specific to hosts.
    /// </summary>
    public class IdentityHelper
    {
        // This can be static as we will never create an XDPIdentityHelper for both the machine and domain, only ever one.
        protected static PrincipalContext m_oPrincipalContext;
        // Same reason as above, this can be static
        protected internal static IIdentityCache m_oCache;

        internal protected IdentityHelper(ContextType eContextType)
        {
            if (null == m_oPrincipalContext)
            {
                m_oPrincipalContext = new PrincipalContext(eContextType);
                m_oCache = CreateIdentityCache();
            }
            else if (m_oPrincipalContext.ContextType != eContextType)
                throw new XDPException("Cannot create a new XDPIdentityHelper with a different ContextType after first XDPIdentityHelper has been created");
            
        }

        protected virtual IIdentityCache CreateIdentityCache()
        {
            return new IdentityCache();
        }

        /// <summary>
        /// Queries Directory Services to get the SID of an Identity
        /// </summary>
        /// <param name="strIdentity">The Identity to get the SID for</param>
        /// <returns></returns>
        protected IdentityInfo GetInfoforIdentity(String strIdentity)
        {
            // Check the cache for a hit
            IdentityInfo oCacheEntry = m_oCache.Find(strIdentity);
            if (null != oCacheEntry)
                return oCacheEntry;
            bool bIsUser = true;
            SecurityIdentifier oIdentitySid = null;
            // Verify the identity is recognised by the local machine
            try
            {
                oIdentitySid = FindSid(strIdentity, out bIsUser);
            }
            catch (MultipleMatchesException)
            {
                throw new XDPInvalidIdentityException("There were multiple matches for the identity '" + strIdentity + "'");
            }
            if (null != oIdentitySid)
            {
                // Add to cache
                IdentityInfo ii = new IdentityInfo(oIdentitySid, bIsUser ? IdentityType.User : IdentityType.Group);
                m_oCache.Add(strIdentity, ii);

                return ii;
            }
            return null;
        }

        protected virtual SecurityIdentifier FindSid(String strIdentity, out bool bIsUser)
        {
            bIsUser = true;
            // Verify the identity is recognised by the local machine
            Principal oPrincipal = Principal.FindByIdentity(m_oPrincipalContext, strIdentity);
            if (null != oPrincipal)
            {
                if (oPrincipal is GroupPrincipal)
                    bIsUser = false;
                else if (oPrincipal is UserPrincipal)
                    bIsUser = true;
                else
                    throw new XDPInvalidIdentityException("The identity '" + strIdentity + "' was resolved, but was not a User or Group");
                return oPrincipal.Sid;
            }
            return null;
        }

        /// <summary>
        /// Checks the cache for an Identity based on the Identites Sid
        /// </summary>
        /// <param name="strIdentity">The SID of the Identity</param>
        /// <returns></returns>
        protected IdentityInfo GetCachedIdentityInfoForSid(String strSid)
        {
            return m_oCache.FindBySid(strSid);
        }

        /// <summary>
        /// Adds IdentityInfo to the cache.  Assumes it does not already exist in the cache
        /// </summary>
        /// <param name="Entry"></param>
        protected void AddToCache(String Identity, IdentityInfo Entry)
        {
            m_oCache.Add(Identity, Entry);
        }

        /// <summary>
        /// Gets the current users identity.
        /// </summary>
        /// <param name="oSecurityIdentifier">Gets set to the SecurityIdentifier of the current user</param>
        /// <param name="DomainName">If the current user is part of a domain, this gets set to the domain name, otherwise String.Empty</param>
        /// <param name="MachineName">If the current user is part of a machine, this gets set to the machine name, otherwise String.Empty</param>
        public static void GetCurrentUser(out SecurityIdentifier oSecurityIdentifier, out String DomainName, out String MachineName)
        {
            DomainName = String.Empty;
            MachineName = String.Empty;
            // Get the current user.  We don't care if we are impersonating or not, this check is done elsewhere
            WindowsIdentity oUser = WindowsIdentity.GetCurrent();
            oSecurityIdentifier = oUser.User;

            // .NET weirdness, if the current user is NOT a domain user, then Environment.UserDomainName returns the machine name
            if (Environment.UserDomainName.Equals(Environment.MachineName, StringComparison.InvariantCultureIgnoreCase))
            {
                // User belongs to a machine, which has to be this local machine (otherwise how could they be logged in)
                MachineName = Environment.MachineName;
            }
            else
            {
                DomainName = Environment.UserDomainName;
            }
        }
    }
}
