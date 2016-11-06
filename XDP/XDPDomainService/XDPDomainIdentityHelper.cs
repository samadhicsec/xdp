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
using log4net;
using XDP.XDPCore;
using XDP.XDPCore.Identity;

namespace XDP.DomainService
{
    class XDPDomainIdentityHelper : IdentityHelper
    {
        private static readonly ILog log = LogManager.GetLogger(typeof(XDPDomainIdentityHelper));

        public XDPDomainIdentityHelper()
            : base(ContextType.Domain)
        {

        }

        /// <summary>
        /// Verifies that all the requested Identities are members of the Domain
        /// </summary>
        /// <param name="oIdentities"></param>
        /// <param name="oSids"></param>
        /// <returns></returns>
        public void VerifyIdentities(string[] oIdentities, List<SecurityIdentifier> oSids)
        {
            if ((null == oIdentities) || (0 == oIdentities.Length))
                throw new XDPInvalidIdentityException("No identities were specified");
            if (null == oSids)
                throw new XDPException("Parameter oSids was null");     // This should never happen

            List<string> oIdentitesList = new List<string>(oIdentities);

            // Check whether or not we need to add to add the Domain Recovery Group to the list of Authorised Identities
            string DataRecoveryGroupName = XDPDomainSettings.DataRecoveryGroupName;
            if (!String.IsNullOrEmpty(DataRecoveryGroupName))
            {
                ContextHelper oDRGNContextHelper = new ContextHelper(DataRecoveryGroupName);
                if (XDPCommon.DomainsEqual(oDRGNContextHelper.Context, XDPDomainSettings.DomainName) && (null != GetInfoforIdentity(DataRecoveryGroupName)))
                {
                    oIdentitesList.Add(oDRGNContextHelper.Identity);
                }
            }

            SortedList<string, SecurityIdentifier> oSortedSids = new SortedList<string, SecurityIdentifier>();

            for (int i = 0; i < oIdentitesList.Count; i++)
            {
                ContextHelper oContextHelper = new ContextHelper(oIdentitesList[i]);
                if (XDPCommon.DomainsEqual(oContextHelper.Context, XDPDomainSettings.DomainName))
                {
                    IdentityInfo oId = GetInfoforIdentity(oIdentitesList[i]);
                    if (null != oId)
                    {
                        // If we found a Principal add it.  We also handle duplicates here, which we ignore.
                        if (!oSortedSids.ContainsKey(oId.oSid.Value))
                        {
                            oSortedSids.Add(oId.oSid.Value, oId.oSid);
                            log.Debug("Added " + oId.oSid.Value + " to authorized identities");
                        }
                    }
                    else
                    {
                        // throw an exception
                        throw new XDPInvalidIdentityException("'" + oIdentities[i] + "' is not a valid Domain identity");
                    }
                }
            }
            oSids.AddRange(oSortedSids.Values);
        }

        public bool IsAMemberOfAuthorizedGroup(WindowsIdentity oId, string[] oIdentities)
        {
            if ((null == oId) || (null == oIdentities) || (0 == oIdentities.Length))
                return false;

            WindowsPrincipal oWindowsPrincipal = new WindowsPrincipal(oId);

            // See if we can get a hit from the cache
            IdentityInfo oCallerIdInfo = GetCachedIdentityInfoForSid(oId.User.ToString());
            if ((null != oCallerIdInfo) && (oCallerIdInfo.MemberOf.Count > 0))
            {
                // Check authorised groups to see if any are in the cached list of groups this Identity is a member of
                for (int i = 0; i < oIdentities.Length; i++)
                {
                    if (oCallerIdInfo.MemberOf.ContainsKey(oIdentities[i]))
                        return true;
                }
            }
            if (null == oCallerIdInfo)
            {
                oCallerIdInfo = new IdentityInfo(oId.User, XDP.XDPCore.Identity.IdentityType.User);
                AddToCache(oId.Name, oCallerIdInfo);
            }
            
            // Use the System to determine group membership
            for (int i = 0; i < oIdentities.Length; i++)
            {
                IdentityInfo oIdInfo = GetInfoforIdentity(oIdentities[i]);
                if ((null != oIdInfo) && (XDP.XDPCore.Identity.IdentityType.Group == oIdInfo.eType))
                {
                    if (oWindowsPrincipal.IsInRole(oCallerIdInfo.oSid))
                    {
                        // Cache the information
                        oCallerIdInfo.MemberOf.Add(oIdentities[i], oIdentities[i]);
                        return true;
                    }
                }
            }
            return false;
        }
    }
}
