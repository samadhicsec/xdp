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
using System.Linq;
using System.Security.Principal;
using System.Threading;
using log4net;

namespace XDP.XDPCore.Identity
{
    public class MachineIdentityHelper : IdentityHelper
    {
        private static readonly ILog log = LogManager.GetLogger(typeof(MachineIdentityHelper));
        private enum State
        {
            IdentitiesUnresolved,
            IdentitiesResolved
        };
        struct ThreadParams
        {
            public String Id;
            public ContextHelper oContextHelper;
            public AutoResetEvent oAutoResetEvent;
        }
        private object m_ExceptionLock = new object();
        private object m_ProcessIdLock = new object();
        private XDPInvalidIdentityException m_oXDPInvalidIdentityException;

        private List<String> m_DomainIdentities;
        private Dictionary<String, List<SecurityIdentifier>> m_HostIdentitiesDict;
        private List<AutoResetEvent> m_oResolvingIdentitiesWaitHandles;

        internal MachineIdentityHelper() : base(ContextType.Machine)
        {
            m_DomainIdentities = new List<String>();
            m_HostIdentitiesDict = new Dictionary<string, List<SecurityIdentifier>>();
            m_HostIdentitiesDict.Add(Environment.MachineName, new List<SecurityIdentifier>());
            m_oResolvingIdentitiesWaitHandles = new List<AutoResetEvent>();
        }

        internal void AddIdentites(string[] Identities)
        {
            log.Debug("Entering " + System.Reflection.MethodInfo.GetCurrentMethod().Name);
            log.Debug("Identifying " + Identities.Length + " users");

            m_oXDPInvalidIdentityException = null;
            // For each Identity, determine if it is a local machine or domain account/group.  If it is local confirm
            // it actually exists, if it is domain, then just copy, the XDP Domain Service will validate    
            for (int i = 0; i < Identities.Length; i++)
            { 
                String Identity = Identities[i];
                ContextHelper oContextHelper = new ContextHelper(Identity);
                if (oContextHelper.Context.Equals(Environment.MachineName, StringComparison.InvariantCultureIgnoreCase))
                {
                    // Check the cache for a hit
                    IdentityInfo oId = m_oCache.Find(oContextHelper.Identity);
                    if (null != oId)
                    {
                        ProcessIdentity(oId, Identity, oContextHelper);
                    }
                    else
                    {
                        // It can take several seconds to lookup a local user
                        m_oResolvingIdentitiesWaitHandles.Add(new AutoResetEvent(false));
                        
                        // Since we are in a loop, we need to pass variables into the anonymous method
                        ThreadParams oThreadParams;
                        oThreadParams.Id = Identity;
                        oThreadParams.oContextHelper = oContextHelper;
                        oThreadParams.oAutoResetEvent = m_oResolvingIdentitiesWaitHandles[m_oResolvingIdentitiesWaitHandles.Count - 1];
                        
                        ThreadPool.QueueUserWorkItem(new WaitCallback(
                            delegate(object o)
                            {
                                ThreadParams oLocalThreadParams = (ThreadParams)o;
                                try
                                {

                                    oId = GetInfoforIdentity(oLocalThreadParams.oContextHelper.Identity);
                                    ProcessIdentity(oId, oLocalThreadParams.Id, oLocalThreadParams.oContextHelper);
                                }
                                catch (XDPInvalidIdentityException e)
                                {
                                    lock (m_ExceptionLock)
                                    {
                                        m_oXDPInvalidIdentityException = e;
                                    }
                                }
                                finally
                                {
                                    oLocalThreadParams.oAutoResetEvent.Set();
                                }
                            }
                        ), oThreadParams);
                    }
                }
                else if (XDPCommon.DomainsEqual(oContextHelper.Context, XDPCommon.GetDomainName()))
                {
                    // We let the XDP Domain Service determine if the supplied Identites are valid
                    m_DomainIdentities.Add(Identity);
                   log.Debug("Adding domain authorized identity: " + oContextHelper.Identity);
                }
                else
                {
                    throw new XDPInvalidIdentityException("The context of '" + Identity + "' was not the local machine or the domain");
                }
            }

            // If we got an exception looking up an Identity, then m_oXDPInvalidIdentityException will have a list of the invalid Identities
            if (null != m_oXDPInvalidIdentityException)
                throw m_oXDPInvalidIdentityException;

            log.Debug("Exiting " + System.Reflection.MethodInfo.GetCurrentMethod().Name);
        }

        private void ProcessIdentity(IdentityInfo oId, String Identity, ContextHelper oContextHelper)
        {
            // This code is fast (looking up the SID is slow) so we can put it in a lock in the threads looking up Identities
            lock (m_ProcessIdLock)
            {
                if (null != oId)
                {
                    // Check to see if this SID already exists
                    if (m_HostIdentitiesDict[Environment.MachineName].Contains(oId.oSid, new SidEqualityComparer()))
                        return;
                    // If we found a SID add it
                    List<SecurityIdentifier> HostIdentites = m_HostIdentitiesDict[Environment.MachineName];
                    HostIdentites.Add(oId.oSid);
                    m_HostIdentitiesDict[Environment.MachineName] = HostIdentites;
                    log.Debug("Adding local authorized identity: " + oContextHelper.Identity);
                }
                else
                {
                    String msg = "'" + Identity + "' is not a valid local account.  ";
                    // We are already inside a lock here, so no need to use m_ExceptionLock 
                    m_oXDPInvalidIdentityException = new XDPInvalidIdentityException(((null == m_oXDPInvalidIdentityException) ? "" : m_oXDPInvalidIdentityException.Message) + msg);
                }
            }
        }

        /// <summary>
        /// Returns all the Identies belonging to the domain
        /// </summary>
        internal List<String> DomainIdentities
        {
            get
            {
                return m_DomainIdentities;
            }
        }

        /// <summary>
        /// Returns all the Identities belonging to a specific host.  Currently only the local host is supported.
        /// </summary>
        internal Dictionary<String, List<SecurityIdentifier>> LocalIdentitiesDictionary
        {
            get
            {
                if(m_oResolvingIdentitiesWaitHandles.Count != 0 )
                    WaitHandle.WaitAll(m_oResolvingIdentitiesWaitHandles.ToArray(), 30000);
                
                if (null != m_oXDPInvalidIdentityException)
                    throw m_oXDPInvalidIdentityException;
                
                return m_HostIdentitiesDict;
            }
        }
    }
}
