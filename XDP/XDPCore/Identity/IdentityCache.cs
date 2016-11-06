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
using System.Security.Principal;
using System.Threading;

namespace XDP.XDPCore.Identity
{
    public enum IdentityType
    {
        User,
        Group
    }

    public class IdentityInfo
    {
        public SecurityIdentifier oSid;
        public IdentityType eType;
        public SortedList<string, string> MemberOf;
        public DateTime Created;

        public IdentityInfo(SecurityIdentifier oSid, IdentityType eType)
        {
            this.oSid = oSid;
            this.eType = eType;
            MemberOf = new SortedList<string, string>();
            Created = DateTime.Now;
        }
    }

    public interface IIdentityCache
    {
        void Add(string Identity, IdentityInfo oIdentityInfo);
        IdentityInfo Find(string Identity);
        IdentityInfo FindBySid(string Sid);
    }

    internal class IdentityCache : IIdentityCache
    {
        // Make operations on the SortedDictionaries thread safe
        object m_oCacheLock = new object();
        TimeSpan m_oCacheTimeout = new TimeSpan(0, 1, 0);
        // Store Identities so they can be recovered by name or Sid
        protected SortedDictionary<string, IdentityInfo> m_oNameIdInfoDictionary;
        protected SortedDictionary<string, IdentityInfo> m_oSidIdInfoDictionary;

        public IdentityCache()
        {
            m_oNameIdInfoDictionary = new SortedDictionary<string, IdentityInfo>(StringComparer.CurrentCultureIgnoreCase);
            m_oSidIdInfoDictionary = new SortedDictionary<string, IdentityInfo>(StringComparer.CurrentCultureIgnoreCase);

            // Create a thread to expire the contents of the cache
            Thread t = new Thread(new ThreadStart(
                delegate()
                {
                    while (true)
                    {
                        //System.Diagnostics.Debug.WriteLine("Cache expiration thread running");
                        string NamedIdEntryToExpire = String.Empty;
                        lock (m_oCacheLock)
                        {
                            // Loop through the cache
                            foreach (KeyValuePair<string, IdentityInfo> kvp in m_oNameIdInfoDictionary)
                            {
                                // Find an expired entry
                                if (kvp.Value.Created + m_oCacheTimeout < DateTime.Now)
                                {
                                    NamedIdEntryToExpire = kvp.Key;
                                    break;
                                }
                            }
                            if (!String.IsNullOrEmpty(NamedIdEntryToExpire))
                            {
                                System.Diagnostics.Debug.WriteLine("Found cache entry to expire '" + NamedIdEntryToExpire + "'");
                                // If we found an expired entry, delete it
                                SecurityIdentifier oSidEntryToExpire = m_oNameIdInfoDictionary[NamedIdEntryToExpire].oSid;
                                m_oNameIdInfoDictionary.Remove(NamedIdEntryToExpire);
                                m_oSidIdInfoDictionary.Remove(oSidEntryToExpire.ToString());
                            }
                        }
                        if (String.IsNullOrEmpty(NamedIdEntryToExpire))
                        {
                            //System.Diagnostics.Debug.WriteLine("Cache expiration thread sleeping");
                            Thread.Sleep(m_oCacheTimeout);  // If there is no expired entry then sleep the thread
                        }
                    }
                }));
            t.Priority = ThreadPriority.BelowNormal;
            t.Start();
        }

        protected IdentityCache(TimeSpan CacheTimeout)
            : this()
        {
            m_oCacheTimeout = CacheTimeout;
        }

        /// <summary>
        /// Add an entry to the cache
        /// </summary>
        /// <param name="Identity"></param>
        /// <param name="oSid"></param>
        public void Add(string Identity, IdentityInfo oIdentityInfo)
        {
            if(String.IsNullOrEmpty(Identity))
                return;
            if (null == oIdentityInfo)
                return;
            lock (m_oCacheLock)
            {
                m_oNameIdInfoDictionary[Identity] = oIdentityInfo;
                m_oSidIdInfoDictionary[oIdentityInfo.oSid.ToString()] = oIdentityInfo;
                System.Diagnostics.Debug.WriteLine("Added '" + Identity + "' to cache");
            }
        }

        /// <summary>
        /// Looks for an entry in the cache, if it doesn't exist null is returned
        /// </summary>
        /// <param name="Identity"></param>
        /// <returns></returns>
        public IdentityInfo Find(string Identity)
        {
            if (String.IsNullOrEmpty(Identity))
                return null;
            IdentityInfo oIdInfo = null;
            lock (m_oCacheLock)
            {
                m_oNameIdInfoDictionary.TryGetValue(Identity, out oIdInfo);
            }
            return oIdInfo;
        }

        /// <summary>
        /// Looks for an entry in the cache by Sid, if it doesn't exist null is returned
        /// </summary>
        /// <param name="Identity"></param>
        /// <returns></returns>
        public IdentityInfo FindBySid(string Sid)
        {
            if (String.IsNullOrEmpty(Sid))
                return null;
            IdentityInfo oIdInfo = null;
            lock (m_oCacheLock)
            {
                m_oSidIdInfoDictionary.TryGetValue(Sid, out oIdInfo);
            }
            return oIdInfo;
        }
    }
}
