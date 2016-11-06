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
using log4net;
using Microsoft.Win32;

namespace XDP.XDPCore.Settings
{
    public class SettingsStore
    {
        private static readonly ILog log = LogManager.GetLogger(typeof(SettingsStore));
        RegistryKey m_oStore;

        /// <summary>
        /// Opens the Settings Store at the given location, or creates it if it does not exist
        /// </summary>
        /// <param name="Location"></param>
        public SettingsStore(string Location)
        {
            if(!Location.StartsWith("SOFTWARE"))
                Location = ("SOFTWARE\\" + Location);
            // Check if the key exists
            if(null == Registry.LocalMachine.OpenSubKey(Location))
            {
                try
                {
                    // Try to create the key
                    Registry.LocalMachine.CreateSubKey(Location, RegistryKeyPermissionCheck.ReadWriteSubTree);
                }
                catch { }
            }
            // Open the store
            m_oStore = Registry.LocalMachine.OpenSubKey(Location, false);
        }

        ~SettingsStore()
        {
            try
            {
                if (null != m_oStore)
                    m_oStore.Close();
            }
            catch (Exception e)
            {
                log.Debug("", e);
            }
        }

        /// <summary>
        /// Gets a string setting from the store
        /// </summary>
        /// <param name="SettingName"></param>
        /// <param name="DefaultValue"></param>
        /// <returns></returns>
        public string GetStringValue(string SettingName, string DefaultValue)
        {
            if (null != m_oStore)
            {
                try
                {
                    //log.Debug("Reading " + SettingName + " as " + System.Security.Principal.WindowsIdentity.GetCurrent().Name);
                    object value = m_oStore.GetValue(SettingName);
                    if (null == value)
                    {
                        // Create the Setting using the default value
                        SetStringValue(SettingName, DefaultValue);
                    }
                    else
                        return (string)value;
                }
                catch (Exception e)
                {
                    log.Warn("Unable to read '" + SettingName + "' from registry, using default value", e);
                }
            }
            return DefaultValue;
        }

        /// <summary>
        /// Gets an unsigned int setting from the store
        /// </summary>
        /// <param name="SettingName"></param>
        /// <param name="DefaultValue"></param>
        /// <returns></returns>
        public uint GetUIntValue(string SettingName, uint DefaultValue)
        {
            if (null != m_oStore)
            {
                try
                {
                    //log.Debug("Reading " + SettingName + " as " + System.Security.Principal.WindowsIdentity.GetCurrent().Name);
                    object value = m_oStore.GetValue(SettingName);
                    if (null == value)
                    {
                        // Create the Setting using the default value
                        SetUIntValue(SettingName, DefaultValue);
                    }
                    else
                        return UInt32.Parse(value.ToString());
                }
                catch(Exception e)
                { 
                    log.Warn("Unable to read '" + SettingName + "' from registry, using default value", e); 
                }
            }
            return DefaultValue;
        }

        /// <summary>
        /// Sets a string setting in the store
        /// </summary>
        /// <param name="SettingName"></param>
        /// <param name="Value"></param>
        /// <returns></returns>
        public bool SetStringValue(string SettingName, string Value)
        {
            if (null != m_oStore)
            {
                try
                {
                    return SetValue(SettingName, Value, m_oStore.Name, RegistryValueKind.String);
                }
                catch { }
            }
            return false;
        }

        /// <summary>
        /// Sets an unsigned int setting in the store
        /// </summary>
        /// <param name="SettingName"></param>
        /// <param name="Value"></param>
        /// <returns></returns>
        public bool SetUIntValue(string SettingName, uint Value)
        {
            if (null != m_oStore)
            {
                try
                {
                    //m_oStore.SetValue(SettingName, Value, RegistryValueKind.DWord);
                    return SetValue(SettingName, Value, m_oStore.Name, RegistryValueKind.DWord);
                }
                catch { }
            }
            return false;
        }

        /// <summary>
        /// Most of the time we want to set a store value we are impersonating a client who does not have privileges, so
        /// create a new thread and revert to our system privileges.
        /// </summary>
        /// <param name="SettingName"></param>
        /// <param name="Value"></param>
        /// <param name="Location"></param>
        /// <param name="kind"></param>
        /// <returns></returns>
        private bool SetValue(string SettingName, object Value, string Location, Microsoft.Win32.RegistryValueKind kind)
        {
            //log.Debug("Entering " + System.Reflection.MethodInfo.GetCurrentMethod().Name);
            System.Threading.Thread StoreWriteThread = new System.Threading.Thread(delegate()
            {
                try
                {
                    //log.Debug("Reverting to service account.  Currently " + System.Security.Principal.WindowsIdentity.GetCurrent().Name);
                    // Revert to self
                    NativeWin32Functions.RevertToSelf();
                    //log.Debug("Reverted to " + System.Security.Principal.WindowsIdentity.GetCurrent().Name);

                    RegistryKey oWritableStore = Registry.LocalMachine.OpenSubKey(Location, true);
                    oWritableStore.SetValue(SettingName, Value, kind);
                    oWritableStore.Close();
                }
                catch (Exception) { }
            });
            StoreWriteThread.Start();
            if (!StoreWriteThread.Join(1000))
            {
                // Something bad happened in our thread
                StoreWriteThread.Abort();
                log.Error("Unable to set settings store value");
                return false;
            }
            //log.Debug("Exiting " + System.Reflection.MethodInfo.GetCurrentMethod().Name);
            return true;
        }
    }
}
