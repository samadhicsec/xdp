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
using log4net;

namespace XDP.XDPCore.DataFormat.V1
{
    /// <remarks/>
    [System.SerializableAttribute()]
    [System.Xml.Serialization.XmlTypeAttribute(AnonymousType = true, Namespace = "urn:com.XDP.XDPData")]
    [System.Xml.Serialization.XmlRootAttribute(Namespace = "urn:com.XDP.XDPData", IsNullable = false)]
    public class XDPAuthorizedIdentities
    {
        private static readonly ILog log = LogManager.GetLogger(typeof(XDPAuthorizedIdentities));

        private string[] identityField;

        /// <remarks/>
        [System.Xml.Serialization.XmlElementAttribute("Identity")]
        public string[] Identity
        {
            get
            {
                return this.identityField;
            }
            set
            {
                this.identityField = value;
            }
        }

        /// <summary>
        /// Validates that the values of XDPAuthorizedIdentities are not null or empty
        /// </summary>
        /// <param name="oXDPAuthorizedIdentities"></param>
        /// <returns></returns>
        internal static bool Validate(XDPAuthorizedIdentities oXDPAuthorizedIdentities, XDP.XDPCore.Messages.XDPExceptionHelper oExceptionHelper)
        {
            log.Debug("Entering " + System.Reflection.MethodInfo.GetCurrentMethod().Name);
            if (null == oXDPAuthorizedIdentities)
            {
                // Send back bad parameter
                oExceptionHelper.SendBadParameterException("XDPAuthorizedIdentities", "Parameter was null");
                return false;
            }

            if (null == oXDPAuthorizedIdentities.Identity)
            {
                // Send back bad parameter
                oExceptionHelper.SendBadParameterException("XDPAuthorizedIdentities.Identity", "Parameter was null");
                return false;
            }

            if (0 == oXDPAuthorizedIdentities.Identity.Length)
            {
                // Send back bad parameter
                oExceptionHelper.SendBadParameterException("XDPAuthorizedIdentities.Identity", "Array was empty");
                return false;
            }

            log.Debug("Exiting " + System.Reflection.MethodInfo.GetCurrentMethod().Name);
            return true;
        }
    }   
}
