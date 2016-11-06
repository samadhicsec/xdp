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

namespace XDP.XDPCore.DataFormat
{
    /// <summary>
    /// XDPHeader holds the version and the IXDPInternalHeader data.  Based on the version the correct implementation of IXDPInternalHeader is used.
    /// </summary>
    [System.SerializableAttribute()]
    [System.Xml.Serialization.XmlTypeAttribute(AnonymousType = true, Namespace = "urn:com.XDP.XDPData")]
    [System.Xml.Serialization.XmlRootAttribute(Namespace = "urn:com.XDP.XDPData", IsNullable = false)]
    public class XDPHeader
    {
        private ushort m_XDPVersionField;

        private XDPInternalHeaderBase m_XDPInternalHeaderField;

        /// <summary>
        /// Parameterless constructor used for Serialization
        /// </summary>
        public XDPHeader()
        {

        }

        /// <summary>
        /// The current version of the XDPHeader format
        /// </summary>
        public ushort XDPVersion
        {
            get
            {
                return this.m_XDPVersionField;
            }
            set
            {
                m_XDPVersionField = value;
            }
        }

        /// <summary>
        /// The version specific internal header
        /// </summary>
        public XDPInternalHeaderBase XDPInternalHeader
        {
            get
            {
                return this.m_XDPInternalHeaderField;
            }
            set
            {
                m_XDPInternalHeaderField = value;
            }
        }

        internal void Validate()
        {
            // Ignoring the XDPVersion

            // Check the XDPInternalHeader
            if (null == m_XDPInternalHeaderField)
                throw new XDPInvalidFormatExcepton("No XDPInternalHeader was present");
            m_XDPInternalHeaderField.Validate();
        }
    }
}
