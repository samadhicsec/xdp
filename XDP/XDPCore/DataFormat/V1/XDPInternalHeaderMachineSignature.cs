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

namespace XDP.XDPCore.DataFormat.V1
{
    /// <remarks/>
    [System.SerializableAttribute()]
    [System.Xml.Serialization.XmlTypeAttribute(AnonymousType = true, Namespace = "urn:com.XDP.XDPData")]
    [System.Xml.Serialization.XmlRootAttribute(Namespace = "urn:com.XDP.XDPData", IsNullable = false)]
    public class XDPInternalHeaderMachineSignature
    {
        private string hostnameField;

        private byte[] valueField;

        /// <summary>
        /// Parameterless constructor used for Serialization
        /// </summary>
        public XDPInternalHeaderMachineSignature()
        {

        }

        /// <summary>
        /// Validate the XDPInternalHeaderMachineSignature
        /// </summary>
        internal void Validate()
        {
            if (String.IsNullOrEmpty(hostnameField))
                throw new XDPBadParameterException("XDPInternalHeaderMachineSignature.Hostname", "Value was null or empty");
            if(null == valueField)
                throw new XDPBadParameterException("XDPInternalHeaderMachineSignature", "Value was null");
            if (0 == valueField.Length)
                throw new XDPBadParameterException("XDPInternalHeaderMachineSignature", "Array was empty");
        }

        /// <remarks/>
        public string Hostname
        {
            get
            {
                return this.hostnameField;
            }
            set
            {
                this.hostnameField = value;
            }
        }

        /// <remarks/>
        [System.Xml.Serialization.XmlElementAttribute(DataType = "hexBinary")]
        public byte[] Value
        {
            get
            {
                return this.valueField;
            }
            set
            {
                this.valueField = value;
            }
        }
    }
}
