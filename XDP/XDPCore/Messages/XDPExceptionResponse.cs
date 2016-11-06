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
using XDP.XDPCore.DataFormat.V1;

namespace XDP.XDPCore.Messages
{
    /// <remarks/>
    [System.SerializableAttribute()]
    [System.Xml.Serialization.XmlTypeAttribute(AnonymousType = true, Namespace = "urn:com.XDP.XDPMessages")]
    [System.Xml.Serialization.XmlRootAttribute(Namespace = "urn:com.XDP.XDPMessages", IsNullable = false)]
    public class XDPExceptionResponse
    {

        private object itemField;

        private XDPExceptionType itemElementNameField;

        /// <remarks/>
        [System.Xml.Serialization.XmlElementAttribute("XDPBadParameter", typeof(XDPExceptionXDPBadParameter))]
        [System.Xml.Serialization.XmlElementAttribute("XDPBadSignature", typeof(string))]
        [System.Xml.Serialization.XmlElementAttribute("XDPGeneralException", typeof(string))]
        [System.Xml.Serialization.XmlElementAttribute("XDPNotAuthorized", typeof(string))]
        [System.Xml.Serialization.XmlElementAttribute("XDPUnknownIdentity", typeof(string))]
        [System.Xml.Serialization.XmlElementAttribute("XDPUpdateCommonHeader", typeof(XDPExceptionXDPUpdateCommonHeader))]
        [System.Xml.Serialization.XmlChoiceIdentifierAttribute("ItemElementName")]
        public object Item
        {
            get
            {
                return this.itemField;
            }
            set
            {
                this.itemField = value;
            }
        }

        /// <remarks/>
        [System.Xml.Serialization.XmlIgnoreAttribute()]
        public XDPExceptionType ItemElementName
        {
            get
            {
                return this.itemElementNameField;
            }
            set
            {
                this.itemElementNameField = value;
            }
        }
    }

    /// <remarks/>
    [System.SerializableAttribute()]
    [System.Xml.Serialization.XmlTypeAttribute(AnonymousType = true, Namespace = "urn:com.XDP.XDPMessages")]
    public class XDPExceptionXDPBadParameter
    {

        private string parameterField;

        private string reasonField;

        /// <remarks/>
        public string Parameter
        {
            get
            {
                return this.parameterField;
            }
            set
            {
                this.parameterField = value;
            }
        }

        /// <remarks/>
        public string Reason
        {
            get
            {
                return this.reasonField;
            }
            set
            {
                this.reasonField = value;
            }
        }
    }

    /// <remarks/>
    [System.SerializableAttribute()]
    [System.Xml.Serialization.XmlTypeAttribute(AnonymousType = true, Namespace = "urn:com.XDP.XDPMessages")]
    public class XDPExceptionXDPUpdateCommonHeader
    {

        private XDPInternalCommonHeader xDPInternalCommonHeaderField;

        /// <remarks/>
        [System.Xml.Serialization.XmlElementAttribute(Namespace = "urn:com.XDP.XDPData")]
        public XDPInternalCommonHeader XDPInternalCommonHeader
        {
            get
            {
                return this.xDPInternalCommonHeaderField;
            }
            set
            {
                this.xDPInternalCommonHeaderField = value;
            }
        }
    }

    /// <remarks/>
    [System.SerializableAttribute()]
    [System.Xml.Serialization.XmlTypeAttribute(Namespace = "urn:com.XDP.XDPMessages", IncludeInSchema = false)]
    public enum XDPExceptionType
    {

        /// <remarks/>
        XDPBadParameter,

        /// <remarks/>
        XDPBadSignature,

        /// <remarks/>
        XDPGeneralException,

        /// <remarks/>
        XDPNotAuthorized,

        /// <remarks/>
        XDPUnknownIdentity,

        /// <remarks/>
        XDPUpdateCommonHeader,
    }
}
