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

namespace XDP.XDPCore.DataFormat.V1
{
    /// <remarks/>
    [System.SerializableAttribute()]
    [System.Xml.Serialization.XmlTypeAttribute(AnonymousType = true, Namespace = "urn:com.XDP.XDPData")]
    public class XDPInternalHeaderSignatures
    {

        private List<XDPInternalHeaderMachineSignature> m_XDPInternalHeaderMachineSignatureField;

        private byte[] m_XDPInternalHeaderDomainSignatureField;

        /// <summary>
        /// Parameterless constructor used for Serialization
        /// </summary>
        public XDPInternalHeaderSignatures()
        {

        }

        /// <summary>
        /// Initializes the list of InternalMachineHeaderSignatures to those of remote machines and the that of the Domain
        /// </summary>
        /// <param name="oRemoteInternalMachineHeaderSignatures"></param>
        /// <param name="oInternalDomainHeaderSignature"></param>
        internal XDPInternalHeaderSignatures(List<XDPInternalHeaderMachineSignature> oRemoteInternalMachineHeaderSignatures, 
                                           byte[] oInternalDomainHeaderSignature)
        {
            if (null != oRemoteInternalMachineHeaderSignatures)
                m_XDPInternalHeaderMachineSignatureField = oRemoteInternalMachineHeaderSignatures;
            else
                m_XDPInternalHeaderMachineSignatureField = new List<XDPInternalHeaderMachineSignature>();

            if (null != oInternalDomainHeaderSignature)
            {
                m_XDPInternalHeaderDomainSignatureField = new byte[oInternalDomainHeaderSignature.Length];
                Array.Copy(oInternalDomainHeaderSignature, m_XDPInternalHeaderDomainSignatureField, oInternalDomainHeaderSignature.Length);
            }
        }

        /// <summary>
        /// Validate the format and values of this XDPInternalHeaderSignatures
        /// </summary>
        /// <param name="oXDPInternalMachineHeader">The XDPInternalMachineHeader should have been validated already</param>
        /// <param name="oXDPInternalDomainHeader">The XDPInternalDomainHeader should have been validated already</param>
        internal void Validate(XDPInternalMachineHeader[] oXDPInternalMachineHeaders, XDPInternalDomainHeader oXDPInternalDomainHeader)
        {
            if ((null != oXDPInternalMachineHeaders) && (oXDPInternalMachineHeaders.Length > 0))
            {
                // We have XDPInternalMachineHeaders so make sure we have some signatures
                if (null == m_XDPInternalHeaderMachineSignatureField)
                    throw new XDPBadParameterException("XDPInternalHeaderSignatures.XDPInternalHeaderMachineSignature", "Value was null");

                for (int i = 0; i < m_XDPInternalHeaderMachineSignatureField.Count; i++)
                    m_XDPInternalHeaderMachineSignatureField[i].Validate();

                // We don't care if the signatures match up with the headers, our signature checking will ensure validity.  A XDPInternalHeaderMachineSignature
                // could be injected, but this has no effect on security.
            }
            else
            {
                // We have no XDPInternalMachineHeaders so we should have no signatures
                if ((null == m_XDPInternalHeaderMachineSignatureField) && (m_XDPInternalHeaderMachineSignatureField.Count > 0))
                    throw new XDPBadParameterException("XDPInternalHeaderSignatures.XDPInternalHeaderMachineSignature", "Signature(s) for non-existant XDPInternalMachineHeaders were present");
            }

            // If a XDPInternalDomainHeader is present then there should be a signature, if there isn't then there should be no signature
            if ((null != oXDPInternalDomainHeader) && ((null == m_XDPInternalHeaderDomainSignatureField) || ((null != m_XDPInternalHeaderDomainSignatureField) && (0 == m_XDPInternalHeaderDomainSignatureField.Length))))
                throw new XDPBadParameterException("XDPInternalHeaderSignatures.XDPInternalHeaderDomainSignature", "No signature for the XDPInternalDomainHeader was present");
            if((null == oXDPInternalDomainHeader) && (null != m_XDPInternalHeaderDomainSignatureField) && (0 != m_XDPInternalHeaderDomainSignatureField.Length))
                throw new XDPBadParameterException("XDPInternalHeaderSignatures.XDPInternalHeaderDomainSignature", "A signature for a non-existant XDPInternalDomainHeader was present");
        }

        /// <summary>
        /// Creates and adds a XDPInternalHeaderMachineSignature for the local machine
        /// </summary>
        /// <param name="oSignatureHelper">XDPSignatureHelper with signature key for the local machine</param>
        /// <param name="oInternalCommonHeader">The common header</param>
        /// <param name="oLocalInternalMachineHeader">The local machine header</param>
        internal void AddLocalMachineHeaderSignature(XDPSignatureHelper oSignatureHelper, XDPInternalCommonHeader oInternalCommonHeader, XDPInternalMachineHeader oLocalInternalMachineHeader)
        {
            // Create the XDPInternalHeaderMachineSignature for the local machine
            XDPInternalHeaderMachineSignature oLocalInternalHeaderMachineSignature = new XDPInternalHeaderMachineSignature();
            oLocalInternalHeaderMachineSignature.Hostname = oLocalInternalMachineHeader.Hostname;
            oLocalInternalHeaderMachineSignature.Value = CreateLocalMachineHeaderSignature(oSignatureHelper, oInternalCommonHeader, oLocalInternalMachineHeader);
            // Add to the List
            m_XDPInternalHeaderMachineSignatureField.Insert(0, oLocalInternalHeaderMachineSignature);
        }

        /// <summary>
        /// Creates the InternalMachineHeaderSignature value for the local machine
        /// </summary>
        /// <param name="oSignatureHelper">XDPSignatureHelper with signature key for the local machine</param>
        /// <param name="oInternalCommonHeader">The common header</param>
        /// <param name="oLocalInternalMachineHeader">The local machine header</param>
        /// <returns>The signature value</returns>
        internal byte[] CreateLocalMachineHeaderSignature(XDPSignatureHelper oSignatureHelper, XDPInternalCommonHeader oInternalCommonHeader, XDPInternalMachineHeader oLocalInternalMachineHeader)
        {
            // Serialize oInternalCommonHeader
            byte[] SerializedInternalCommonHeader = XDPCommon.SerializeToXml(oInternalCommonHeader, "urn:com.XDP.XDPData");

            // Serialize the oLocalInternalMachineHeaders
            byte[] SerializedLocalInternalMachineHeader = XDPCommon.SerializeToXml(oLocalInternalMachineHeader, "urn:com.XDP.XDPData");

            // Combine
            byte[] SerializedSignatureData = new byte[SerializedInternalCommonHeader.Length + SerializedLocalInternalMachineHeader.Length];
            Array.Copy(SerializedInternalCommonHeader, SerializedSignatureData, SerializedInternalCommonHeader.Length);
            Array.Copy(SerializedLocalInternalMachineHeader, 0, SerializedSignatureData, SerializedInternalCommonHeader.Length, SerializedLocalInternalMachineHeader.Length);

            // Sign the signature data
            return oSignatureHelper.Sign(SerializedSignatureData);
        }

        /// <summary>
        /// Returns the XDPInternalHeaderMachineSignature for the specified Hostname, or null if it does not exist
        /// </summary>
        /// <param name="Hostname">The Hostname of the XDPInternalHeaderMachineSignatureto search for</param>
        /// <returns>XDPInternalHeaderMachineSignature for the specified Hostname, or null if it does not exist</returns>
        internal XDPInternalHeaderMachineSignature GetMachineSigature(String Hostname)
        {
            for (int i = 0; i < m_XDPInternalHeaderMachineSignatureField.Count; i++)
            {
                if (m_XDPInternalHeaderMachineSignatureField[i].Hostname.Equals(Hostname, StringComparison.InvariantCultureIgnoreCase))
                    return m_XDPInternalHeaderMachineSignatureField[i];
            }
            return null;
        }

        /// <remarks/>
        public XDPInternalHeaderMachineSignature[] XDPInternalHeaderMachineSignature
        {
            get
            {
                return this.m_XDPInternalHeaderMachineSignatureField.ToArray();
            }
            set
            {
                this.m_XDPInternalHeaderMachineSignatureField = new List<XDPInternalHeaderMachineSignature>(value);
            }
        }

        /// <remarks/>
        [System.Xml.Serialization.XmlElementAttribute(DataType = "hexBinary")]
        public byte[] XDPInternalHeaderDomainSignature
        {
            get
            {
                return this.m_XDPInternalHeaderDomainSignatureField;
            }
            set
            {
                this.m_XDPInternalHeaderDomainSignatureField = value;
            }
        }
    }
}
