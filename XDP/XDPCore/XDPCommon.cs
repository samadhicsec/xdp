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
using System.IO;
using System.IO.Compression;
using System.Linq;
using System.Xml.Serialization;
using log4net;

namespace XDP.XDPCore
{
    /// <summary>
    /// Class to group native Windows API calls
    /// </summary>
    internal static class NativeWin32Functions
    {
        [System.Runtime.InteropServices.DllImport("advapi32.dll", SetLastError = true)]
        public static extern bool RevertToSelf();
    }

    /// <summary>
    /// Common static functionality
    /// </summary>
    internal class XDPCommon
    {
        private static readonly ILog log = LogManager.GetLogger(typeof(XDPCommon));

        /// <summary>
        /// Serializes an object to XML
        /// </summary>
        /// <param name="ObjectToSerialize">The object to serialize</param>
        /// <param name="Namespace">The XML namespace</param>
        /// <returns>The serialized object</returns>
        internal static byte[] SerializeToXml(object ObjectToSerialize, string Namespace)
        {
            // Serialise Object
            MemoryStream oSerializedObject = new MemoryStream();
            try
            {
                XmlSerializer oSerializer = new XmlSerializer(ObjectToSerialize.GetType(), Namespace);
                oSerializer.Serialize(oSerializedObject, ObjectToSerialize);
            }
            catch (InvalidOperationException ioe)
            {
                log.Debug("", ioe);
                throw new XDPException(ioe.Message);
            }
            catch (Exception e)
            {
                log.Debug("Unexpected exception", e);
                throw;
            }

            return oSerializedObject.ToArray();
        }

        internal static T DeserializeFromXml<T>(byte[] SerializedObject)
        {
            T DeserializedObject = default(T);
            MemoryStream SerializedObjectStream = new MemoryStream(SerializedObject);
            SerializedObjectStream.Seek(0, SeekOrigin.Begin);
            //try
            //{
                XmlSerializer oSerializer = new XmlSerializer(typeof(T));
                DeserializedObject = (T)oSerializer.Deserialize(SerializedObjectStream);
            //}
            //catch
            //{

            //}
            return DeserializedObject;
        }

        //public static System.Xml.XmlDocument ShowXML<T>(object XmlObject)
        //{
        //    byte[] data = SerializeToXml<T>(XmlObject, "urn:com.XDP.XDPData");
        //    string xmlstring = ASCIIEncoding.ASCII.GetString(data);
        //    System.Xml.XmlDocument oXmlDoc = new System.Xml.XmlDocument();
        //    oXmlDoc.LoadXml(xmlstring);
        //    return oXmlDoc;
        //}

        /// <summary>
        /// Uses WMI to recover the Domain the current computer belongs to.
        /// </summary>
        /// <returns>The Domain name or null if the computer is not part of a Domain</returns>
        internal static String GetDomainName()
        {
            System.Management.SelectQuery query = new System.Management.SelectQuery("Win32_ComputerSystem");
            using (System.Management.ManagementObjectSearcher searcher = new System.Management.ManagementObjectSearcher(query))
            {
                foreach (System.Management.ManagementObject mo in searcher.Get())
                {
                    if ((bool)mo["partofdomain"] == true)
                    {
                        return mo["domain"].ToString();
                    }
                }
            }
            return null;
        }

        /// <summary>
        /// Compares 2 Domain names for equality.  If one domain name is not a FQDN, will return true if the other is a FQDN domain name and 
        /// starts with the first i.e. 'domainname' and 'domainname.com' will be considered equal.
        /// </summary>
        /// <param name="Domain1"></param>
        /// <param name="Domain2"></param>
        /// <returns></returns>
        internal static bool DomainsEqual(string Domain1, string Domain2)
        {
            if ((null == Domain1) || (null == Domain2))
                return false;

            // If the domain names are the same length just do a straight comparison
            if (Domain1.Length == Domain2.Length)
                if (Domain1.Equals(Domain2, StringComparison.InvariantCultureIgnoreCase))
                    return true;
                else
                    return false;

            // Find the longest domain name, this is the FQDN
            string FQDN = Domain1;
            string nonFQDN = Domain2;
            if (Domain1.Length < Domain2.Length)
            {
                FQDN = Domain2;
                nonFQDN = Domain1;
            }
            // Make sure the nonFQDN does not contain '.'.  This avoids scenarios like 'domainname.corp' being considered equal to 'domainname.corp.net'
            if (nonFQDN.Contains('.'))
                return false;

            // See if the FQDN starts with the nonFQDN
            if (FQDN.StartsWith(nonFQDN + ".", StringComparison.InvariantCultureIgnoreCase))
                return true;

            return false;
        }

        /// <summary>
        /// Compresses a byte array
        /// </summary>
        /// <param name="Data"></param>
        /// <param name="ZeroData">Zeros all intermediate data stores.  Use when compressing sensitive data</param>
        /// <returns></returns>
        internal static byte[] Compress(byte[] DataToCompress, bool ZeroData)
        {
            MemoryStream oCompressedData = new MemoryStream();
            GZipStream oCompressor = new GZipStream(oCompressedData, CompressionMode.Compress);
            oCompressor.Write(DataToCompress, 0, DataToCompress.Length);
            oCompressor.Close();
            byte[] ret = oCompressedData.ToArray();
            if(ZeroData)
                XDPCommon.Zero(oCompressedData);
            return ret;
        }

        /// <summary>
        /// Decompress compressed data
        /// </summary>
        /// <param name="CompressedDataBytes"></param>
        /// <param name="ZeroData">Zeros all intermediate data stores.  Use when compressing sensitive data</param>
        /// <returns></returns>
        internal static byte[] Decompress(byte[] CompressedData, bool ZeroData)
        {
            MemoryStream CompressedDataStream = new MemoryStream(CompressedData);
            GZipStream Decompressor = new GZipStream(CompressedDataStream, CompressionMode.Decompress);
            byte[] DecompressedBuffer = new byte[8196];
            MemoryStream DecompressedData = new MemoryStream();
            while (true)
            {
                int bytesread = Decompressor.Read(DecompressedBuffer, 0, DecompressedBuffer.Length);
                if (0 == bytesread)
                    break;
                DecompressedData.Write(DecompressedBuffer, 0, bytesread);
            }
            Decompressor.Close();
            byte[] ret = DecompressedData.ToArray();
            if (ZeroData)
            {
                XDPCommon.Zero(DecompressedBuffer);
                XDPCommon.Zero(CompressedDataStream);
                XDPCommon.Zero(DecompressedData);
            }
            return ret;
        }

        /// <summary>
        /// Zeros the contents of a byte array
        /// </summary>
        /// <param name="Data">The byte array to zero</param>
        internal static void Zero(byte[] Data)
        {
            // There is an Array.Clear method, but it is O(n) so this routine is probably as good as it gets
            for (int i = 0; i < Data.Length; i++)
            {
                Data[i] = 0;
            }
        }

        /// <summary>
        /// Zeroes the contents of a stream if the stream is writable
        /// </summary>
        /// <param name="Data">The stream to zero</param>
        internal static void Zero(Stream Data)
        {
            if (Data.CanWrite)
            {
                Data.Seek(0, SeekOrigin.Begin);
                for (int i = 0; i < Data.Length; i++)
                {
                    Data.WriteByte(0);
                }
            }
        }
    }
}
