using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Xml;
using System.Xml.XPath;
using NUnit.Framework;
using XDP.XDPCore.Settings;
using XDP.XDPCore.DataFormat;
using XDP.XDPCore.DataFormat.V1;

namespace XDPCoreTests.DataFormat
{
    internal class XDPCryptoSettingsMock : IXDPCryptoSettings
    {
        #region IXDPCryptoSettings Members

        public string EncryptionAlgorithm
        {
            get
            {
                return "AesManaged";
            }
            set
            {
                throw new NotImplementedException();
            }
        }

        public System.Security.Cryptography.CipherMode EncryptionMode
        {
            get
            {
                return System.Security.Cryptography.CipherMode.CBC;
            }
            set
            {
                throw new NotImplementedException();
            }
        }

        public string SignatureAlgorithm
        {
            get
            {
                return "HMACSHA256";
            }
            set
            {
                throw new NotImplementedException();
            }
        }

        #endregion
    }
 

    internal class XDPMachineSettingsMock : IXDPMachineSettings
    {
        #region IXDPMachineSettings Members

        public string DomainHostname
        {
            get { throw new NotImplementedException(); }
        }

        public string XDPDSAccount
        {
            get { throw new NotImplementedException(); }
        }

        #endregion

        #region IXDPSettings Members

        public CommunicationSecurityLevel CommunicationSecurity
        {
            get { return CommunicationSecurityLevel.Kerberos; }
        }

        public IXDPCryptoSettings CryptoSettings
        {
            get { return new XDPCryptoSettingsMock(); }
        }

        public ushort DomainPort
        {
            get { return 3483; }
        }

        public uint NetworkTimout
        {
            get { return 30000; }
        }

        public uint ThreadPoolSize
        {
            get { return 5; }
        }

        #endregion
    }


    internal class XDPInternalHeaderMock : XDPInternalHeaderBase
    {
        XDPKeys m_oXDPKeys = new XDPKeys();

        #region IXDPInternalHeader Members

        public override IXDPKeys KeyStore
        {
            get { return m_oXDPKeys; }
        }

        public override void Populate(byte[] DataSignature, XDP.XDPCore.Identity.MachineIdentityHelper oIdentityHelper)
        {
            ;
        }

        public override void GetDecryptionParameters(out XDP.XDPCore.Settings.IXDPCryptoSettings oCryptoSettings, out byte[] DataSignature)
        {
            throw new NotImplementedException();
        }

        public override void Validate()
        {
            
        }

        #endregion
    }

    internal class DataFormatFactoryMock : IDataFormatFactory
    {
        #region IDataFormatFactory Members

        public IXDPInternalHeader CreateInternalHeader(XDP.XDPCore.Settings.IXDPMachineSettings oSettings)
        {
            return new XDPInternalHeaderMock();
        }

        #endregion
    }

    /// <summary>
    /// Basically XDPData except we mock the IXDPMachineSettings
    /// </summary>
    internal class XDPDataMock : XDPData
    {
        public XDPDataMock(IDataFormatFactory oDFFactory) : base(oDFFactory)
        {
        }

        protected override IXDPMachineSettings CreateMachineSettings()
        {
            return new XDPMachineSettingsMock();
        }
    }

    internal class DeserialiseTestHelper
    {
        byte[] m_oCiphertext;

        public XmlDocument GetXMLHeader(byte[] DataOut)
        {
            // Read the header length
            uint SerializedXDPHeaderLength = BitConverter.ToUInt32(DataOut, 4);
            byte[] SerializedXDPHeader = new byte[SerializedXDPHeaderLength];
            Buffer.BlockCopy(DataOut, 8, SerializedXDPHeader, 0, (int)SerializedXDPHeaderLength);
            uint DataOutBytesRemaining = (uint)(DataOut.Length - 8);
            DataOutBytesRemaining -= SerializedXDPHeaderLength;

            // Decompress the XDPHeader if it's compressed
            if (DataOut[3] == 0x02)
            {
                SerializedXDPHeader = XDP.XDPCore.XDPCommon.Decompress(SerializedXDPHeader, false);
            }

            // Create a copy the ciphertext
            m_oCiphertext = new byte[DataOutBytesRemaining];
            Buffer.BlockCopy(DataOut, (int)(DataOut.Length - DataOutBytesRemaining), m_oCiphertext, 0, (int)DataOutBytesRemaining);

            System.IO.MemoryStream XmlHeaderStream = new System.IO.MemoryStream(SerializedXDPHeader);
            XmlDocument oXmlDoc = new XmlDocument();
            oXmlDoc.Load(XmlHeaderStream);
            return oXmlDoc;
        }

        public byte[] Reserialize(XmlDocument oXmlDoc)
        {
            // Serialise the magic bytes            
            byte[] MagicBytes = ASCIIEncoding.ASCII.GetBytes("XDP");
            // Serialise the XDPHeader
            System.IO.MemoryStream SerialisedXDPHeaderStream = new System.IO.MemoryStream();
            XmlWriter oXmlWriter = XmlWriter.Create(SerialisedXDPHeaderStream);
            oXmlDoc.WriteTo(oXmlWriter);
            oXmlWriter.Flush();
            byte[] SerialisedXDPHeader = SerialisedXDPHeaderStream.ToArray();
            byte m_Flags = 0;
            // If SerialisedXDPHeader.Length > 200 bytes (200 was determined experimentally), then we should compress it
            if (SerialisedXDPHeader.Length > 200)
            {
                m_Flags = 0x02;
                SerialisedXDPHeader = XDP.XDPCore.XDPCommon.Compress(SerialisedXDPHeader, false);
            }
            // Serialise the XDPHeader length
            byte[] SerialisedXDPHeaderLength = BitConverter.GetBytes(SerialisedXDPHeader.Length);

            int offset = 0;
            byte[] SerialisedData = new byte[MagicBytes.Length + 1 + SerialisedXDPHeaderLength.Length + SerialisedXDPHeader.Length + m_oCiphertext.Length];
            // Copy serialised data to an XDPData blob
            Buffer.BlockCopy(MagicBytes, 0, SerialisedData, offset, MagicBytes.Length);
            offset += MagicBytes.Length;
            SerialisedData[offset++] = ((byte)m_Flags);
            Buffer.BlockCopy(SerialisedXDPHeaderLength, 0, SerialisedData, offset, SerialisedXDPHeaderLength.Length);
            offset += SerialisedXDPHeaderLength.Length;
            Buffer.BlockCopy(SerialisedXDPHeader, 0, SerialisedData, offset, SerialisedXDPHeader.Length);
            offset += SerialisedXDPHeader.Length;
            Buffer.BlockCopy(m_oCiphertext, 0, SerialisedData, offset, m_oCiphertext.Length);

            return SerialisedData;
        }

        public byte[] RemoveHeaderNode(byte[] DataOut, string NodeName)
        {
            XmlDocument oXmlDoc = GetXMLHeader(DataOut);

            XPathNavigator oNav = oXmlDoc.CreateNavigator();
            //XPathNodeIterator oNodeIt = oNav.SelectDescendants("//" + NodeName, "urn:com.XDP.XDPData", true);
            //if (oNodeIt.Count != 1)
            //    throw new Exception("Could not find node '" + NodeName + "'");
            //oNav = oNodeIt.Current;
            oNav = FindNode(oNav, NodeName);
            oNav.DeleteSelf();

            return Reserialize(oXmlDoc);
        }

        public byte[] BlankHeaderNode(byte[] DataOut, string NodeName)
        {
            XmlDocument oXmlDoc = GetXMLHeader(DataOut);

            XPathNavigator oNav = oXmlDoc.CreateNavigator();
            oNav = FindNode(oNav, NodeName);
            oNav.SetValue("");

            return Reserialize(oXmlDoc);
        }

        private XPathNavigator FindNode(XPathNavigator oXPathNav, string NodeName)
        {
            if(!oXPathNav.MoveToFirstChild())
                return null;
            do
            {
                if (oXPathNav.LocalName.Equals(NodeName))
                    return oXPathNav;
                if (oXPathNav.HasChildren)
                {
                    XPathNavigator res = FindNode(oXPathNav.Clone(), NodeName);
                    if (null != res)
                        return res;
                }
            }
            while (oXPathNav.MoveToNext());

            return null;
        }
    }

    [TestFixture]
    public class XDPDataTests
    {
        [Test]
        public void Encrypt_ValidMockMachineEncrypt_NoException()
        {
            // arrange
            XDPDataMock oXDPDataMock = new XDPDataMock(new DataFormatFactoryMock());
            byte[] message = new byte[] {0};
            string[] user = new string[] { System.Security.Principal.WindowsIdentity.GetCurrent().Name };
            //act
            oXDPDataMock.Encrypt(message, user);

            //assert
            Assert.IsTrue(true);
        }

        [Test]
        public void Decrypt_ValidMachineEncrypt_RecoverMessage()
        {
            // arrange
            XDPData oXDPData = new XDPData(new XDP.XDPCore.DataFormat.V1.V1DataFormatFactory());
            byte[] message = ASCIIEncoding.ASCII.GetBytes("hello world");
            string[] user = new string[] { System.Security.Principal.WindowsIdentity.GetCurrent().Name };
            //act
            oXDPData.Encrypt(message, user);
            byte[] ciphertext = oXDPData.Serialize();
            oXDPData = new XDPData(new XDP.XDPCore.DataFormat.V1.V1DataFormatFactory());
            oXDPData.Deserialize(ciphertext);
            // We need to be impersonating for decrypt to work
            System.Security.Principal.WindowsImpersonationContext wic = System.Security.Principal.WindowsIdentity.Impersonate(System.Security.Principal.WindowsIdentity.GetCurrent().Token);
            byte[] plaintext = new byte[0];
            try
            {
                plaintext = oXDPData.Decrypt();
            }
            catch (Exception e) { throw e; }
            finally { wic.Undo(); }

            //assert
            bool success = (message.Length == plaintext.Length);
            for (int i = 0; success && (i < message.Length); i++)
                if (message[i] != plaintext[i])
                    success = false;
            Assert.IsTrue(success);
        }

        [Test]
        [ExpectedException(typeof(XDP.XDPCore.XDPNullArgumentException), UserMessage = "Null DataIn was processed")]
        public void Encrypt_NullDataIn_XDPInvalidIdentityException()
        {
            // arrange
            XDPDataMock oXDPDataMock = new XDPDataMock(new DataFormatFactoryMock());
            byte[] message = null;
            string[] user = new string[] { System.Security.Principal.WindowsIdentity.GetCurrent().Name };
            //act
            oXDPDataMock.Encrypt(message, user);

            //assert
            Assert.IsTrue(false);
        }

        [Test]
        [ExpectedException(typeof(XDP.XDPCore.XDPZeroLengthArrayException), UserMessage = "No DataIn was processed")]
        public void Encrypt_EmptyDataIn_XDPZeroLengthArrayException()
        {
            // arrange
            XDPDataMock oXDPDataMock = new XDPDataMock(new DataFormatFactoryMock());
            byte[] message = new byte[] { };
            string[] user = new string[] { System.Security.Principal.WindowsIdentity.GetCurrent().Name };
            //act
            oXDPDataMock.Encrypt(message, user);

            //assert
            Assert.IsTrue(false);
        }

        [Test]
        [ExpectedException(typeof(XDP.XDPCore.XDPNullArgumentException), UserMessage = "Null Auths Users was processed")]
        public void Encrypt_NullAuthdUsers_XDPInvalidIdentityException()
        {
            // arrange
            XDPDataMock oXDPDataMock = new XDPDataMock(new DataFormatFactoryMock());
            byte[] message = new byte[] { 0 };
            string[] user = null;
            //act
            oXDPDataMock.Encrypt(message, user);

            //assert
            Assert.IsTrue(false);
        }

        [Test]
        [ExpectedException(typeof(XDP.XDPCore.XDPZeroLengthArrayException), UserMessage = "No Auths Users was processed")]
        public void Encrypt_EmptyAuthdUsers_XDPZeroLengthArrayException()
        {
            // arrange
            XDPDataMock oXDPDataMock = new XDPDataMock(new DataFormatFactoryMock());
            byte[] message = new byte[] { 0 };
            string[] user = new string[0];
            //act
            oXDPDataMock.Encrypt(message, user);

            //assert
            Assert.IsTrue(false);
        }

        [Test]
        [ExpectedException(typeof(XDP.XDPCore.XDPBadStateException), UserMessage = "Serialize was able to be called before Encrypt")]
        public void Serialize_CalledBeforeEncrypt_XDPBadStateException()
        {
            // arrange
            XDPDataMock oXDPDataMock = new XDPDataMock(new DataFormatFactoryMock());
            byte[] message = new byte[] { 0 };
            string[] user = new string[] { System.Security.Principal.WindowsIdentity.GetCurrent().Name };
            //act
            oXDPDataMock.Serialize();

            //assert
            Assert.IsTrue(false);
        }

        [Test]
        [ExpectedException(typeof(XDP.XDPCore.XDPNullArgumentException), UserMessage = "Null DataOut was processed")]
        public void Deserialize_NullDataOut_XDPInvalidIdentityException()
        {
            // arrange
            XDPDataMock oXDPDataMock = new XDPDataMock(new DataFormatFactoryMock());
            byte[] ciphertext = null;
            //act
            oXDPDataMock.Deserialize(ciphertext);

            //assert
            Assert.IsTrue(false);
        }

        [Test]
        [ExpectedException(typeof(XDP.XDPCore.XDPZeroLengthArrayException), UserMessage = "No DataIn was processed")]
        public void Deserialize_EmptyDataOut_XDPZeroLengthArrayException()
        {
            // arrange
            XDPDataMock oXDPDataMock = new XDPDataMock(new DataFormatFactoryMock());
            byte[] ciphertext = new byte[] { };
            //act
            oXDPDataMock.Deserialize(ciphertext);

            //assert
            Assert.IsTrue(false);
        }

        [Test]
        [ExpectedException(typeof(XDP.XDPCore.DataFormat.XDPInvalidFormatExcepton), UserMessage = "An invalid format was processed")]
        public void Deserialize_ShortDataOut_XDPInvalidFormatExcepton()
        {
            // arrange
            XDPDataMock oXDPDataMock = new XDPDataMock(new DataFormatFactoryMock());
            byte[] ciphertext = new byte[] { 0, 0, 0, 0, 0, 0, 0 };
            //act
            oXDPDataMock.Deserialize(ciphertext);

            //assert
            Assert.IsTrue(false);
        }

        [Test]
        [ExpectedException(typeof(XDP.XDPCore.DataFormat.XDPInvalidFormatExcepton), ExpectedMessage="DataOut did not start with byte sequence 'XDP'", UserMessage = "An invalid format was processed")]
        public void Deserialize_BadMagicBytes_XDPInvalidFormatExcepton()
        {
            // arrange
            XDPDataMock oXDPDataMock = new XDPDataMock(new DataFormatFactoryMock());
            byte[] ciphertext = new byte[8];
            //act
            oXDPDataMock.Deserialize(ciphertext);

            //assert
            Assert.IsTrue(false);
        }

        [Test]
        [ExpectedException(typeof(XDP.XDPCore.DataFormat.XDPInvalidFormatExcepton), UserMessage = "An invalid format was processed")]
        public void Deserialize_HeaderLengthToBig_XDPInvalidFormatExcepton()
        {
            // arrange
            XDPDataMock oXDPDataMock = new XDPDataMock(new DataFormatFactoryMock());
            byte[] ciphertext = new byte[8];
            byte[] MagicBytes = ASCIIEncoding.ASCII.GetBytes("XDP");
            ciphertext[0] = MagicBytes[0]; ciphertext[1] = MagicBytes[1]; ciphertext[2] = MagicBytes[2];    // Magic bytes
            ciphertext[3] = 0;                                                                              // Flags
            byte[] headerlength = new byte[4];                                                              // Header length
            // Make the header length 1 byte greater than the length of the data passed to the deserialize method
            Array.Copy(BitConverter.GetBytes(ciphertext.Length - 8 + 1), headerlength, 4);
            Array.Copy(headerlength, 0, ciphertext, 4, 4);
            //act
            oXDPDataMock.Deserialize(ciphertext);

            //assert
            Assert.IsTrue(false);
        }

        [Test]
        [ExpectedException(typeof(XDP.XDPCore.XDPZeroLengthArrayException), UserMessage = "Encrypted data of zero length was processed")]
        public void Deserialize_HeaderLengthToSmall_XDPZeroLengthArrayException()
        {
            // arrange
            XDPDataMock oXDPDataMock = new XDPDataMock(new DataFormatFactoryMock());
            byte[] ciphertext = new byte[8];
            byte[] MagicBytes = ASCIIEncoding.ASCII.GetBytes("XDP");
            ciphertext[0] = MagicBytes[0]; ciphertext[1] = MagicBytes[1]; ciphertext[2] = MagicBytes[2];    // Magic bytes
            ciphertext[3] = 0;                                                                              // Flags
            byte[] headerlength = new byte[4];                                                              // Header length
            // Make the header length 0
            Array.Copy(headerlength, 0, ciphertext, 4, 4);
            //act
            oXDPDataMock.Deserialize(ciphertext);

            //assert
            Assert.IsTrue(false);
        }

        [Test]
        [ExpectedException(typeof(XDP.XDPCore.DataFormat.XDPInvalidFormatExcepton), UserMessage = "An invalid format was processed")]
        public void Deserialize_HeaderLengthInt32MaxValue_XDPInvalidFormatExcepton()
        {
            // arrange
            XDPDataMock oXDPDataMock = new XDPDataMock(new DataFormatFactoryMock());
            byte[] ciphertext = new byte[8];
            byte[] MagicBytes = ASCIIEncoding.ASCII.GetBytes("XDP");
            ciphertext[0] = MagicBytes[0]; ciphertext[1] = MagicBytes[1]; ciphertext[2] = MagicBytes[2];    // Magic bytes
            ciphertext[3] = 0;                                                                              // Flags
            byte[] headerlength = new byte[4];                                                              // Header length
            // Make the header length Int32.MaxValue
            Array.Copy(BitConverter.GetBytes(Int32.MaxValue), headerlength, 4);
            Array.Copy(headerlength, 0, ciphertext, 4, 4);
            //act
            oXDPDataMock.Deserialize(ciphertext);

            //assert
            Assert.IsTrue(false);
        }

        [Test]
        [ExpectedException(typeof(XDP.XDPCore.DataFormat.XDPInvalidFormatExcepton), UserMessage = "An invalid format was processed")]
        public void Deserialize_HeaderLengthInt32MinValue_XDPInvalidFormatExcepton()
        {
            // arrange
            XDPDataMock oXDPDataMock = new XDPDataMock(new DataFormatFactoryMock());
            byte[] ciphertext = new byte[8];
            byte[] MagicBytes = ASCIIEncoding.ASCII.GetBytes("XDP");
            ciphertext[0] = MagicBytes[0]; ciphertext[1] = MagicBytes[1]; ciphertext[2] = MagicBytes[2];    // Magic bytes
            ciphertext[3] = 0;                                                                              // Flags
            byte[] headerlength = new byte[4];                                                              // Header length
            // Make the header length Int32.MinValue
            Array.Copy(BitConverter.GetBytes(Int32.MinValue), headerlength, 4);
            Array.Copy(headerlength, 0, ciphertext, 4, 4);
            //act
            oXDPDataMock.Deserialize(ciphertext);

            //assert
            Assert.IsTrue(false);
        }

        private void TestRemoveHeaderNode(string NodeName)
        {
            XDPData oXDPData = new XDPData(new XDP.XDPCore.DataFormat.V1.V1DataFormatFactory());
            byte[] message = ASCIIEncoding.ASCII.GetBytes("hello world");
            string[] user = new string[] { System.Security.Principal.WindowsIdentity.GetCurrent().Name };
            //act
            oXDPData.Encrypt(message, user);
            byte[] ciphertext = oXDPData.Serialize();

            DeserialiseTestHelper oHelper = new DeserialiseTestHelper();
            ciphertext = oHelper.RemoveHeaderNode(ciphertext, NodeName);

            oXDPData = new XDPData(new XDP.XDPCore.DataFormat.V1.V1DataFormatFactory());
            oXDPData.Deserialize(ciphertext);
            // We need to be impersonating for decrypt to work
            System.Security.Principal.WindowsImpersonationContext wic = System.Security.Principal.WindowsIdentity.Impersonate(System.Security.Principal.WindowsIdentity.GetCurrent().Token);
            byte[] plaintext = new byte[0];
            try
            {
                plaintext = oXDPData.Decrypt();
            }
            catch (Exception e) { throw e; }
            finally { wic.Undo(); }
        }

        private void TestBlankHeaderNode(string NodeName)
        {
            XDPData oXDPData = new XDPData(new XDP.XDPCore.DataFormat.V1.V1DataFormatFactory());
            byte[] message = ASCIIEncoding.ASCII.GetBytes("hello world");
            string[] user = new string[] { System.Security.Principal.WindowsIdentity.GetCurrent().Name };
            //act
            oXDPData.Encrypt(message, user);
            byte[] ciphertext = oXDPData.Serialize();

            DeserialiseTestHelper oHelper = new DeserialiseTestHelper();
            ciphertext = oHelper.BlankHeaderNode(ciphertext, NodeName);

            oXDPData = new XDPData(new XDP.XDPCore.DataFormat.V1.V1DataFormatFactory());
            oXDPData.Deserialize(ciphertext);
            // We need to be impersonating for decrypt to work
            System.Security.Principal.WindowsImpersonationContext wic = System.Security.Principal.WindowsIdentity.Impersonate(System.Security.Principal.WindowsIdentity.GetCurrent().Token);
            byte[] plaintext = new byte[0];
            try
            {
                plaintext = oXDPData.Decrypt();
            }
            catch (Exception e) { throw e; }
            finally { wic.Undo(); }
        }

        // An example of all the nodes in XDP for a local encryption
        //<?xml version="1.0"?>
        //<XDPHeader xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance" xmlns:xsd="http://www.w3.org/2001/XMLSchema" xmlns="urn:com.XDP.XDPData">
        //    <XDPVersion>0</XDPVersion>
        //    <XDPInternalHeaderV1 xsi:type="XDPInternalHeader">
        //        <XDPInternalCommonHeader>
        //            <XDPEncryptionAlgorithm>AesManaged</XDPEncryptionAlgorithm>
        //            <XDPEncryptionMode>CBC</XDPEncryptionMode>
        //            <XDPEncryptionIV>29100DA2D1F67C87EE1FC39C6CD2E68A</XDPEncryptionIV>
        //            <XDPSignatureAlgorithm>HMACSHA256</XDPSignatureAlgorithm>
        //            <XDPDataSignature>82FB6D75B7A4E0B19CEF7CDB54011930B35FCC5C50C21521FFA433F9E563E332</XDPDataSignature>
        //        </XDPInternalCommonHeader>
        //        <XDPInternalMachineHeader>
        //            <Hostname>IGNORE</Hostname>
        //            <XDPAuthorizedIdentities>
        //                <Identity>S-1-5-21-3244928938-2378541080-2249242540-1001</Identity>
        //            </XDPAuthorizedIdentities>
        //            <XDPEncryptedKeys>01000000D08C9DDF0115D1118C7A00C04FC297EB01000000B0A1B4348A49934B8A4504F28779E84700000000020000000000106600000001000020000000E7BAFCECC32DA09C9DA6A4B54F63AAA390D53740FE3C31191AFF4F35F40BD790000000000E8000000002000020000000DFDF8CAC0F134321B51E069DFB479ED43AA8AFD9B562F2C4E96B52C9F0AA7A56800100007E45376DB429F43F5952573DD07B7ED35E904B659A9E6B98D99E48FB2EE22AEB98A6C4E8AA16F1084C96FA15B2CAFBE1B4B08E31030A5A0405CD7505F02EDA6DDCAA4B4CAD0E5E407290BB331B3677694BF5D8EE32C6821A043C4DFF6D05611C48DA2E36054CD504E79105ECF8531A3FAF3BFD969066F15BDDABF12BF63C79F3103A93EA93317223E51235DEE1AD14EF5FCAF14356D70EC25E3A52F917D203524737E68EE15DC0E92118C4682E78AF5B2A17D412FFDCBA8AD1EBE4A2A8BFB7786A336C4A6073686B72B305089C7394326179CA30A9E9363E5D5C3BED14624FED2BD19C02B27BD3935FEEBAAD9BD51C738B830F7271E7D12E61723408069BB3B481F73D84FE762C8E3B4A6DCD8AF830E0F9ED9EBECB7028BF90EE919C1F1FABA951BBA936DF9CC8B626D8A02AAC6ED77F758536FC930CED2EFF2415856BAF01E00B20E8FD3FC6F84C2B11498263359B2E26D4ADC36AA106027CE155E54F59E6E559A506073D5C955630E0E538670B668789DCAD986E608CC48002BDDC154579EC40000000AC1FA4C1A6E230ACDA8BAF8C8E597B6DF07527693D39B373D43A35A49DD1BCBA2882931A104D125AD30FCB801142B17E4D614351A8BFA49E9E82AB3D9B5939AA</XDPEncryptedKeys>
        //        </XDPInternalMachineHeader>
        //        <XDPInternalHeaderSignatures>
        //            <XDPInternalHeaderMachineSignature>
        //                <XDPInternalHeaderMachineSignature>
        //                    <Hostname>IGNORE</Hostname>
        //                    <Value>30E5D94C30F64D7CADF36A80D7150DCCFBDC0D132F3BBFC4725328BA28F1D998</Value>
        //                </XDPInternalHeaderMachineSignature>
        //            </XDPInternalHeaderMachineSignature>
        //        </XDPInternalHeaderSignatures>
        //    </XDPInternalHeaderV1>
        //</XDPHeader>

        //[Test]
        //[ExpectedException(typeof(XDP.XDPCore.DataFormat.XDPInvalidFormatExcepton), UserMessage = "An invalid format was processed")]
        //public void Deserialize_RemovedXDPVersion_XDPInvalidFormatExcepton()
        //{
        //    TestRemoveHeaderNode("XDPVersion");

        //    //assert
        //    Assert.IsTrue(false);
        //}

        [Test]
        [ExpectedException(typeof(XDP.XDPCore.DataFormat.XDPInvalidFormatExcepton), UserMessage = "An invalid format was processed")]
        public void Deserialize_RemovedXDPInternalHeaderV1_XDPInvalidFormatExcepton()
        {
            TestRemoveHeaderNode("XDPInternalHeader");

            //assert
            Assert.IsTrue(false);
        }

        [Test]
        [ExpectedException(typeof(XDP.XDPCore.DataFormat.XDPInvalidFormatExcepton), UserMessage = "An invalid format was processed")]
        public void Deserialize_RemovedXDPInternalCommonHeader_XDPInvalidFormatExcepton()
        {
            TestRemoveHeaderNode("XDPInternalCommonHeader");

            //assert
            Assert.IsTrue(false);
        }

        [Test]
        [ExpectedException(typeof(XDP.XDPCore.XDPBadParameterException), UserMessage = "An invalid format was processed")]
        public void Deserialize_BlankXDPEncryptionAlgorithm_XDPBadParameterException()
        {
            TestBlankHeaderNode("XDPEncryptionAlgorithm");

            //assert
            Assert.IsTrue(false);
        }

        [Test]
        [ExpectedException(typeof(XDP.XDPCore.XDPBadParameterException), UserMessage = "An invalid format was processed")]
        public void Deserialize_RemovedXDPEncryptionMode_XDPBadParameterException()
        {
            TestRemoveHeaderNode("XDPEncryptionMode");

            //assert
            Assert.IsTrue(false);
        }

        [Test]
        [ExpectedException(typeof(XDP.XDPCore.XDPBadParameterException), UserMessage = "An invalid format was processed")]
        public void Deserialize_BlankXDPEncryptionMode_XDPBadParameterException()
        {
            TestBlankHeaderNode("XDPEncryptionMode");

            //assert
            Assert.IsTrue(false);
        }

        [Test]
        [ExpectedException(typeof(XDP.XDPCore.XDPBadParameterException), UserMessage = "An invalid format was processed")]
        public void Deserialize_RemovedXDPEncryptionIV_XDPBadParameterException()
        {
            TestRemoveHeaderNode("XDPEncryptionIV");

            //assert
            Assert.IsTrue(false);
        }

        [Test]
        [ExpectedException(typeof(XDP.XDPCore.XDPBadParameterException), UserMessage = "An invalid format was processed")]
        public void Deserialize_BlankXDPEncryptionIV_XDPBadParameterException()
        {
            TestBlankHeaderNode("XDPEncryptionIV");

            //assert
            Assert.IsTrue(false);
        }

        [Test]
        [ExpectedException(typeof(XDP.XDPCore.XDPBadParameterException), UserMessage = "An invalid format was processed")]
        public void Deserialize_RemovedXDPSignatureAlgorithm_XDPBadParameterException()
        {
            TestRemoveHeaderNode("XDPSignatureAlgorithm");

            //assert
            Assert.IsTrue(false);
        }

        [Test]
        [ExpectedException(typeof(XDP.XDPCore.XDPBadParameterException), UserMessage = "An invalid format was processed")]
        public void Deserialize_BlankXDPSignatureAlgorithm_XDPBadParameterException()
        {
            TestBlankHeaderNode("XDPSignatureAlgorithm");

            //assert
            Assert.IsTrue(false);
        }

        [Test]
        [ExpectedException(typeof(XDP.XDPCore.XDPBadParameterException), UserMessage = "An invalid format was processed")]
        public void Deserialize_RemovedXDPDataSignature_XDPBadParameterException()
        {
            TestRemoveHeaderNode("XDPDataSignature");

            //assert
            Assert.IsTrue(false);
        }

        [Test]
        [ExpectedException(typeof(XDP.XDPCore.DataFormat.XDPInvalidFormatExcepton), UserMessage = "An invalid format was processed")]
        public void Deserialize_RemovedXDPInternalMachineHeader_XDPInvalidFormatExcepton()
        {
            TestRemoveHeaderNode("XDPInternalMachineHeader");

            //assert
            Assert.IsTrue(false);
        }

        [Test]
        [ExpectedException(typeof(XDP.XDPCore.XDPBadParameterException), UserMessage = "An invalid format was processed")]
        public void Deserialize_RemovedHostname_XDPBadParameterException()
        {
            TestRemoveHeaderNode("Hostname");

            //assert
            Assert.IsTrue(false);
        }

        [Test]
        [ExpectedException(typeof(XDP.XDPCore.XDPBadParameterException), UserMessage = "An invalid format was processed")]
        public void Deserialize_BlankHostname_XDPBadParameterException()
        {
            TestBlankHeaderNode("Hostname");

            //assert
            Assert.IsTrue(false);
        }

        [Test]
        [ExpectedException(typeof(XDP.XDPCore.XDPBadParameterException), UserMessage = "An invalid format was processed")]
        public void Deserialize_RemovedXDPAuthorizedIdentities_XDPBadParameterException()
        {
            TestRemoveHeaderNode("XDPAuthorizedIdentities");

            //assert
            Assert.IsTrue(false);
        }

        [Test]
        [ExpectedException(typeof(XDP.XDPCore.XDPBadParameterException), UserMessage = "An invalid format was processed")]
        public void Deserialize_RemovedIdentity_XDPBadParameterException()
        {
            TestRemoveHeaderNode("Identity");

            //assert
            Assert.IsTrue(false);
        }

        [Test]
        [ExpectedException(typeof(XDP.XDPCore.XDPAuthorizationException), UserMessage = "An invalid format was processed")]
        public void Deserialize_BlankIdentity_XDPBadParameterException()
        {
            TestBlankHeaderNode("Identity");

            //assert
            Assert.IsTrue(false);
        }

        [Test]
        [ExpectedException(typeof(XDP.XDPCore.XDPBadParameterException), UserMessage = "An invalid format was processed")]
        public void Deserialize_RemovedXDPEncryptedKeys_XDPBadParameterException()
        {
            TestRemoveHeaderNode("XDPEncryptedKeys");

            //assert
            Assert.IsTrue(false);
        }

        [Test]
        [ExpectedException(typeof(XDP.XDPCore.XDPBadParameterException), UserMessage = "An invalid format was processed")]
        public void Deserialize_BlankXDPEncryptedKeys_XDPBadParameterException()
        {
            TestBlankHeaderNode("XDPEncryptedKeys");

            //assert
            Assert.IsTrue(false);
        }

        [Test]
        [ExpectedException(typeof(XDP.XDPCore.DataFormat.XDPInvalidFormatExcepton), UserMessage = "An invalid format was processed")]
        public void Deserialize_RemovedXDPInternalHeaderSignatures_XDPInvalidFormatExcepton()
        {
            TestRemoveHeaderNode("XDPInternalHeaderSignatures");

            //assert
            Assert.IsTrue(false);
        }

        [Test]
        [ExpectedException(typeof(XDP.XDPCore.XDPBadParameterException), UserMessage = "An invalid format was processed")]
        public void Deserialize_RemovedXDPInternalHeaderMachineSignature_XDPBadParameterException()
        {
            TestRemoveHeaderNode("XDPInternalHeaderMachineSignature");

            //assert
            Assert.IsTrue(false);
        }

        [Test]
        [ExpectedException(typeof(XDP.XDPCore.XDPBadParameterException), UserMessage = "An invalid format was processed")]
        public void Deserialize_RemovedValue_XDPBadParameterException()
        {
            TestRemoveHeaderNode("Value");

            //assert
            Assert.IsTrue(false);
        }

        [Test]
        [ExpectedException(typeof(XDP.XDPCore.XDPBadParameterException), UserMessage = "An invalid format was processed")]
        public void Deserialize_BlankValue_XDPBadParameterException()
        {
            TestBlankHeaderNode("Value");

            //assert
            Assert.IsTrue(false);
        }
    }
}
