using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Configuration;
using System.Configuration.Provider;
using System.Xml;
using System.Collections.Specialized;

namespace XDP
{
    public class XDPProtectedConfigurationProvider : ProtectedConfigurationProvider
    {
        List<String> AuthorizedIdentities;

        public override void Initialize(string name, NameValueCollection config)
        {
            //base.Initialize(name, config);

            String IDList = config["AuthorizedIdentities"];

            AuthorizedIdentities = new List<string>(IDList.Split(new Char[] { ' ', '\t', '\n' }));
        }

        public override XmlNode Decrypt(XmlNode encryptedNode)
        {
            // Decrypt encryptedNode.InnerText
            string decryptedData = UnicodeEncoding.UTF8.GetString(XDP.ProtectedData.Unprotect(Convert.FromBase64String(encryptedNode.InnerText)));

            XmlDocument xmlDoc = new XmlDocument();
            xmlDoc.PreserveWhitespace = true;
            xmlDoc.LoadXml(decryptedData);

            return xmlDoc.DocumentElement;
        }

        public override XmlNode Encrypt(XmlNode node)
        {
            // Encrypt the node.OuterXml
            String encryptedData = Convert.ToBase64String(XDP.ProtectedData.Protect(UnicodeEncoding.UTF8.GetBytes(node.OuterXml), AuthorizedIdentities));

            XmlDocument xmlDoc = new XmlDocument();
            xmlDoc.PreserveWhitespace = true;
            xmlDoc.LoadXml("<EncryptedData>" +
                encryptedData + "</EncryptedData>");

            return xmlDoc.DocumentElement;

        }
    }
}
