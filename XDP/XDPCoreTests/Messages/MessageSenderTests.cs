using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using NUnit.Framework;
using XDP.XDPCore.Messaging;

namespace XDPCoreTests.Messages
{
    class TestIPC : IIPC
    {
        public bool bDataAvailable;

        #region IIPC Members

        public bool DataAvailable(object oClient)
        {
 	        return bDataAvailable;
        }

        public int Timeout()
        {
 	        return 5000;
        }

        public void CloseClient(object oClient)
        {
 	        
        }

        #endregion

    }

    [Serializable]
    class SerializableObject
    {
        public String Value;
    }

    [TestFixture]
    class MessageSenderTests
    {
        
    }
}
