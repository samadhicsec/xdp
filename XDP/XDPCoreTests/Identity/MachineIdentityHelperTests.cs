using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using NUnit.Framework;
using System.Security.Principal;
using XDP.XDPCore.Identity;

namespace XDPCoreTests.Identity
{
    class MockIdentityCache : IIdentityCache
    {
        public IdentityInfo CacheEntry = null;

        #region IIdentityCache Members

        public void Add(string Identity, IdentityInfo oIdentityInfo)
        {
            
        }

        public IdentityInfo Find(string Identity)
        {
            return CacheEntry;
        }

        public IdentityInfo FindBySid(string Sid)
        {
            return CacheEntry;
        }

        #endregion
    }


    class MachineIdentityHelperPartialMock : MachineIdentityHelper
    {
        public bool m_bIsUser = false;
        public bool m_bIsGroup = false;
        public MockIdentityCache oMockIdentityCache = new MockIdentityCache();

        public MachineIdentityHelperPartialMock(bool? IsUser) : base()
        {
            if (true == IsUser)
                m_bIsUser = true;
            else if (false == IsUser)
                m_bIsGroup = true;
        }

        protected override IIdentityCache CreateIdentityCache()
        {
            return oMockIdentityCache;
        }

        protected override SecurityIdentifier FindSid(string strIdentity, out bool bIsUser)
        {
            bIsUser = true;
            SecurityIdentifier si = null;
            if (m_bIsUser)
            {
                si = new SecurityIdentifier(WellKnownSidType.LocalSystemSid, null);
                bIsUser = true;
            }
            else if (m_bIsGroup)
            {
                si = new SecurityIdentifier(WellKnownSidType.BuiltinAdministratorsSid, null);
                bIsUser = false;
            }
            return si;
        }
    }


    [TestFixture]
    class MachineIdentityHelperTests
    {
        [Test]
        [ExpectedException(typeof(XDP.XDPCore.XDPInvalidIdentityException), UserMessage="A non-existant identity was resolved")]
        public void LocalIdentitiesDictionary_NonExistantIdentity_ThrowsException()
        {
            // arrange
            String[] oIdentities = new string[1];
            oIdentities[0] = "nonexistantuser";
            // act
            MachineIdentityHelperPartialMock oMIHelper = new MachineIdentityHelperPartialMock(null);
            oMIHelper.AddIdentites(oIdentities);
            Console.WriteLine(oMIHelper.LocalIdentitiesDictionary[Environment.MachineName][0].Value);
            //assert
        }

        [Test]
        public void LocalIdentitiesDictionary_UserIdentity_LocalIDDictionaryCountIs1()
        {
            // arrange
            String[] oIdentities = new string[1];
            oIdentities[0] = "existantuser";
            // act
            MachineIdentityHelperPartialMock oMIHelper = new MachineIdentityHelperPartialMock(true);
            oMIHelper.AddIdentites(oIdentities);
            //assert
            Assert.IsTrue(oMIHelper.LocalIdentitiesDictionary[Environment.MachineName].Count == 1);
        }

        [Test]
        public void LocalIdentitiesDictionary_UserIdentityLookup_CheckTiming()
        {
            // arrange
            String[] oIdentities = new string[1];
            for (int i = 0; i < oIdentities.Length; i++)
            {
                oIdentities[i] = WindowsIdentity.GetCurrent().Name;
                //oIdentities[i] = (Environment.MachineName + "\\NETWORK SERVICE");
            }
            
            // act
            MachineIdentityHelper oMIHelper = new MachineIdentityHelper();
            DateTime oStart = DateTime.Now;
            oMIHelper.AddIdentites(oIdentities);
            Dictionary<String, List<SecurityIdentifier>> LocalIdentitiesDictionary = oMIHelper.LocalIdentitiesDictionary;
            TimeSpan oDuration = DateTime.Now - oStart;
            Console.WriteLine("Duration = " + oDuration.ToString());
            //assert
            Assert.IsTrue(true);
        }

        [Test]
        public void LocalIdentitiesDictionary_LocalSystemIdentityResolves_LocalIDDictionaryCountIs1()
        {
            // arrange
            String[] oIdentities = new string[] {"System", "LocalSystem", "Local System", "NT AUTHORITY\\Local System", (Environment.MachineName + "\\Local System") };
            // act
            MachineIdentityHelper oMIHelper = new MachineIdentityHelper();
            oMIHelper.AddIdentites(oIdentities);
            //assert
            Assert.IsTrue(oMIHelper.LocalIdentitiesDictionary[Environment.MachineName].Count == 1);
        }

        [Test]
        public void LocalIdentitiesDictionary_NetworkServiceIdentityResolves_LocalIDDictionaryCountIs1()
        {
            // arrange
            String[] oIdentities = new string[] { "Network", "NetworkService", "Network Service", "NTAUTHORITY\\NetworkService", (Environment.MachineName + "\\NetworkService") };
            // act
            MachineIdentityHelper oMIHelper = new MachineIdentityHelper();
            oMIHelper.AddIdentites(oIdentities);
            //assert
            Assert.IsTrue(oMIHelper.LocalIdentitiesDictionary[Environment.MachineName].Count == 1);
        }

        [Test]
        public void LocalIdentitiesDictionary_LocalServiceIdentityResolves_LocalIDDictionaryCountIs1()
        {
            // arrange
            String[] oIdentities = new string[] { "Local", "LocalService", "Local Service", "NTAUTHORITY\\Local Service", (Environment.MachineName + "\\LocalService") };
            // act
            MachineIdentityHelper oMIHelper = new MachineIdentityHelper();
            oMIHelper.AddIdentites(oIdentities);
            //assert
            Assert.IsTrue(oMIHelper.LocalIdentitiesDictionary[Environment.MachineName].Count == 1);
        }

        [Test]
        public void LocalIdentitiesDictionary_UsersIdentityResolves_LocalIDDictionaryCountIs1()
        {
            // arrange
            String[] oIdentities = new string[] { "Users" };
            // act
            MachineIdentityHelper oMIHelper = new MachineIdentityHelper();
            oMIHelper.AddIdentites(oIdentities);
            //assert
            Assert.IsTrue(oMIHelper.LocalIdentitiesDictionary[Environment.MachineName].Count == 1);
        }

        [Test]
        public void LocalIdentitiesDictionary_AdministratorsIdentityResolves_LocalIDDictionaryCountIs1()
        {
            // arrange
            String[] oIdentities = new string[] { "Administrators" };
            // act
            MachineIdentityHelper oMIHelper = new MachineIdentityHelper();
            oMIHelper.AddIdentites(oIdentities);
            //assert
            Assert.IsTrue(oMIHelper.LocalIdentitiesDictionary[Environment.MachineName].Count == 1);
        }

        [Test]
        public void LocalIdentitiesDictionary_SidsResolve_LocalIDDictionaryCountIsArrayLength()
        {
            // arrange
            SecurityIdentifier InteractiveSid = new SecurityIdentifier(WellKnownSidType.InteractiveSid, null);
            SecurityIdentifier AuthenticatedUserSid = new SecurityIdentifier(WellKnownSidType.AuthenticatedUserSid, null);
            SecurityIdentifier AnonymousSid = new SecurityIdentifier(WellKnownSidType.AnonymousSid, null);
            String[] oIdentities = new string[] { InteractiveSid.Value, AuthenticatedUserSid.Value, AnonymousSid.Value};
            // act
            MachineIdentityHelper oMIHelper = new MachineIdentityHelper();
            oMIHelper.AddIdentites(oIdentities);
            //Console.WriteLine("Resolved Count = " + oMIHelper.LocalIdentitiesDictionary[Environment.MachineName].Count.ToString());
            //assert
            Assert.IsTrue(oMIHelper.LocalIdentitiesDictionary[Environment.MachineName].Count == oIdentities.Length);
        }
    }
}
