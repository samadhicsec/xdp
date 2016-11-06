using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using NUnit.Framework;
using XDP.XDPCore.Identity;

namespace XDPCoreTests.Identity
{
    class IdentityCacheMock : IdentityCache
    {
        public IdentityCacheMock(TimeSpan CacheTimeout) : base(CacheTimeout)
        {
        }

        public int Count()
        {
            return m_oNameIdInfoDictionary.Count;
        }
    }

    [TestFixture]
    public class IdentityCacheTests
    {
        private IdentityInfo CreateIdentityInfo()
        {
            return new IdentityInfo(new System.Security.Principal.SecurityIdentifier(System.Security.Principal.WellKnownSidType.LocalSystemSid, null), IdentityType.Group);
        }

        [Test]
        public void Add_AddNullKey_CacheEmpty()
        {
            IdentityCacheMock icm = new IdentityCacheMock(new TimeSpan(0,10,0));
            icm.Add(null, CreateIdentityInfo());
            Assert.IsTrue(icm.Count() == 0);
        }

        [Test]
        public void Add_AddNullIdentityInfo_CacheEmpty()
        {
            IdentityCacheMock icm = new IdentityCacheMock(new TimeSpan(0, 10, 0));
            icm.Add("LocalSystem", null);
            Assert.IsTrue(icm.Count() == 0);
        }

        [Test]
        public void Add_AddEntry_CacheCountIs1()
        {
            IdentityCacheMock icm = new IdentityCacheMock(new TimeSpan(0, 10, 0));
            icm.Add("LocalSystem", CreateIdentityInfo());
            Assert.IsTrue(icm.Count() == 1);
        }

        [Test]
        public void Find_CanFindEntryAdded_EntryCached()
        {
            IdentityCacheMock icm = new IdentityCacheMock(new TimeSpan(0, 10, 0));
            icm.Add("LocalSystem", CreateIdentityInfo());
            Assert.IsNotNull(icm.Find("LocalSystem"));
        }

        [Test]
        public void Find_EntryExpires_CacheEmpty()
        {
            IdentityCacheMock icm = new IdentityCacheMock(new TimeSpan(0, 0, 1));
            icm.Add("LocalSystem", CreateIdentityInfo());
            System.Threading.Thread.Sleep(3000);
            Assert.IsTrue(icm.Count() == 0);
        }

        [Test]
        public void FindBySid_CanFindEntryAdded_EntryCached()
        {
            IdentityCacheMock icm = new IdentityCacheMock(new TimeSpan(0, 10, 0));
            IdentityInfo ii = CreateIdentityInfo();
            icm.Add("LocalSystem", ii);
            Assert.IsNotNull(icm.FindBySid(ii.oSid.Value));
        }

        [Test]
        public void FindBySid_EntryExpires_CacheEmpty()
        {
            IdentityCacheMock icm = new IdentityCacheMock(new TimeSpan(0, 0, 1));
            IdentityInfo ii = CreateIdentityInfo();
            icm.Add("LocalSystem", ii);
            System.Threading.Thread.Sleep(3000);
            Assert.IsTrue(icm.Count() == 0);
        }
    }
}
