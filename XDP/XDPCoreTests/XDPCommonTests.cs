using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using NUnit.Framework;
using XDP.XDPCore;

namespace XDPCoreTests
{
    [TestFixture]
    public class XDPCommonTests
    {
        [Test]
        public void DomainsEqual_IdenticalDomains_ReturnsTrue()
        {
            Assert.IsTrue(XDPCommon.DomainsEqual("Domain1", "Domain1"), "Identical domains not considered equal");
        }

        [Test]
        public void DomainsEqual_DifferentDomainsSameLength_ReturnsFalse()
        {
            Assert.IsFalse(XDPCommon.DomainsEqual("Domain1", "Domain2"), "Different domains considered equal");
        }

        [Test]
        public void DomainsEqual_FirstDomainNull_ReturnsFalse()
        {
            Assert.IsFalse(XDPCommon.DomainsEqual(null, "Domain1"));
        }

        [Test]
        public void DomainsEqual_SecondDomainNull_ReturnsFalse()
        {
            Assert.IsFalse(XDPCommon.DomainsEqual("Domain1", null));
        }

        [Test]
        public void DomainsEqual_EqualFQDNandNonFQDN_ReturnsTrue()
        {
            Assert.IsTrue(XDPCommon.DomainsEqual("Domain1", "Domain1.com"), "Identical domains not considered equal");
        }

        [Test]
        public void DomainsEqual_NonEqualFQDNandNonFQDN_ReturnsFalse()
        {
            Assert.IsFalse(XDPCommon.DomainsEqual("Domain1.dom", "Domain1.dom.com"), "Non-identical domains considered equal");
        }

        [Test]
        public void DomainsEqual_NonEqualFQDNandNonFQDN2Dots_ReturnsFalse()
        {
            Assert.IsFalse(XDPCommon.DomainsEqual("Domain1.dom1.dom2", "Domain1.dom1.dom2.com"), "Non-identical domains considered equal");
        }
    }
}
