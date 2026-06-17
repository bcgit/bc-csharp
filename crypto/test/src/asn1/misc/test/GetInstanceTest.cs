using System;

using NUnit.Framework;

using Org.BouncyCastle.Asn1.Crmf;

namespace Org.BouncyCastle.Asn1.Misc.Tests
{
    [TestFixture]
    public class GetInstanceTest
    {
        [Test]
        public void OptionalValidityAtLeastOne()
        {
            // RFC 4211: OptionalValidity requires at least one of notBefore/notAfter.
            // An empty SEQUENCE must be rejected on decode, matching the constructor.
            try
            {
                OptionalValidity.GetInstance(DerSequence.Empty);
                Assert.Fail("empty OptionalValidity SEQUENCE accepted on decode");
            }
            catch (ArgumentException e)
            {
                Assert.NotNull(e.Message);
                Assert.That(e.Message.StartsWith("at least one of notBefore/notAfter MUST be present."), "exception message");
            }
        }
    }
}
