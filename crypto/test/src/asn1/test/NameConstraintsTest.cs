using System;

using NUnit.Framework;

using Org.BouncyCastle.Asn1.X509;

namespace Org.BouncyCastle.Asn1.Tests
{
    [TestFixture]
    public class NameConstraintsTest
    {
        [Test]
        public void EmptySequenceRejection()
        {
            // GeneralSubtree ::= SEQUENCE { base GeneralName, ... } - base is mandatory, so an empty
            // sequence is malformed and must be rejected with a clean ArgumentException rather than an unchecked
            // IndexOutOfRangeException escaping the parse path.
            try
            {
                GeneralSubtree.GetInstance(DerSequence.Empty);
                Assert.Fail("empty GeneralSubtree accepted");
            }
            catch (ArgumentException e)
            {
                Assert.NotNull(e.Message);
                Assert.That(e.Message.StartsWith("Bad sequence size: 0"));
            }
        }

        [Test]
        public void EmptyExcludedSubtreesRejection()
        {
            // GeneralSubtrees ::= SEQUENCE SIZE (1..MAX) OF GeneralSubtree (RFC 5280 sec. 4.2.1.10):
            // an empty permittedSubtrees [0] must be rejected.
            try
            {
                NameConstraints.GetInstance(new DerSequence(new DerTaggedObject(false, 1, DerSequence.Empty)));
                Assert.Fail("empty permittedSubtrees accepted");
            }
            catch (ArgumentException e)
            {
                Assert.NotNull(e.Message);
                Assert.That(e.Message.StartsWith("Minimum sequence size "));
            }
        }

        [Test]
        public void EmptyPermittedSubtreesRejection()
        {
            // GeneralSubtrees ::= SEQUENCE SIZE (1..MAX) OF GeneralSubtree (RFC 5280 sec. 4.2.1.10):
            // an empty permittedSubtrees [0] must be rejected.
            try
            {
                NameConstraints.GetInstance(new DerSequence(new DerTaggedObject(false, 0, DerSequence.Empty)));
                Assert.Fail("empty permittedSubtrees accepted");
            }
            catch (ArgumentException e)
            {
                Assert.NotNull(e.Message);
                Assert.That(e.Message.StartsWith("Minimum sequence size "));
            }
        }

        [Test]
        public void Roundtrip()
        {
            // a valid non-empty NameConstraints still round-trips through the parse path.
            GeneralSubtree subtree = new GeneralSubtree(new GeneralName(GeneralName.DnsName, "test.example.com"));
            NameConstraints nc = new NameConstraints(new GeneralSubtrees(subtree), null);

            NameConstraints parsed = NameConstraints.GetInstance(nc.ToAsn1Object());
            Assert.NotNull(parsed.PermittedSubtreesValue, "permitted subtrees present");
            Assert.AreEqual(1, parsed.PermittedSubtreesValue.Elements.Count, "permitted subtree count");
            Assert.Null(parsed.ExcludedSubtreesValue, "excluded subtrees absent");
        }
    }
}
