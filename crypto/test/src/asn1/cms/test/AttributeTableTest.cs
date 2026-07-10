using System;

using NUnit.Framework;

using Org.BouncyCastle.Utilities.Test;

namespace Org.BouncyCastle.Asn1.Cms.Tests
{
    [TestFixture]
    public class AttributeTableTest
    {
        private static readonly DerObjectIdentifier type1 = new DerObjectIdentifier("1.1.1");
        private static readonly DerObjectIdentifier type2 = new DerObjectIdentifier("1.1.2");
        private static readonly DerObjectIdentifier type3 = new DerObjectIdentifier("1.1.3");

        [Test]
        public void Basic()
        {
            Asn1EncodableVector v = new Asn1EncodableVector(
                new Asn1.Cms.Attribute(type1, new DerSet(type1)),
                new Asn1.Cms.Attribute(type2, new DerSet(type2)));

            AttributeTable table = new AttributeTable(v);

            Assert.AreEqual(2, table.Count, "wrong count for table");

            Assert.True(table.HasAny(type1));
            Assert.True(table.HasAny(type2));
            Assert.False(table.HasAny(type3));

            Asn1.Cms.Attribute a1 = table[type1];
            Assert.NotNull(a1, "type1 attribute not found.");
            Assert.AreEqual(new DerSet(type1), a1.AttrValues, "wrong value retrieved for type1!");

            Asn1.Cms.Attribute a2 = table[type2];
            Assert.NotNull(a2, "type2 attribute not found.");
            Assert.AreEqual(new DerSet(type2), a2.AttrValues, "wrong value retrieved for type2!");

            Asn1.Cms.Attribute a3 = table[type3];
            Assert.Null(a3, "type3 attribute found when none expected.");

            Asn1EncodableVector vec1 = table.GetAll(type1);
            Assert.AreEqual(1, vec1.Count, "wrong vector size for type1.");

            Asn1EncodableVector vec3 = table.GetAll(type3);
            Assert.AreEqual(0, vec3.Count, "wrong vector size for type3.");

            Asn1EncodableVector vec = table.ToAsn1EncodableVector();
            Assert.AreEqual(2, vec.Count, "wrong vector size for single.");

            var t = table.ToDictionary();
            Assert.AreEqual(2, t.Count, "Dictionary wrong size.");

            // multiple

            v = new Asn1EncodableVector(
                new Asn1.Cms.Attribute(type1, new DerSet(type1)),
                new Asn1.Cms.Attribute(type1, new DerSet(type2)),
                new Asn1.Cms.Attribute(type1, new DerSet(type3)),
                new Asn1.Cms.Attribute(type2, new DerSet(type2)));

            table = new AttributeTable(v);

            Assert.AreEqual(4, table.Count, "wrong count for table");

            Assert.True(table.HasAny(type1));
            Assert.True(table.HasAny(type2));
            Assert.False(table.HasAny(type3));

            a1 = table[type1];
            Assert.AreEqual(new DerSet(type1), a1.AttrValues, "wrong value retrieved for type1 multi get!");

            vec = table.GetAll(type1);
            Assert.AreEqual(3, vec.Count, "wrong vector size for multiple type1.");

            Asn1.Cms.Attribute a;

            a = (Asn1.Cms.Attribute)vec[0];
            Assert.AreEqual(new DerSet(type1), a.AttrValues, "wrong value retrieved for type1(0)!");

            a = (Asn1.Cms.Attribute)vec[1];
            Assert.AreEqual(new DerSet(type2), a.AttrValues, "wrong value retrieved for type1(1)!");

            a = (Asn1.Cms.Attribute)vec[2];
            Assert.AreEqual(new DerSet(type3), a.AttrValues, "wrong value retrieved for type1(2)!");

            vec = table.GetAll(type2);
            Assert.AreEqual(1, vec.Count, "wrong vector size for multiple type2.");

            vec = table.ToAsn1EncodableVector();
            Assert.AreEqual(4, vec.Count, "wrong vector size for multiple.");

            // Attribute.GetInstance must reject a structurally-valid SEQUENCE whose type element is not an
            // OBJECT IDENTIFIER (here a tagged object) with ArgumentException, rather than leak an
            // InvalidCastException from the (DerObjectIdentifier) cast out of the GetInstance contract.
            DerSequence badAttr = DerSequence.FromElements(
                new DerTaggedObject(0, new DerOctetString(new byte[]{ 1, 2, 3 })),
                new DerSet());
            try
            {
                Asn1.Cms.Attribute.GetInstance(badAttr);
                Assert.Fail("Attribute.GetInstance accepted a non-OID type element");
            }
            catch (ArgumentException)
            {
                // expected - documented malformed reject
            }
        }
    }
}
