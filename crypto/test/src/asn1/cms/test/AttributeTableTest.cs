﻿using System;

using NUnit.Framework;

using Org.BouncyCastle.Utilities.Test;

namespace Org.BouncyCastle.Asn1.Cms.Tests
{
    [TestFixture]
    public class AttributeTableTest
        : SimpleTest
    {
        private static readonly DerObjectIdentifier type1 = new DerObjectIdentifier("1.1.1");
        private static readonly DerObjectIdentifier type2 = new DerObjectIdentifier("1.1.2");
        private static readonly DerObjectIdentifier type3 = new DerObjectIdentifier("1.1.3");

        public override string Name => "AttributeTable";

        public override void PerformTest()
        {
            Asn1EncodableVector v = new Asn1EncodableVector();

            v.Add(new Attribute(type1, new DerSet(type1)));
            v.Add(new Attribute(type2, new DerSet(type2)));

            AttributeTable table = new AttributeTable(v);

            Attribute a = table[type1];
            if (a == null)
            {
                Fail("type1 attribute not found.");
            }
            if (!a.AttrValues.Equals(new DerSet(type1)))
            {
                Fail("wrong value retrieved for type1!");
            }

            a = table[type2];
            if (a == null)
            {
                Fail("type2 attribute not found.");
            }
            if (!a.AttrValues.Equals(new DerSet(type2)))
            {
                Fail("wrong value retrieved for type2!");
            }

            a = table[type3];
            if (a != null)
            {
                Fail("type3 attribute found when none expected.");
            }

            Asn1EncodableVector vec = table.GetAll(type1);
            if (vec.Count != 1)
            {
                Fail("wrong vector size for type1.");
            }

            vec = table.GetAll(type3);
            if (vec.Count != 0)
            {
                Fail("wrong vector size for type3.");
            }

            vec = table.ToAsn1EncodableVector();
            if (vec.Count != 2 || table.Count != 2)
            {
                Fail("wrong vector size for single.");
            }

            var t = table.ToDictionary();

            if (t.Count != 2)
            {
                Fail("hashtable wrong size.");
            }

            // multiple

            v = new Asn1EncodableVector();

            v.Add(new Attribute(type1, new DerSet(type1)));
            v.Add(new Attribute(type1, new DerSet(type2)));
            v.Add(new Attribute(type1, new DerSet(type3)));
            v.Add(new Attribute(type2, new DerSet(type2)));

            table = new AttributeTable(v);

            a = table[type1];
            if (!a.AttrValues.Equals(new DerSet(type1)))
            {
                Fail("wrong value retrieved for type1 multi get!");
            }

            vec = table.GetAll(type1);
            if (vec.Count != 3)
            {
                Fail("wrong vector size for multiple type1.");
            }

            a = (Attribute)vec[0];
            if (!a.AttrValues.Equals(new DerSet(type1)))
            {
                Fail("wrong value retrieved for type1(0)!");
            }

            a = (Attribute)vec[1];
            if (!a.AttrValues.Equals(new DerSet(type2)))
            {
                Fail("wrong value retrieved for type1(1)!");
            }

            a = (Attribute)vec[2];
            if (!a.AttrValues.Equals(new DerSet(type3)))
            {
                Fail("wrong value retrieved for type1(2)!");
            }

            vec = table.GetAll(type2);
            if (vec.Count != 1)
            {
                Fail("wrong vector size for multiple type2.");
            }

            vec = table.ToAsn1EncodableVector();
            if (vec.Count != 4 || table.Count != 4)
            {
                Fail("wrong vector size for multiple.");
            }
        }

        [Test]
        public void TestFunction()
        {
            string resultText = Perform().ToString();

            Assert.AreEqual(Name + ": Okay", resultText);
        }
    }
}
