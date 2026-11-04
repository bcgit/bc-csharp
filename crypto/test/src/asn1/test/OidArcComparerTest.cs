using System;
using System.Collections.Generic;
using System.Text;

using NUnit.Framework;

using Org.BouncyCastle.Math;
using Org.BouncyCastle.Utilities;

namespace Org.BouncyCastle.Asn1.Tests
{
    [TestFixture]
    public class OidArcComparerTest
    {
        // Strictly increasing in arc order. Includes subidentifier length boundaries (127/128, 2.47/2.48 for the
        // combined first subidentifier) and pairs whose plain octet order is the reverse of arc order.
        private static readonly string[] OrderedOids =
        {
            "0.0",
            "0.39",
            "1.0",
            "1.2",
            "1.2.0",
            "1.2.3",
            "1.2.10",
            "1.2.127",
            "1.2.128",
            "1.2.840",
            "1.2.840.113549",
            "1.2.16383",
            "1.2.16383.0",      // 2A FF 7F 00
            "1.2.16384",        // 2A 81 80 00
            "1.3.6.1.4.1.311",  // ... 82 37
            "1.3.6.1.4.1.22554",// ... 81 B0 1A
            "1.10",
            "1.39",
            "2.0",
            "2.47",
            "2.48",
            "2.999",
            "2.999.1",
            "2.18446744073709551616",
        };

        // Strictly increasing in arc order, as above.
        private static readonly string[] OrderedRelativeOids =
        {
            "0",
            "0.0",
            "1",
            "1.3",
            "1.10",
            "1.127",
            "1.128",
            "1.16383",
            "1.16383.0",
            "1.16384",
            "10",
            "127",
            "128",
            "16383.0",          // FF 7F 00
            "16384",            // 81 80 00
            "18446744073709551616",
        };

        [Test]
        public void OidOrderedPairs()
        {
            CheckOrderedPairs(DerObjectIdentifier.ArcComparer, OrderedOids, id => new DerObjectIdentifier(id));
        }

        [Test]
        public void RelativeOidOrderedPairs()
        {
            CheckOrderedPairs(Asn1RelativeOid.ArcComparer, OrderedRelativeOids, id => new Asn1RelativeOid(id));
        }

        [Test]
        public void EqualContents()
        {
            foreach (string id in OrderedOids)
            {
                CheckEqualContents(new DerObjectIdentifier(id));
            }
            foreach (string id in OrderedRelativeOids)
            {
                CheckEqualContents(new Asn1RelativeOid(id));
            }
        }

        [Test]
        public void OidNulls()
        {
            CheckNulls(DerObjectIdentifier.ArcComparer, new DerObjectIdentifier("1.2.3"));
        }

        [Test]
        public void RelativeOidNulls()
        {
            CheckNulls(Asn1RelativeOid.ArcComparer, new Asn1RelativeOid("1.2.3"));
        }

        [Test]
        public void OidRandomAgainstReference()
        {
            CheckRandomAgainstReference(DerObjectIdentifier.ArcComparer, RandomOidArcs,
                id => new DerObjectIdentifier(id), sharedMinimum: 2);
        }

        [Test]
        public void RelativeOidRandomAgainstReference()
        {
            CheckRandomAgainstReference(Asn1RelativeOid.ArcComparer, RandomRelativeOidArcs,
                id => new Asn1RelativeOid(id), sharedMinimum: 1);
        }

        private static void CheckOrderedPairs<T>(IComparer<T> comparer, string[] ordered, Func<string, T> create)
        {
            for (int i = 0; i < ordered.Length; ++i)
            {
                T a = create(ordered[i]);

                Assert.AreEqual(0, comparer.Compare(a, a), ordered[i]);

                for (int j = i + 1; j < ordered.Length; ++j)
                {
                    T b = create(ordered[j]);

                    Assert.Less(comparer.Compare(a, b), 0, ordered[i] + " vs " + ordered[j]);
                    Assert.Greater(comparer.Compare(b, a), 0, ordered[j] + " vs " + ordered[i]);
                }
            }
        }

        private static void CheckEqualContents(Asn1Object oid)
        {
            byte[] encoding = oid.GetEncoded();
            Assert.Less(encoding[1], 0x80);
            byte[] contents = Arrays.CopyOfRange(encoding, 2, encoding.Length);

            Assert.AreEqual(0, Asn1RelativeOid.CompareContents(contents, Arrays.Clone(contents)), oid.ToString());
        }

        private static void CheckNulls<T>(IComparer<T> comparer, T value)
            where T : class
        {
            Assert.AreEqual(0, comparer.Compare(null, null));
            Assert.Less(comparer.Compare(null, value), 0);
            Assert.Greater(comparer.Compare(value, null), 0);
        }

        private static void CheckRandomAgainstReference<T>(IComparer<T> comparer,
            Func<Random, List<BigInteger>> randomArcs, Func<string, T> create, int sharedMinimum)
        {
            var random = new Random(0x0AC0);

            for (int n = 0; n < 5000; ++n)
            {
                var xArcs = randomArcs(random);
                var yArcs = randomArcs(random);

                // Mostly share a prefix, so that comparisons reach deep mismatches between similar subidentifiers.
                // For OIDs the second arc's range depends on the first, so they are only shared together.
                int shared = random.Next(System.Math.Min(xArcs.Count, yArcs.Count) + 1);
                if (shared > 0 && shared < sharedMinimum)
                {
                    shared = sharedMinimum;
                }

                for (int k = 0; k < shared; ++k)
                {
                    yArcs[k] = xArcs[k];
                }

                string xID = ToID(xArcs), yID = ToID(yArcs);
                T x = create(xID), y = create(yID);

                int expected = ReferenceCompare(xArcs, yArcs);

                Assert.AreEqual(expected, System.Math.Sign(comparer.Compare(x, y)), xID + " vs " + yID);
                Assert.AreEqual(-expected, System.Math.Sign(comparer.Compare(y, x)), yID + " vs " + xID);
            }
        }

        private static List<BigInteger> RandomOidArcs(Random random)
        {
            var arcs = new List<BigInteger>();

            int first = random.Next(3);
            arcs.Add(BigInteger.ValueOf(first));
            arcs.Add(first < 2 ? BigInteger.ValueOf(random.Next(40)) : RandomArc(random));

            int count = random.Next(6);
            for (int k = 0; k < count; ++k)
            {
                arcs.Add(RandomArc(random));
            }

            return arcs;
        }

        private static List<BigInteger> RandomRelativeOidArcs(Random random)
        {
            var arcs = new List<BigInteger>();

            int count = 1 + random.Next(6);
            for (int k = 0; k < count; ++k)
            {
                arcs.Add(RandomArc(random));
            }

            return arcs;
        }

        private static BigInteger RandomArc(Random random)
        {
            // Mostly 1-4 octet subidentifiers, occasionally much larger
            int bits = random.Next(8) == 0 ? random.Next(200) : random.Next(23);
            return new BigInteger(bits, random);
        }

        private static int ReferenceCompare(List<BigInteger> x, List<BigInteger> y)
        {
            int count = System.Math.Min(x.Count, y.Count);
            for (int k = 0; k < count; ++k)
            {
                int c = x[k].CompareTo(y[k]);
                if (c != 0)
                    return System.Math.Sign(c);
            }

            return System.Math.Sign(x.Count.CompareTo(y.Count));
        }

        private static string ToID(List<BigInteger> arcs)
        {
            var sb = new StringBuilder();
            foreach (var arc in arcs)
            {
                if (sb.Length > 0)
                {
                    sb.Append('.');
                }
                sb.Append(arc);
            }
            return sb.ToString();
        }
    }
}
