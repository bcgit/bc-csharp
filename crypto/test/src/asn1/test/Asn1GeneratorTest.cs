using System.IO;

using NUnit.Framework;

using Org.BouncyCastle.Utilities;

namespace Org.BouncyCastle.Asn1.Tests
{
    /// <summary>ASN.1 streaming generator tests.</summary>
    /// <remarks>
    /// Tests that the streaming generators (<see cref="BerSequenceGenerator"/>, <see cref="BerOctetStringGenerator"/>,
    /// <see cref="DerSequenceGenerator"/>) produce valid encodings for untagged, explicitly tagged and implicitly
    /// tagged (X.690 8.14.2 / 8.14.3) forms, including high tag numbers (X.690 8.1.2.4).
    /// </remarks>
    [TestFixture]
    public class Asn1GeneratorTest
    {
        // spans the single-byte identifier limit (30) and multi-byte high-tag-number forms
        private static readonly int[] TAG_NOS = { 0, 1, 30, 31, 127, 128, 5000 };

        [Test]
        public void All()
        {
            byte[] content = new byte[2500];    // > 1000 to force octet string chunking
            for (int i = 0; i != content.Length; i++)
            {
                content[i] = (byte)i;
            }

            Asn1EncodableVector v = new Asn1EncodableVector();
            v.Add(DerInteger.ValueOf(4095));
            v.Add(DerOctetString.WithContents(new byte[]{ 1, 2, 3, 4 }));

            BerSequence berSeq = new BerSequence(v);
            DerSequence derSeq = new DerSequence(v);
            BerOctetString berOctets = new BerOctetString(content);

            // untagged baselines
            MemoryStream bOut = new MemoryStream();
            using (var berSeqGen = new BerSequenceGenerator(bOut))
            {
                AddSequenceContents(berSeqGen);
            }
            Assert.True(Arrays.AreEqual(berSeq.GetEncoded(), bOut.ToArray()), "untagged BER seq");

            bOut = new MemoryStream();
            using (var derSeqGen = new DerSequenceGenerator(bOut))
            {
                AddSequenceContents(derSeqGen);
            }
            Assert.True(Arrays.AreEqual(derSeq.GetEncoded(Asn1Encodable.Der), bOut.ToArray()), "untagged DER seq");

            bOut = new MemoryStream();
            using (var berOctGen = new BerOctetStringGenerator(bOut))
            {
                WriteOctets(berOctGen, content);
            }
            CheckBerOctetStringEncoding(bOut.ToArray(), content, "untagged BER octets");

            for (int i = 0; i != TAG_NOS.Length; i++)
            {
                int tagNo = TAG_NOS[i];

                TestTaggedBerSequence(tagNo, true, berSeq);
                TestTaggedBerSequence(tagNo, false, berSeq);
                TestTaggedDerSequence(tagNo, true, derSeq);
                TestTaggedDerSequence(tagNo, false, derSeq);
                TestTaggedBerOctetString(tagNo, true, content);
                TestTaggedBerOctetString(tagNo, false, content);
            }
        }

        private void AddSequenceContents(BerSequenceGenerator gen)
        {
            gen.AddObject(DerInteger.ValueOf(4095));
            gen.AddObject(DerOctetString.WithContents(new byte[]{ 1, 2, 3, 4 }));
        }

        private void AddSequenceContents(DerSequenceGenerator gen)
        {
            gen.AddObject(DerInteger.ValueOf(4095));
            gen.AddObject(DerOctetString.WithContents(new byte[]{ 1, 2, 3, 4 }));
        }

        private void WriteOctets(BerOctetStringGenerator gen, byte[] octets)
        {
            using (var octOut = gen.GetOctetOutputStream())
            {
                octOut.Write(octets, 0, octets.Length);
            }
        }

        private void TestTaggedBerSequence(int tagNo, bool declaredExplicit, BerSequence seq)
        {
            MemoryStream bOut = new MemoryStream();
            using (var gen = new BerSequenceGenerator(bOut, tagNo, declaredExplicit))
            {
                AddSequenceContents(gen);
            }

            byte[] expected = new BerTaggedObject(declaredExplicit, tagNo, seq).GetEncoded();
            Assert.True(Arrays.AreEqual(expected, bOut.ToArray()),
                "BER seq [" + tagNo + "] explicit=" + declaredExplicit);

            CheckSequenceRoundTrip(bOut.ToArray(), tagNo, declaredExplicit, seq);
        }

        private void TestTaggedDerSequence(int tagNo, bool declaredExplicit, DerSequence seq)
        {
            MemoryStream bOut = new MemoryStream();
            using (var gen = new DerSequenceGenerator(bOut, tagNo, declaredExplicit))
            {
                AddSequenceContents(gen);
            }

            byte[] expected = new DerTaggedObject(declaredExplicit, tagNo, seq).GetEncoded(Asn1Encodable.Der);
            Assert.That(Arrays.AreEqual(expected, bOut.ToArray()),
                "DER seq [" + tagNo + "] explicit=" + declaredExplicit);

            CheckSequenceRoundTrip(bOut.ToArray(), tagNo, declaredExplicit, seq);
        }

        private void TestTaggedBerOctetString(int tagNo, bool declaredExplicit, byte[] octets)
        {
            MemoryStream bOut = new MemoryStream();
            using (var gen = new BerOctetStringGenerator(bOut, tagNo, declaredExplicit))
            {
                WriteOctets(gen, octets);
            }

            CheckTaggedOctetStringEncoding(bOut.ToArray(), tagNo, declaredExplicit, octets,
                "BER octets [" + tagNo + "] explicit=" + declaredExplicit);
        }

        private void CheckSequenceRoundTrip(byte[] encoding, int tagNo, bool declaredExplicit, Asn1Sequence expected)
        {
            Asn1TaggedObject taggedObject = Asn1TaggedObject.GetInstance(encoding);
            Assert.That(taggedObject.HasContextTag(tagNo), "seq tagNo [" + tagNo + "]");

            var sequence = Asn1Sequence.GetInstance(taggedObject, declaredExplicit);
            Assert.AreEqual(expected, sequence, "seq content [" + tagNo + "] explicit=" + declaredExplicit);
        }

        private static void CheckBerOctetStringEncoding(byte[] encoding, byte[] expectedOctets, string message)
        {
            // Only require a valid encoding, not necessarily the same output as BerOctetString

            var octetString = Asn1OctetString.GetInstance(encoding);
            Assert.That(Arrays.AreEqual(expectedOctets, octetString.GetOctets()), message);
        }

        private static void CheckTaggedOctetStringEncoding(byte[] encoding, int expectedTagNo, bool declaredExplicit,
            byte[] expectedOctets, string message)
        {
            // Only require a valid encoding, not necessarily the same output as (BerTaggedObject/) BerOctetString

            var taggedObject = Asn1TaggedObject.GetInstance(encoding);
            Assert.That(taggedObject.HasContextTag(expectedTagNo), "octets tagNo [" + expectedTagNo + "]");

            var octetString = Asn1OctetString.GetInstance(taggedObject, declaredExplicit);
            Assert.That(Arrays.AreEqual(expectedOctets, octetString.GetOctets()),
                "octets content [" + expectedTagNo + "] explicit=" + declaredExplicit);
        }
    }
}
