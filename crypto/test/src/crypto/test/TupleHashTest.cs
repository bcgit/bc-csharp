using System;

using NUnit.Framework;

using Org.BouncyCastle.Crypto.Digests;
using Org.BouncyCastle.Security;
using Org.BouncyCastle.Utilities;
using Org.BouncyCastle.Utilities.Encoders;
using Org.BouncyCastle.Utilities.Test;

namespace Org.BouncyCastle.Crypto.Tests
{
    /**
     * TupleHash test vectors from:
     * <p>
     * https://csrc.nist.gov/CSRC/media/Projects/Cryptographic-Standards-and-Guidelines/documents/examples/KMAC_samples.pdf
     */
    [TestFixture]
    public class TupleHashTest
        : SimpleTest
    {
        public override string Name
        {
            get { return "TupleHash"; }
        }

        public override void PerformTest()
        {
            TupleHash tHash = new TupleHash(128, new byte[0]);

            tHash.BlockUpdate(Hex.Decode("000102"), 0, 3);
            tHash.BlockUpdate(Hex.Decode("101112131415"), 0, 6);

            byte[] res = new byte[tHash.GetDigestSize()];

            tHash.DoFinal(res, 0);
            IsTrue("oops!", Arrays.AreEqual(Hex.Decode("C5 D8 78 6C 1A FB 9B 82 11 1A B3 4B 65 B2 C0 04 8F A6 4E 6D 48 E2 63 26 4C E1 70 7D 3F FC 8E D1"), res));

            tHash = new TupleHash(128, Strings.ToByteArray("My Tuple App"));

            tHash.BlockUpdate(Hex.Decode("000102"), 0, 3);
            tHash.BlockUpdate(Hex.Decode("101112131415"), 0, 6);

            tHash.DoFinal(res, 0);

            IsTrue("oops!", Arrays.AreEqual(Hex.Decode("75 CD B2 0F F4 DB 11 54 E8 41 D7 58 E2 41 60 C5 4B AE 86 EB 8C 13 E7 F5 F4 0E B3 55 88 E9 6D FB"), res));

            tHash.BlockUpdate(Hex.Decode("000102"), 0, 3);
            tHash.BlockUpdate(Hex.Decode("101112131415"), 0, 6);
            tHash.BlockUpdate(Hex.Decode("202122232425262728"), 0, 9);

            tHash.DoFinal(res, 0);

            IsTrue("oops!", Arrays.AreEqual(Hex.Decode("E6 0F 20 2C 89 A2 63 1E DA 8D 4C 58 8C A5 FD 07 F3 9E 51 51 99 8D EC CF 97 3A DB 38 04 BB 6E 84"), res));

            tHash = new TupleHash(256, new byte[0]);

            tHash.BlockUpdate(Hex.Decode("000102"), 0, 3);
            tHash.BlockUpdate(Hex.Decode("101112131415"), 0, 6);

            res = new byte[tHash.GetDigestSize()];

            tHash.DoFinal(res, 0);

            IsTrue("oops!", Arrays.AreEqual(Hex.Decode("CF B7 05 8C AC A5 E6 68 F8 1A 12 A2 0A 21 95 CE 97 A9 25 F1 DB A3 E7 44 9A 56 F8 22 01 EC 60 73 11 AC 26 96 B1 AB 5E A2 35 2D F1 42 3B DE 7B D4 BB 78 C9 AE D1 A8 53 C7 86 72 F9 EB 23 BB E1 94"), res));

            tHash = new TupleHash(256, Strings.ToByteArray("My Tuple App"));

            tHash.BlockUpdate(Hex.Decode("000102"), 0, 3);
            tHash.BlockUpdate(Hex.Decode("101112131415"), 0, 6);

            tHash.DoFinal(res, 0);

            IsTrue("oops!", Arrays.AreEqual(Hex.Decode("14 7C 21 91 D5 ED 7E FD 98 DB D9 6D 7A B5 A1 16 92 57 6F 5F E2 A5 06 5F 3E 33 DE 6B BA 9F 3A A1 C4 E9 A0 68 A2 89 C6 1C 95 AA B3 0A EE 1E 41 0B 0B 60 7D E3 62 0E 24 A4 E3 BF 98 52 A1 D4 36 7E"), res));

            tHash.BlockUpdate(Hex.Decode("000102"), 0, 3);
            tHash.BlockUpdate(Hex.Decode("101112131415"), 0, 6);
            tHash.BlockUpdate(Hex.Decode("202122232425262728"), 0, 9);

            tHash.DoFinal(res, 0);

            IsTrue("oops!", Arrays.AreEqual(Hex.Decode("45 00 0B E6 3F 9B 6B FD 89 F5 47 17 67 0F 69 A9 BC 76 35 91 A4 F0 5C 50 D6 88 91 A7 44 BC C6 E7 D6 D5 B5 E8 2C 01 8D A9 99 ED 35 B0 BB 49 C9 67 8E 52 6A BD 8E 85 C1 3E D2 54 02 1D B9 E7 90 CE"), res));

            tHash = new TupleHash(128, Strings.ToByteArray("My Tuple App"));

            tHash.BlockUpdate(Hex.Decode("000102"), 0, 3);
            tHash.BlockUpdate(Hex.Decode("101112131415"), 0, 6);
            tHash.BlockUpdate(Hex.Decode("202122232425262728"), 0, 9);

            res = new byte[32];
            tHash.Output(res, 0, res.Length);

            IsTrue("oops!", !Arrays.AreEqual(Hex.Decode("E6 0F 20 2C 89 A2 63 1E DA 8D 4C 58 8C A5 FD 07 F3 9E 51 51 99 8D EC CF 97 3A DB 38 04 BB 6E 84"), res));
            IsTrue("oops!", Arrays.AreEqual(Hex.Decode("900fe16cad098d28e74d632ed852f99daab7f7df4d99e775657885b4bf76d6f8"), res));

            tHash = new TupleHash(256, Strings.ToByteArray("My Tuple App"));

            tHash.BlockUpdate(Hex.Decode("000102"), 0, 3);
            tHash.BlockUpdate(Hex.Decode("101112131415"), 0, 6);
            tHash.BlockUpdate(Hex.Decode("202122232425262728"), 0, 9);

            res = new byte[64];
            tHash.Output(res, 0, res.Length);

            IsTrue("oops!", !Arrays.AreEqual(Hex.Decode("45 00 0B E6 3F 9B 6B FD 89 F5 47 17 67 0F 69 A9 BC 76 35 91 A4 F0 5C 50 D6 88 91 A7 44 BC C6 E7 D6 D5 B5 E8 2C 01 8D A9 99 ED 35 B0 BB 49 C9 67 8E 52 6A BD 8E 85 C1 3E D2 54 02 1D B9 E7 90 CE"), res));
            IsTrue("oops!", Arrays.AreEqual(Hex.Decode("0c59b11464f2336c34663ed51b2b950bec743610856f36c28d1d088d8a2446284dd09830a6a178dc752376199fae935d86cfdee5913d4922dfd369b66a53c897"), res));

            SpanConsistencyTests();
        }

        [Test]
        public void TestFunction()
        {
            string resultText = Perform().ToString();

            Assert.AreEqual(Name + ": Okay", resultText);
        }

        internal void SpanConsistencyTests()
        {
            // NOTE: .NET Core 3.1 has Span<T>, but is tested against our .NET Standard 2.0 assembly.
//#if NETCOREAPP2_1_OR_GREATER || NETSTANDARD2_1_OR_GREATER
#if NET6_0_OR_GREATER || NETSTANDARD2_1_OR_GREATER
            IDigest digest1 = new TupleHash(128, new byte[0]);
            IDigest digest2 = new TupleHash(128, new byte[0]);

            // Span-based API consistency checks
            byte[] data = new byte[16 + 256];
            DigestTest.Random.NextBytes(data);

            for (int len = 0; len <= 256; ++len)
            {
                int off = DigestTest.Random.Next(0, 17);

                SpanConsistencyTest(digest1, digest2, data, off, len);
            }
#endif
        }

        internal void SpanConsistencyTest(IDigest digest1, IDigest digest2, byte[] buf, int off, int len)
        {
            // NOTE: .NET Core 3.1 has Span<T>, but is tested against our .NET Standard 2.0 assembly.
//#if NETCOREAPP2_1_OR_GREATER || NETSTANDARD2_1_OR_GREATER
#if NET6_0_OR_GREATER || NETSTANDARD2_1_OR_GREATER
            digest1.Reset();
            digest2.Reset();

            byte[] arrayResult1 = DigestUtilities.DoFinal(digest1, buf, off, len);
            byte[] spanResult1 = DigestUtilities.DoFinal(digest2, buf.AsSpan(off, len));

            if (!AreEqual(arrayResult1, spanResult1))
            {
                Fail("failing span consistency test 1", Hex.ToHexString(arrayResult1), Hex.ToHexString(spanResult1));
            }

            int pos = 0;
            while (pos < len)
            {
                int next = 1 + DigestTest.Random.Next(len - pos);
                digest1.BlockUpdate(buf, off + pos, next);
                digest2.BlockUpdate(buf.AsSpan(off + pos, next));
                pos += next;
            }

            byte[] arrayResult2 = new byte[digest1.GetDigestSize()];
            digest1.DoFinal(arrayResult2, 0);

            byte[] spanResult2 = new byte[digest2.GetDigestSize()];
            digest2.DoFinal(spanResult2.AsSpan());

            if (!AreEqual(arrayResult2, spanResult2))
            {
                Fail("failing span consistency test 2", Hex.ToHexString(arrayResult2), Hex.ToHexString(spanResult2));
            }
#endif
        }
    }
}
