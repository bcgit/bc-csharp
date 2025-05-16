using System;

using Org.BouncyCastle.Security;
using Org.BouncyCastle.Utilities;
using Org.BouncyCastle.Utilities.Encoders;
using Org.BouncyCastle.Utilities.Test;

namespace Org.BouncyCastle.Crypto.Tests
{
    public abstract class DigestTest
        : SimpleTest
    {
        internal static readonly SecureRandom Random = new SecureRandom();

        private readonly IDigest digest;
        private readonly string[] input;
        private readonly string[] results;

        protected DigestTest(IDigest digest, string[] input, string[] results)
        {
            this.digest = digest;
            this.input = input;
            this.results = results;
        }

        public override string Name => digest.AlgorithmName;

        public override void PerformTest()
        {
            byte[] resBuf = new byte[digest.GetDigestSize()];

            for (int i = 0; i < input.Length - 1; i++)
            {
                byte[] msg = ToByteArray(input[i]);

                VectorTest(digest, i, resBuf, msg, Hex.Decode(results[i]));
            }

            byte[] lastV = ToByteArray(input[input.Length - 1]);
            byte[] lastDigest = Hex.Decode(results[input.Length - 1]);

            VectorTest(digest, input.Length - 1, resBuf, lastV, Hex.Decode(results[input.Length - 1]));

            //
            // clone test
            //
            digest.BlockUpdate(lastV, 0, lastV.Length / 2);

            // clone the Digest
            IDigest d = CloneDigest(digest);

            digest.BlockUpdate(lastV, lastV.Length / 2, lastV.Length - lastV.Length / 2);
            digest.DoFinal(resBuf, 0);

            if (!AreEqual(lastDigest, resBuf))
            {
                Fail("failing clone vector test", results[results.Length - 1], Hex.ToHexString(resBuf));
            }

            d.BlockUpdate(lastV, lastV.Length / 2, lastV.Length - lastV.Length / 2);
            d.DoFinal(resBuf, 0);

            if (!AreEqual(lastDigest, resBuf))
            {
                Fail("failing second clone vector test", results[results.Length - 1], Hex.ToHexString(resBuf));
            }

            //
            // memo test
            //
            IMemoable m = (IMemoable)digest;

            digest.BlockUpdate(lastV, 0, lastV.Length / 2);

            // copy the Digest
            IMemoable copy1 = m.Copy();
            IMemoable copy2 = copy1.Copy();

            digest.BlockUpdate(lastV, lastV.Length / 2, lastV.Length - lastV.Length / 2);
            digest.DoFinal(resBuf, 0);

            if (!AreEqual(lastDigest, resBuf))
            {
                Fail("failing memo vector test", results[results.Length - 1], Hex.ToHexString(resBuf));
            }

            m.Reset(copy1);

            digest.BlockUpdate(lastV, lastV.Length / 2, lastV.Length - lastV.Length / 2);
            digest.DoFinal(resBuf, 0);

            if (!AreEqual(lastDigest, resBuf))
            {
                Fail("failing memo reset vector test", results[results.Length - 1], Hex.ToHexString(resBuf));
            }

            IDigest md = (IDigest)copy2;

            md.BlockUpdate(lastV, lastV.Length / 2, lastV.Length - lastV.Length / 2);
            md.DoFinal(resBuf, 0);

            if (!AreEqual(lastDigest, resBuf))
            {
                Fail("failing memo copy vector test", results[results.Length - 1], Hex.ToHexString(resBuf));
            }

            SpanConsistencyTests(this, digest);
        }

        private static byte[] ToByteArray(string input)
        {
            byte[] bytes = new byte[input.Length];

            for (int i = 0; i != bytes.Length; i++)
            {
                bytes[i] = (byte)input[i];
            }

            return bytes;
        }

        private void VectorTest(IDigest digest, int count, byte[] resBuf, byte[] input, byte[] expected)
        {
            digest.BlockUpdate(input, 0, input.Length);
            digest.DoFinal(resBuf, 0);

            if (!AreEqual(resBuf, expected))
            {
                Fail("Vector " + count + " failed got " + Hex.ToHexString(resBuf));
            }
        }

        protected abstract IDigest CloneDigest(IDigest digest);

        //
        // optional tests
        //
        protected void MillionATest(string expected)
        {
            byte[] resBuf = new byte[digest.GetDigestSize()];

            for (int i = 0; i < 1000000; i++)
            {
                digest.Update((byte)'a');
            }

            digest.DoFinal(resBuf, 0);

            if (!AreEqual(resBuf, Hex.Decode(expected)))
            {
                Fail("Million a's failed");
            }
        }

        protected void SixtyFourKTest(string expected)
        {
            byte[] resBuf = new byte[digest.GetDigestSize()];

            for (int i = 0; i < 65536; i++)
            {
                digest.Update((byte)i);
            }

            digest.DoFinal(resBuf, 0);

            if (!AreEqual(resBuf, Hex.Decode(expected)))
            {
                Fail("64k test failed");
            }
        }

        internal static void SpanConsistencyTests(SimpleTest test, IDigest digest)
        {
            // NOTE: .NET Core 3.1 has Span<T>, but is tested against our .NET Standard 2.0 assembly.
//#if NETCOREAPP2_1_OR_GREATER || NETSTANDARD2_1_OR_GREATER
#if NET6_0_OR_GREATER || NETSTANDARD2_1_OR_GREATER

            // Span-based API consistency checks
            byte[] data = new byte[16 + 256];
            Random.NextBytes(data);

            for (int len = 0; len <= 256; ++len)
            {
                int off = Random.Next(0, 17);

                SpanConsistencyTest(test, digest, data, off, len);
            }
#endif
        }

        internal static void SpanConsistencyTest(SimpleTest test, IDigest digest, byte[] buf, int off, int len)
        {
            // NOTE: .NET Core 3.1 has Span<T>, but is tested against our .NET Standard 2.0 assembly.
//#if NETCOREAPP2_1_OR_GREATER || NETSTANDARD2_1_OR_GREATER
#if NET6_0_OR_GREATER || NETSTANDARD2_1_OR_GREATER
            digest.Reset();

            byte[] arrayResult = DigestUtilities.DoFinal(digest, buf, off, len);
            byte[] spanResult1 = DigestUtilities.DoFinal(digest, buf.AsSpan(off, len));

            if (!Arrays.AreEqual(arrayResult, spanResult1))
            {
                test.Fail("failing span consistency test 1", Hex.ToHexString(arrayResult), Hex.ToHexString(spanResult1));
            }

            int pos = 0;
            while (pos < len)
            {
                int next = 1 + Random.Next(len - pos);
                digest.BlockUpdate(buf.AsSpan(off + pos, next));
                pos += next;
            }

            byte[] spanResult2 = new byte[digest.GetDigestSize()];
            digest.DoFinal(spanResult2.AsSpan());

            if (!Arrays.AreEqual(arrayResult, spanResult2))
            {
                test.Fail("failing span consistency test 2", Hex.ToHexString(arrayResult), Hex.ToHexString(spanResult2));
            }
#endif
        }

        internal static bool TestDigestReset(IDigest digest)
        {
            int DATALEN = 100;
            /* Obtain some random data */
            byte[] myData = new byte[DATALEN];
            SecureRandom myRandom = new SecureRandom();
            myRandom.NextBytes(myData);

            /* Update and finalise digest */
            int myHashLen = digest.GetDigestSize();
            byte[] myFirst = new byte[myHashLen];
            digest.BlockUpdate(myData, 0, DATALEN);
            digest.DoFinal(myFirst, 0);

            /* Reuse the digest */
            byte[] mySecond = new byte[myHashLen];
            digest.BlockUpdate(myData, 0, DATALEN);
            digest.DoFinal(mySecond, 0);

            /* Check that we have the same result */
            return Arrays.AreEqual(myFirst, mySecond);
        }
    }
}
