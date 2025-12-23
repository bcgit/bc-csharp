using System;
using System.IO;
using System.Text;

using NUnit.Framework;

using Org.BouncyCastle.Crypto.Digests;
using Org.BouncyCastle.Math;
using Org.BouncyCastle.Utilities;
using Org.BouncyCastle.Utilities.Encoders;
using Org.BouncyCastle.Utilities.Test;

namespace Org.BouncyCastle.Crypto.Tests
{
    /**
     * SHAKE Digest Test
     */
    [TestFixture]
    public class ShakeDigestTest
        : SimpleTest
    {
        public override string Name => "SHAKE";

        public override void PerformTest()
        {
            TestVectors();

            DigestTest.SpanConsistencyTests(this, new ShakeDigest());
        }

        public void TestVectors()
        {
            using (StreamReader r = new StreamReader(GetTestDataAsStream("crypto.SHAKETestVectors.txt")))
            {
                string line;
                while (null != (line = ReadLine(r)))
                {
                    if (line.Length != 0)
                    {
                        TestVector v = ReadTestVector(r, line);
                        RunTestVector(v);
                    }
                }
            }
        }

        [Test]
        public void TestFunction()
        {
            string resultText = Perform().ToString();

            Assert.AreEqual(Name + ": Okay", resultText);
        }

        [Test, Explicit]
        public void BenchXof_Shake128()
        {
            ImplBenchXof(128);
        }

        [Test, Explicit]
        public void BenchXof_Shake256()
        {
            ImplBenchXof(256);
        }

        [Test]
        public void TestOutputXof_Shake128()
        {
            ImplTestOutputXof(128);
        }

        [Test]
        public void TestOutputXof_Shake256()
        {
            ImplTestOutputXof(256);
        }

        private TestVector ReadTestVector(StreamReader r, string header)
        {
            string[] parts = SplitAround(header, TestVector.SAMPLE_OF);

            string algorithm = parts[0];
            int bits = ParseDecimal(StripFromChar(parts[1], '-'));

            SkipUntil(r, TestVector.MSG_HEADER);
            string messageBlock = ReadBlock(r);
            if (messageBlock.Length != bits)
            {
                throw new InvalidOperationException("Test vector length mismatch");
            }
            byte[] message = DecodeBinary(messageBlock);

            SkipUntil(r, TestVector.OUTPUT_HEADER);
            byte[] output = Hex.Decode(ReadBlock(r));

            return new TestVector(algorithm, bits, message, output);
        }

        private void RunTestVector(TestVector v)
        {
            int bits = v.Bits;
            int partialBits = bits % 8;

            byte[] expected = v.Output;

            int outLen = expected.Length;

            MyShakeDigest d = CreateDigest(v.Algorithm);
            byte[] output = new byte[outLen];

            byte[] m = v.Message;
            if (partialBits == 0)
            {
                d.BlockUpdate(m, 0, m.Length);
                d.OutputFinal(output, 0, outLen);
            }
            else
            {
                d.BlockUpdate(m, 0, m.Length - 1);
                d.MyOutputFinal(output, 0, outLen, m[m.Length - 1], partialBits);
            }

            if (!Arrays.AreEqual(expected, output))
            {
                Fail(v.Algorithm + " " + v.Bits + "-bit test vector hash mismatch");
            }

            if (partialBits == 0)
            {
                d = CreateDigest(v.Algorithm);

                m = v.Message;

                d.BlockUpdate(m, 0, m.Length);
                d.Output(output, 0, outLen / 2);
                d.Output(output, outLen / 2, output.Length - outLen / 2);

                if (!Arrays.AreEqual(expected, output))
                {
                    Fail(v.Algorithm + " " + v.Bits + "-bit test vector extended hash mismatch");
                }

                try
                {
                    d.Update((byte)0x01);
                    Fail("no exception");
                }
                catch (InvalidOperationException e)
                {
                    if (!"attempt to absorb while squeezing".Equals(e.Message))
                    {
                        Fail("wrong exception");
                    }
                }

                d = CreateDigest(v.Algorithm);

                m = v.Message;

                d.BlockUpdate(m, 0, m.Length);
                d.Output(output, 0, outLen / 2);
                d.OutputFinal(output, outLen / 2, output.Length - outLen / 2);

                if (!Arrays.AreEqual(expected, output))
                {
                    Fail(v.Algorithm + " " + v.Bits + "-bit test vector extended doFinal hash mismatch");
                }

                d.Update((byte)0x01); // this should be okay as we've reset on DoFinal()
            }
        }

        private static MyShakeDigest CreateDigest(string algorithm)
        {
            if (algorithm.StartsWith("SHAKE-"))
            {
                int bits = ParseDecimal(algorithm.Substring("SHAKE-".Length));
                return new MyShakeDigest(bits);
            }
            throw new ArgumentException("Unknown algorithm: " + algorithm, "algorithm");
        }

        private static byte[] DecodeBinary(string block)
        {
            int bits = block.Length;
            int fullBytes = bits / 8;
            int totalBytes = (bits + 7) / 8;
            byte[] result = new byte[totalBytes];

            for (int i = 0; i < fullBytes; ++i)
            {
                string byteStr = Reverse(block.Substring(i * 8, 8));
                result[i] = (byte)ParseBinary(byteStr);
            }

            if (totalBytes > fullBytes)
            {
                string byteStr = Reverse(block.Substring(fullBytes * 8));
                result[fullBytes] = (byte)ParseBinary(byteStr);
            }

            return result;
        }

        private static void ImplBenchXof(int bitLength)
        {
            IXof xof = new ShakeDigest(bitLength);

            byte[] data = new byte[1024];
            for (int i = 0; i < 1024; ++i)
            {
                for (int j = 0; j < 1024; ++j)
                {
                    // NOTE: .NET Core 3.1 has Span<T>, but is tested against our .NET Standard 2.0 assembly.
                    //#if NETCOREAPP2_1_OR_GREATER || NETSTANDARD2_1_OR_GREATER
#if NET6_0_OR_GREATER || NETSTANDARD2_1_OR_GREATER
                    xof.BlockUpdate(data);
#else
                    xof.BlockUpdate(data, 0, 1024);
#endif
                }

                // NOTE: .NET Core 3.1 has Span<T>, but is tested against our .NET Standard 2.0 assembly.
                //#if NETCOREAPP2_1_OR_GREATER || NETSTANDARD2_1_OR_GREATER
#if NET6_0_OR_GREATER || NETSTANDARD2_1_OR_GREATER
                xof.OutputFinal(data);
#else
                xof.OutputFinal(data, 0, data.Length);
#endif
            }
        }

        private static void ImplTestOutputXof(int bitLength)
        {
            IXof xof = new ShakeDigest(bitLength);

            int rate = xof.GetByteLength();
            int maxStep = rate * 3;
            int totalOutput = maxStep * rate;
            int iterations = 64;

            Random random = new Random();

            byte[] expected = new byte[totalOutput];
            xof.OutputFinal(expected, 0, expected.Length);

            byte[] output = new byte[expected.Length];
            for (int i = 0; i < iterations; ++i)
            {
                random.NextBytes(output);

                int pos = 0;
                while (pos <= output.Length - maxStep)
                {
                    int len = random.Next(0, maxStep + 1);
                    xof.Output(output, pos, len);
                    pos += len;
                }

                xof.OutputFinal(output, pos, output.Length - pos);

                Assert.True(Arrays.AreEqual(expected, output));
            }
        }

        private static int ParseBinary(string s) => new BigInteger(s, 2).IntValue;

        private static int ParseDecimal(string s) => int.Parse(s);

        private static string ReadBlock(StreamReader r)
        {
            StringBuilder b = new StringBuilder();
            string line;
            while ((line = ReadBlockLine(r)) != null)
            {
                b.Append(line);
            }
            return b.ToString();
        }

        private static string ReadBlockLine(StreamReader r)
        {
            string line = ReadLine(r);
            if (line == null || line.Length == 0)
                return null;

            return line.Replace(" ", "");
        }

        private static string ReadLine(StreamReader r)
        {
            string line = r.ReadLine();
            return line == null ? null : StripFromChar(line, '#').Trim();
        }

        private static string RequireLine(StreamReader r) => ReadLine(r) ?? throw new EndOfStreamException();

        private static string Reverse(string s)
        {
            char[] cs = s.ToCharArray();
            Array.Reverse(cs);
            return new string(cs);
        }

        private static void SkipUntil(StreamReader r, string header)
        {
            string line;
            do
            {
                line = RequireLine(r);
            }
            while (line.Length == 0);

            if (!line.Equals(header))
                throw new IOException("Expected: " + header);
        }

        private static string[] SplitAround(string s, string separator)
        {
            int i = s.IndexOf(separator);
            if (i < 0)
                throw new InvalidOperationException();
            return new string[] { s.Substring(0, i), s.Substring(i + separator.Length) };
        }

        private static string StripFromChar(string s, char c)
        {
            int i = s.IndexOf(c);
            if (i >= 0)
            {
                s = s.Substring(0, i);
            }
            return s;
        }

        internal class MyShakeDigest : ShakeDigest
        {
            internal MyShakeDigest(int bitLength)
                : base(bitLength)
            {
            }

            internal int MyOutputFinal(byte[] output, int outOff, int outLen, byte partialByte, int partialBits) =>
                OutputFinal(output, outOff, outLen, partialByte, partialBits);
        }

        internal class TestVector
        {
            internal static string SAMPLE_OF = " sample of ";
            internal static string MSG_HEADER = "Msg as bit string";
            internal static string OUTPUT_HEADER = "Output val is";

            private readonly string algorithm;
            private readonly int bits;
            private readonly byte[] message;
            private readonly byte[] output;

            internal TestVector(string algorithm, int bits, byte[] message, byte[] output)
            {
                this.algorithm = algorithm;
                this.bits = bits;
                this.message = message;
                this.output = output;
            }

            public string Algorithm => algorithm;

            public int Bits => bits;

            public byte[] Message => message;

            public byte[] Output => output;
        }
    }
}
