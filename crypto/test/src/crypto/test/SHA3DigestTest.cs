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
     * SHA3 Digest Test
     */
    [TestFixture]
    public class Sha3DigestTest
        : SimpleTest
    {
        public override string Name => "SHA-3";

        public override void PerformTest()
        {
            TestVectors();

            DigestTest.SpanConsistencyTests(this, new Sha3Digest());
        }

        public void TestVectors()
        {
            using (StreamReader r = new StreamReader(GetTestDataAsStream("crypto.SHA3TestVectors.txt")))
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
        public void BenchDigest_Sha3_224()
        {
            ImplBenchDigest(224);
        }

        [Test, Explicit]
        public void BenchDigest_Sha3_256()
        {
            ImplBenchDigest(256);
        }

        [Test, Explicit]
        public void BenchDigest_Sha3_384()
        {
            ImplBenchDigest(384);
        }

        [Test, Explicit]
        public void BenchDigest_Sha3_512()
        {
            ImplBenchDigest(512);
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

            SkipUntil(r, TestVector.HASH_HEADER);
            byte[] hash = Hex.Decode(ReadBlock(r));

            return new TestVector(algorithm, bits, message, hash);
        }

        private void RunTestVector(TestVector v)
        {
            int bits = v.Bits;
            int partialBits = bits % 8;

            MySha3Digest d = CreateDigest(v.Algorithm);
            byte[] output = new byte[d.GetDigestSize()];

            byte[] m = v.Message;
            if (partialBits == 0)
            {
                d.BlockUpdate(m, 0, m.Length);
                d.DoFinal(output, 0);
            }
            else
            {
                d.BlockUpdate(m, 0, m.Length - 1);
                d.MyDoFinal(output, 0, m[m.Length - 1], partialBits);
            }

            if (!Arrays.AreEqual(v.Hash, output))
            {
                Fail(v.Algorithm + " " + v.Bits + "-bit test vector hash mismatch");
            }
        }

        private static MySha3Digest CreateDigest(string algorithm)
        {
            if (algorithm.StartsWith("SHA3-"))
            {
                int bits = ParseDecimal(algorithm.Substring("SHA3-".Length));
                return new MySha3Digest(bits);
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

        private static void ImplBenchDigest(int bitLength)
        {
            IDigest digest = new Sha3Digest(bitLength);

            byte[] data = new byte[1024];
            for (int i = 0; i < 1024; ++i)
            {
                for (int j = 0; j < 1024; ++j)
                {
                    // NOTE: .NET Core 3.1 has Span<T>, but is tested against our .NET Standard 2.0 assembly.
                    //#if NETCOREAPP2_1_OR_GREATER || NETSTANDARD2_1_OR_GREATER
#if NET6_0_OR_GREATER || NETSTANDARD2_1_OR_GREATER
                    digest.BlockUpdate(data);
#else
                    digest.BlockUpdate(data, 0, 1024);
#endif
                }

                // NOTE: .NET Core 3.1 has Span<T>, but is tested against our .NET Standard 2.0 assembly.
                //#if NETCOREAPP2_1_OR_GREATER || NETSTANDARD2_1_OR_GREATER
#if NET6_0_OR_GREATER || NETSTANDARD2_1_OR_GREATER
                digest.DoFinal(data);
#else
                digest.DoFinal(data, 0);
#endif
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

        internal class MySha3Digest : Sha3Digest
        {
            internal MySha3Digest(int bitLength)
                : base(bitLength)
            {
            }

            internal int MyDoFinal(byte[] output, int outOff, byte partialByte, int partialBits) =>
                DoFinal(output, outOff, partialByte, partialBits);
        }

        internal class TestVector
        {
            internal static string SAMPLE_OF = " sample of ";
            internal static string MSG_HEADER = "Msg as bit string";
            internal static string HASH_HEADER = "Hash val is";

            private readonly string algorithm;
            private readonly int bits;
            private readonly byte[] message;
            private readonly byte[] hash;

            internal TestVector(string algorithm, int bits, byte[] message, byte[] hash)
            {
                this.algorithm = algorithm;
                this.bits = bits;
                this.message = message;
                this.hash = hash;
            }

            public string Algorithm => algorithm;

            public int Bits => bits;

            public byte[] Message => message;

            public byte[] Hash => hash;
        }
    }
}
