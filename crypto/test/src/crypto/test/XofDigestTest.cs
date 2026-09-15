using System;

using NUnit.Framework;

using Org.BouncyCastle.Crypto.Digests;
using Org.BouncyCastle.Utilities;

namespace Org.BouncyCastle.Crypto.Tests
{
    [TestFixture]
    public class XofDigestTest
    {
        private static byte[] CreateInput(int length)
        {
            byte[] input = new byte[length];
            for (int i = 0; i < length; ++i)
            {
                input[i] = (byte)i;
            }
            return input;
        }

        private static byte[] Squeeze(IXof xof, byte[] input, int outputSize)
        {
            xof.BlockUpdate(input, 0, input.Length);

            byte[] output = new byte[outputSize];
            xof.OutputFinal(output, 0, outputSize);
            return output;
        }

        [Test]
        [TestCase(1)]
        [TestCase(16)]
        [TestCase(24)]
        [TestCase(32)]
        [TestCase(64)]
        [TestCase(200)]
        public void OutputMatchesXofPrefix(int outputSize)
        {
            byte[] input = CreateInput(300);

            // The squeezed output stream is a prefix of any longer one, so a fixed-size digest of it must match
            // the start of a single long squeeze. 200 bytes is past the SHAKE256 rate, and past the 64 bytes
            // that GetDigestSize reports, which a truncating wrapper could not have reached.
            byte[] expected = Squeeze(new ShakeDigest(256), input, 256);

            IDigest digest = new XofDigest(new ShakeDigest(256), outputSize);
            digest.BlockUpdate(input, 0, input.Length);

            byte[] output = new byte[outputSize];
            Assert.That(digest.DoFinal(output, 0), Is.EqualTo(outputSize));
            Assert.That(output, Is.EqualTo(Arrays.CopyOf(expected, outputSize)));
        }

        /**
         * The reason the class exists: IXof extends IDigest, whose GetDigestSize is the XOF's own default - 64
         * bytes for SHAKE256, twice what SP 800-208 wants for the n=32 LMS parameter sets. Squeezing the shorter
         * length must give what truncating the default would have given.
         */
        [Test]
        [TestCase(24)]
        [TestCase(32)]
        public void OutputMatchesTruncatedDefault(int outputSize)
        {
            byte[] input = CreateInput(64);

            IDigest shake = new ShakeDigest(256);
            shake.BlockUpdate(input, 0, input.Length);
            byte[] fullSize = new byte[shake.GetDigestSize()];
            shake.DoFinal(fullSize, 0);

            IDigest digest = new XofDigest(new ShakeDigest(256), outputSize);
            digest.BlockUpdate(input, 0, input.Length);
            byte[] output = new byte[outputSize];
            digest.DoFinal(output, 0);

            Assert.That(shake.GetDigestSize(), Is.EqualTo(64));
            Assert.That(output, Is.EqualTo(Arrays.CopyOf(fullSize, outputSize)));
        }

        [Test]
        public void ReportsOutputSizeAndName()
        {
            IDigest digest = new XofDigest(new ShakeDigest(256), 24);

            Assert.That(digest.AlgorithmName, Is.EqualTo("SHAKE256@192"));
            Assert.That(digest.GetDigestSize(), Is.EqualTo(24));
            Assert.That(digest.GetByteLength(), Is.EqualTo(new ShakeDigest(256).GetByteLength()));
        }

        [Test]
        public void ResetAfterDoFinal()
        {
            byte[] input = CreateInput(64);

            IDigest digest = new XofDigest(new ShakeDigest(128), 20);

            byte[] first = new byte[20];
            digest.BlockUpdate(input, 0, input.Length);
            digest.DoFinal(first, 0);

            // DoFinal leaves the digest reset, and an explicit Reset mid-message discards what was absorbed.
            byte[] second = new byte[20];
            digest.BlockUpdate(input, 0, 1);
            digest.Reset();
            digest.BlockUpdate(input, 0, input.Length);
            digest.DoFinal(second, 0);

            Assert.That(second, Is.EqualTo(first));
        }

        [Test]
        public void UpdateByByte()
        {
            byte[] input = CreateInput(37);

            IDigest byBlock = new XofDigest(new ShakeDigest(256), 32);
            byBlock.BlockUpdate(input, 0, input.Length);
            byte[] expected = new byte[32];
            byBlock.DoFinal(expected, 0);

            IDigest byByte = new XofDigest(new ShakeDigest(256), 32);
            for (int i = 0; i < input.Length; ++i)
            {
                byByte.Update(input[i]);
            }
            byte[] output = new byte[32];
            byByte.DoFinal(output, 0);

            Assert.That(output, Is.EqualTo(expected));
        }

        [Test]
        public void ConstructorValidates()
        {
            Assert.Throws<ArgumentNullException>(() => new XofDigest(null, 32));
            Assert.Throws<ArgumentOutOfRangeException>(() => new XofDigest(new ShakeDigest(256), 0));
            Assert.Throws<ArgumentOutOfRangeException>(() => new XofDigest(new ShakeDigest(256), -1));
        }

// NOTE: .NET Core 3.1 has Span<T>, but is tested against our .NET Standard 2.0 assembly.
//#if NETCOREAPP2_1_OR_GREATER || NETSTANDARD2_1_OR_GREATER
#if NET6_0_OR_GREATER || NETSTANDARD2_1_OR_GREATER
        [Test]
        public void SpanAgreesWithArray()
        {
            byte[] input = CreateInput(200);

            IDigest byArray = new XofDigest(new ShakeDigest(256), 48);
            byArray.BlockUpdate(input, 0, input.Length);
            byte[] expected = new byte[48];
            byArray.DoFinal(expected, 0);

            IDigest bySpan = new XofDigest(new ShakeDigest(256), 48);
            bySpan.BlockUpdate(input.AsSpan());
            byte[] output = new byte[48];
            Assert.That(bySpan.DoFinal(output.AsSpan()), Is.EqualTo(48));

            Assert.That(output, Is.EqualTo(expected));
        }

        [Test]
        public void SpanTooShortRejected()
        {
            IDigest digest = new XofDigest(new ShakeDigest(256), 32);

            Assert.Throws<OutputLengthException>(() => digest.DoFinal(new byte[31].AsSpan()));
        }
#endif
    }
}
