using System;

using NUnit.Framework;

using Org.BouncyCastle.Crypto.Engines;
using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.Security;
using Org.BouncyCastle.Utilities;
using Org.BouncyCastle.Utilities.Encoders;

namespace Org.BouncyCastle.Crypto.Tests
{
    /// <summary>Tests for <see cref="XChaCha20Engine"/> independent of the AEAD wrapper.</summary>
    [TestFixture]
    public class XChaCha20Test
    {
        // draft-irtf-cfrg-xchacha-03 Section 2.2.1: HChaCha20 test vector.
        private const string HChaChaKeyHex   = "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f";
        private const string HChaChaNonceHex = "000000090000004a0000000031415927";
        private const string HChaChaOutHex   = "82413b4227b27bfed30e42508a877d73a0f9e4d58a74a853c12ec41326d3ecdc";

        // draft-irtf-cfrg-xchacha-03 Appendix A.3 AEAD_XChaCha20_Poly1305 test vector.
        // The AEAD ciphertext is exactly XChaCha20(K, N24) keystream at block-counter 1+, XORed
        // with the plaintext (block 0 of the keystream is reserved for the Poly1305 key). So a
        // standalone XChaCha20 stream test can be derived directly from these bytes.
        private const string TVKeyHex   = "808182838485868788898a8b8c8d8e8f909192939495969798999a9b9c9d9e9f";
        private const string TVNonceHex = "404142434445464748494a4b4c4d4e4f5051525354555657";
        private const string TVPlainHex =
              "4c616469657320616e642047656e746c"
            + "656d656e206f662074686520636c6173"
            + "73206f66202739393a20496620492063"
            + "6f756c64206f6666657220796f75206f"
            + "6e6c79206f6e652074697020666f7220"
            + "746865206675747572652c2073756e73"
            + "637265656e20776f756c642062652069"
            + "742e";
        private const string TVCipherHex =
              "bd6d179d3e83d43b9576579493c0e939"
            + "572a1700252bfaccbed2902c21396cbb"
            + "731c7f1b0b4aa6440bf3a82f4eda7e39"
            + "ae64c6708c54c216cb96b72e1213b452"
            + "2f8c9ba40db5d945b11b69b982c1bb9e"
            + "3f3fac2bc369488f76b2383565d3fff9"
            + "21f9664c97637da9768812f615c68b13"
            + "b52e";

        /// <summary>
        /// HChaCha20 has no public surface, so test it indirectly: an XChaCha20 keystream over a
        /// nonce N24 = HChaCha20Nonce || (8 zero bytes) must match a plain ChaCha7539 keystream
        /// keyed by the HChaCha20 output under an all-zero 96-bit nonce. This passes iff the
        /// subkey derivation inside XChaCha20Engine produced the draft-specified HChaCha20 output.
        /// </summary>
        [Test]
        public void HChaCha20Vector()
        {
            byte[] key = Hex.Decode(HChaChaKeyHex);
            byte[] hNonce = Hex.Decode(HChaChaNonceHex);
            byte[] subKey = Hex.Decode(HChaChaOutHex);

            byte[] xNonce = new byte[24];
            Array.Copy(hNonce, 0, xNonce, 0, 16);

            byte[] zeros = new byte[256];

            byte[] streamFromXChaCha = new byte[zeros.Length];
            XChaCha20Engine xEngine = new XChaCha20Engine();
            xEngine.Init(true, new ParametersWithIV(new KeyParameter(key), xNonce));
            xEngine.ProcessBytes(zeros, 0, zeros.Length, streamFromXChaCha, 0);

            byte[] streamFromChaCha = new byte[zeros.Length];
            ChaCha7539Engine cEngine = new ChaCha7539Engine();
            cEngine.Init(true, new ParametersWithIV(new KeyParameter(subKey), new byte[12]));
            cEngine.ProcessBytes(zeros, 0, zeros.Length, streamFromChaCha, 0);

            Assert.IsTrue(Arrays.AreEqual(streamFromXChaCha, streamFromChaCha),
                "HChaCha20 subkey derivation does not match draft test vector");
        }

        /// <summary>
        /// Verify XChaCha20 against the IETF draft. The AEAD draft vector pins the keystream at
        /// block-counter 1 onward; prepending 64 zero bytes (block 0) to the plaintext and
        /// encrypting with the standalone engine must reproduce the AEAD ciphertext in bytes
        /// 64..(64 + |plaintext|).
        /// </summary>
        [Test]
        public void DraftStreamVector()
        {
            byte[] key = Hex.Decode(TVKeyHex);
            byte[] nonce = Hex.Decode(TVNonceHex);
            byte[] plain = Hex.Decode(TVPlainHex);
            byte[] expectedCipher = Hex.Decode(TVCipherHex);

            byte[] input = new byte[64 + plain.Length];
            Array.Copy(plain, 0, input, 64, plain.Length);

            byte[] output = new byte[input.Length];

            XChaCha20Engine engine = new XChaCha20Engine();
            engine.Init(true, new ParametersWithIV(new KeyParameter(key), nonce));
            engine.ProcessBytes(input, 0, input.Length, output, 0);

            byte[] actualCipher = new byte[expectedCipher.Length];
            Array.Copy(output, 64, actualCipher, 0, expectedCipher.Length);

            Assert.AreEqual(Hex.ToHexString(expectedCipher), Hex.ToHexString(actualCipher),
                "XChaCha20 keystream does not match draft AEAD vector");

            // Decryption: feeding the ciphertext back through must reproduce the input bit-for-bit
            // (XChaCha20 is a stream cipher; encrypt and decrypt are identical).
            byte[] roundTrip = new byte[output.Length];
            XChaCha20Engine decEngine = new XChaCha20Engine();
            decEngine.Init(false, new ParametersWithIV(new KeyParameter(key), nonce));
            decEngine.ProcessBytes(output, 0, output.Length, roundTrip, 0);

            Assert.IsTrue(Arrays.AreEqual(input, roundTrip), "XChaCha20 round-trip mismatch");
        }

        [Test]
        public void RandomRoundTrip()
        {
            SecureRandom random = new SecureRandom();

            for (int i = 0; i < 50; ++i)
            {
                byte[] key = new byte[32];
                random.NextBytes(key);

                byte[] nonce = new byte[24];
                random.NextBytes(nonce);

                int len = random.Next(8192);
                byte[] plain = new byte[len];
                random.NextBytes(plain);

                byte[] cipher = new byte[len];
                XChaCha20Engine enc = new XChaCha20Engine();
                enc.Init(true, new ParametersWithIV(new KeyParameter(key), nonce));
                enc.ProcessBytes(plain, 0, len, cipher, 0);

                byte[] back = new byte[len];
                XChaCha20Engine dec = new XChaCha20Engine();
                dec.Init(false, new ParametersWithIV(new KeyParameter(key), nonce));
                dec.ProcessBytes(cipher, 0, len, back, 0);

                Assert.IsTrue(Arrays.AreEqual(plain, back),
                    "XChaCha20 randomized round-trip failed at length " + len);
            }
        }

        /// <summary>
        /// Splitting the input into chunks of varying sizes must produce the same keystream as a
        /// single contiguous call.
        /// </summary>
        [Test]
        public void ChunkedProcessing()
        {
            byte[] key = Hex.Decode(TVKeyHex);
            byte[] nonce = Hex.Decode(TVNonceHex);

            byte[] plain = new byte[1024];
            SecureRandom random = new SecureRandom();
            random.NextBytes(plain);

            byte[] whole = new byte[plain.Length];
            XChaCha20Engine engine = new XChaCha20Engine();
            engine.Init(true, new ParametersWithIV(new KeyParameter(key), nonce));
            engine.ProcessBytes(plain, 0, plain.Length, whole, 0);

            int[] splits = new int[] { 1, 7, 32, 63, 64, 65, 127, 128, 129 };
            foreach (int chunk in splits)
            {
                byte[] piecewise = new byte[plain.Length];
                XChaCha20Engine e = new XChaCha20Engine();
                e.Init(true, new ParametersWithIV(new KeyParameter(key), nonce));

                int off = 0;
                while (off < plain.Length)
                {
                    int n = System.Math.Min(chunk, plain.Length - off);
                    e.ProcessBytes(plain, off, n, piecewise, off);
                    off += n;
                }

                Assert.IsTrue(Arrays.AreEqual(whole, piecewise),
                    "chunked processing differs from bulk at chunk size " + chunk);
            }
        }

        [Test]
        public void RejectShortNonce()
        {
            Assert.Throws<ArgumentException>(() =>
                new XChaCha20Engine().Init(true,
                    new ParametersWithIV(new KeyParameter(new byte[32]), new byte[12])));

            Assert.Throws<ArgumentException>(() =>
                new XChaCha20Engine().Init(true,
                    new ParametersWithIV(new KeyParameter(new byte[32]), new byte[23])));
        }

        [Test]
        public void RejectInvalidKeySize()
        {
            Assert.Throws<ArgumentException>(() =>
                new XChaCha20Engine().Init(true,
                    new ParametersWithIV(new KeyParameter(new byte[16]), new byte[24])));
        }
    }
}
