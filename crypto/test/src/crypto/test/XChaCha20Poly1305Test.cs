using System;

using NUnit.Framework;

using Org.BouncyCastle.Asn1;
using Org.BouncyCastle.Crypto.Modes;
using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.Security;
using Org.BouncyCastle.Utilities;
using Org.BouncyCastle.Utilities.Encoders;

namespace Org.BouncyCastle.Crypto.Tests
{
    [TestFixture]
    public class XChaCha20Poly1305Test
    {
        // draft-irtf-cfrg-xchacha-03, Appendix A.3: AEAD_XChaCha20_Poly1305 test vector.
        private const string TVKeyHex   = "808182838485868788898a8b8c8d8e8f909192939495969798999a9b9c9d9e9f";
        private const string TVNonceHex = "404142434445464748494a4b4c4d4e4f5051525354555657";
        private const string TVAadHex   = "50515253c0c1c2c3c4c5c6c7";
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
        private const string TVTagHex   = "c0875924c1c7987947deafd8780acf49";

        [Test]
        public void DraftVector()
        {
            byte[] key = Hex.Decode(TVKeyHex);
            byte[] nonce = Hex.Decode(TVNonceHex);
            byte[] aad = Hex.Decode(TVAadHex);
            byte[] plain = Hex.Decode(TVPlainHex);
            byte[] expectedCipher = Hex.Decode(TVCipherHex);
            byte[] expectedTag = Hex.Decode(TVTagHex);

            // Encrypt
            XChaCha20Poly1305 enc = new XChaCha20Poly1305();
            enc.Init(true, new AeadParameters(new KeyParameter(key), 128, nonce, aad));

            byte[] outBytes = new byte[enc.GetOutputSize(plain.Length)];
            int len = enc.ProcessBytes(plain, 0, plain.Length, outBytes, 0);
            len += enc.DoFinal(outBytes, len);

            Assert.AreEqual(expectedCipher.Length + expectedTag.Length, len,
                "XChaCha20-Poly1305 encryption produced unexpected output length");

            byte[] actualCipher = new byte[expectedCipher.Length];
            Array.Copy(outBytes, 0, actualCipher, 0, expectedCipher.Length);
            byte[] actualTag = new byte[expectedTag.Length];
            Array.Copy(outBytes, expectedCipher.Length, actualTag, 0, expectedTag.Length);

            Assert.AreEqual(Hex.ToHexString(expectedCipher), Hex.ToHexString(actualCipher),
                "XChaCha20-Poly1305 ciphertext mismatch");
            Assert.AreEqual(Hex.ToHexString(expectedTag), Hex.ToHexString(actualTag),
                "XChaCha20-Poly1305 tag mismatch");
            Assert.IsTrue(Arrays.AreEqual(expectedTag, enc.GetMac()),
                "XChaCha20-Poly1305 GetMac mismatch");

            // Decrypt
            XChaCha20Poly1305 dec = new XChaCha20Poly1305();
            dec.Init(false, new AeadParameters(new KeyParameter(key), 128, nonce, aad));

            byte[] decBytes = new byte[dec.GetOutputSize(outBytes.Length)];
            int decLen = dec.ProcessBytes(outBytes, 0, outBytes.Length, decBytes, 0);
            decLen += dec.DoFinal(decBytes, decLen);

            Assert.AreEqual(plain.Length, decLen,
                "XChaCha20-Poly1305 decryption produced unexpected length");
            Assert.IsTrue(Arrays.AreEqual(plain, decBytes), "XChaCha20-Poly1305 decryption mismatch");
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

                int pLen = random.Next(4096);
                byte[] plain = new byte[pLen];
                random.NextBytes(plain);

                int aLen = random.Next(256);
                byte[] aad = new byte[aLen];
                random.NextBytes(aad);

                AeadParameters parms = new AeadParameters(new KeyParameter(key), 128, nonce, aad);

                XChaCha20Poly1305 enc = new XChaCha20Poly1305();
                enc.Init(true, parms);
                byte[] ct = new byte[enc.GetOutputSize(pLen)];
                int el = enc.ProcessBytes(plain, 0, pLen, ct, 0);
                el += enc.DoFinal(ct, el);
                Assert.AreEqual(ct.Length, el, "round-trip: encryption length mismatch");

                XChaCha20Poly1305 dec = new XChaCha20Poly1305();
                dec.Init(false, parms);
                byte[] pt = new byte[dec.GetOutputSize(ct.Length)];
                int dl = dec.ProcessBytes(ct, 0, ct.Length, pt, 0);
                dl += dec.DoFinal(pt, dl);
                Assert.AreEqual(pLen, dl, "round-trip: decryption length mismatch");
                Assert.IsTrue(Arrays.AreEqual(plain, pt), "round-trip: plaintext mismatch");

                // Tamper-detect: flip a bit in the ciphertext/tag and expect failure.
                if (ct.Length > 0)
                {
                    ct[random.Next(ct.Length)] ^= 0x01;
                    XChaCha20Poly1305 bad = new XChaCha20Poly1305();
                    bad.Init(false, parms);
                    byte[] junk = new byte[bad.GetOutputSize(ct.Length)];
                    Assert.Throws<InvalidCipherTextException>(() =>
                    {
                        int bl = bad.ProcessBytes(ct, 0, ct.Length, junk, 0);
                        bad.DoFinal(junk, bl);
                    }, "round-trip: tampered ciphertext was accepted");
                }
            }
        }

        [Test]
        public void RejectShortNonce()
        {
            Assert.Throws<ArgumentException>(() =>
                new XChaCha20Poly1305().Init(true,
                    new AeadParameters(new KeyParameter(new byte[32]), 128, new byte[12])));
        }

        [Test]
        public void RejectInvalidKeySize()
        {
            Assert.Throws<ArgumentException>(() =>
                new XChaCha20Poly1305().Init(true,
                    new AeadParameters(new KeyParameter(new byte[16]), 128, new byte[24])));
        }

        [Test]
        public void KeyGeneratorReturns256BitKey()
        {
            CipherKeyGenerator kg1 = GeneratorUtilities.GetKeyGenerator("XCHACHA20");
            Assert.AreEqual(256, kg1.DefaultStrength,
                "GeneratorUtilities default key size for XCHACHA20 is wrong");

            CipherKeyGenerator kg2 = GeneratorUtilities.GetKeyGenerator("XCHACHA20-POLY1305");
            Assert.AreEqual(256, kg2.DefaultStrength,
                "GeneratorUtilities default key size for XCHACHA20-POLY1305 is wrong");
        }

        [Test]
        public void ParameterUtilitiesGenerates24ByteIV()
        {
            Asn1OctetString ivParams = (Asn1OctetString)
                ParameterUtilities.GenerateParameters("XCHACHA20", new SecureRandom());
            Assert.AreEqual(24, ivParams.GetOctets().Length,
                "ParameterUtilities generated wrong IV length for XCHACHA20");
        }

        [Test]
        public void CipherUtilitiesProvidesRawStreamCipher()
        {
            byte[] key = Hex.Decode(TVKeyHex);
            byte[] nonce = Hex.Decode(TVNonceHex);
            byte[] plain = Hex.Decode(TVPlainHex);

            IBufferedCipher rawEnc = CipherUtilities.GetCipher("XCHACHA20");
            rawEnc.Init(true, new ParametersWithIV(new KeyParameter(key), nonce));
            byte[] streamCt = rawEnc.DoFinal(plain);

            IBufferedCipher rawDec = CipherUtilities.GetCipher("XCHACHA20");
            rawDec.Init(false, new ParametersWithIV(new KeyParameter(key), nonce));
            byte[] streamPt = rawDec.DoFinal(streamCt);

            Assert.IsTrue(Arrays.AreEqual(plain, streamPt),
                "CipherUtilities XCHACHA20 round-trip failed");
        }

        [Test]
        public void CipherUtilitiesProvidesAeadCipher()
        {
            byte[] key = Hex.Decode(TVKeyHex);
            byte[] nonce = Hex.Decode(TVNonceHex);
            byte[] aad = Hex.Decode(TVAadHex);
            byte[] plain = Hex.Decode(TVPlainHex);
            byte[] expectedCipher = Hex.Decode(TVCipherHex);
            byte[] expectedTag = Hex.Decode(TVTagHex);

            IBufferedCipher aeadEnc = CipherUtilities.GetCipher("XCHACHA20-POLY1305");
            aeadEnc.Init(true, new AeadParameters(new KeyParameter(key), 128, nonce, aad));
            byte[] aeadCt = aeadEnc.DoFinal(plain);

            byte[] expected = new byte[expectedCipher.Length + expectedTag.Length];
            Array.Copy(expectedCipher, 0, expected, 0, expectedCipher.Length);
            Array.Copy(expectedTag, 0, expected, expectedCipher.Length, expectedTag.Length);

            Assert.AreEqual(Hex.ToHexString(expected), Hex.ToHexString(aeadCt),
                "CipherUtilities XCHACHA20-POLY1305 did not reproduce draft vector");
        }
    }
}
