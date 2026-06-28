using System;
using System.Text;

using NUnit.Framework;

using Org.BouncyCastle.Crypto.Engines;
using Org.BouncyCastle.Crypto.Modes;
using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.Utilities;
using Org.BouncyCastle.Utilities.Encoders;
using Org.BouncyCastle.Utilities.Test;

namespace Org.BouncyCastle.Crypto.Tests
{
    [TestFixture]
    public class CcmTest
        : SimpleTest
    {
        private static readonly byte[] K1 = Hex.Decode("404142434445464748494a4b4c4d4e4f");
        private static readonly byte[] N1 = Hex.Decode("10111213141516");
        private static readonly byte[] A1 = Hex.Decode("0001020304050607");
        private static readonly byte[] P1 = Hex.Decode("20212223");
        private static readonly byte[] C1 = Hex.Decode("7162015b4dac255d");
        private static readonly byte[] T1 = Hex.Decode("6084341b");

        private static readonly byte[] K2 = Hex.Decode("404142434445464748494a4b4c4d4e4f");
        private static readonly byte[] N2 = Hex.Decode("1011121314151617");
        private static readonly byte[] A2 = Hex.Decode("000102030405060708090a0b0c0d0e0f");
        private static readonly byte[] P2 = Hex.Decode("202122232425262728292a2b2c2d2e2f");
        private static readonly byte[] C2 = Hex.Decode("d2a1f0e051ea5f62081a7792073d593d1fc64fbfaccd");
        private static readonly byte[] T2 = Hex.Decode("7f479ffca464");

        private static readonly byte[] K3 = Hex.Decode("404142434445464748494a4b4c4d4e4f");
        private static readonly byte[] N3 = Hex.Decode("101112131415161718191a1b");
        private static readonly byte[] A3 = Hex.Decode("000102030405060708090a0b0c0d0e0f10111213");
        private static readonly byte[] P3 = Hex.Decode("202122232425262728292a2b2c2d2e2f3031323334353637");
        private static readonly byte[] C3 = Hex.Decode("e3b201a9f5b71a7a9b1ceaeccd97e70b6176aad9a4428aa5484392fbc1b09951");
        private static readonly byte[] T3 = Hex.Decode("67c99240c7d51048");

        private static readonly byte[] K4 = Hex.Decode("404142434445464748494a4b4c4d4e4f");
        private static readonly byte[] N4 = Hex.Decode("101112131415161718191a1b1c");
        private static readonly byte[] A4 = Hex.Decode("000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f202122232425262728292a2b2c2d2e2f303132333435363738393a3b3c3d3e3f404142434445464748494a4b4c4d4e4f505152535455565758595a5b5c5d5e5f606162636465666768696a6b6c6d6e6f707172737475767778797a7b7c7d7e7f808182838485868788898a8b8c8d8e8f909192939495969798999a9b9c9d9e9fa0a1a2a3a4a5a6a7a8a9aaabacadaeafb0b1b2b3b4b5b6b7b8b9babbbcbdbebfc0c1c2c3c4c5c6c7c8c9cacbcccdcecfd0d1d2d3d4d5d6d7d8d9dadbdcdddedfe0e1e2e3e4e5e6e7e8e9eaebecedeeeff0f1f2f3f4f5f6f7f8f9fafbfcfdfeff");
        private static readonly byte[] P4 = Hex.Decode("202122232425262728292a2b2c2d2e2f303132333435363738393a3b3c3d3e3f");
        private static readonly byte[] C4 = Hex.Decode("69915dad1e84c6376a68c2967e4dab615ae0fd1faec44cc484828529463ccf72b4ac6bec93e8598e7f0dadbcea5b");
        private static readonly byte[] T4 = Hex.Decode("f4dd5d0ee404617225ffe34fce91");

        //
        // long data vector
        //
        private static readonly byte[] C5 = Hex.Decode("49b17d8d3ea4e6174a48e2b65e6d8b417ac0dd3f8ee46ce4a4a2a509661cef52528c1cd9805333a5cfd482fa3f095a3c2fdd1cc47771c5e55fddd60b5c8d6d3fa5c8dd79d08b16242b6642106e7c0c28bd1064b31e6d7c9800c8397dbc3fa8071e6a38278b386c18d65d39c6ad1ef9501a5c8f68d38eb6474799f3cc898b4b9b97e87f9c95ce5c51bc9d758f17119586663a5684e0a0daf6520ec572b87473eb141d10471e4799ded9e607655402eca5176bbf792ef39dd135ac8d710da8e9e854fd3b95c681023f36b5ebe2fb213d0b62dd6e9e3cfe190b792ccb20c53423b2dca128f861a61d306910e1af418839467e466f0ec361d2539eedd99d4724f1b51c07beb40e875a87491ec8b27cd1");
        private static readonly byte[] T5 = Hex.Decode("5c768856796b627b13ec8641581b");

        public override string Name => "CCM";

        public override void PerformTest()
        {
            CcmBlockCipher ccm = new CcmBlockCipher(AesUtilities.CreateEngine());

            CheckVectors(0, K1, 32, N1, A1, P1, T1, C1);
            CheckVectors(1, K2, 48, N2, A2, P2, T2, C2);
            CheckVectors(2, K3, 64, N3, A3, P3, T3, C3);

            IVParamTest(0, ccm, K1, N1);

            //
            // 4 has a reduced associated text which needs to be replicated
            //
            byte[] a4 = new byte[65536]; // 524288 / 8

            for (int i = 0; i < a4.Length; i += A4.Length)
            {
                Array.Copy(A4, 0, a4, i, A4.Length);
            }

            CheckVectors(3, K4, 112, N4, a4, P4, T4, C4);

            //
            // long data test
            //
            CheckVectors(4, K4, 112, N4, A4, A4, T5, C5);

            // decryption with output specified, non-zero offset.
            ccm.Init(false, new AeadParameters(new KeyParameter(K2), 48, N2, A2));

            byte[] inBuf = new byte[C2.Length + 10];
            byte[] outBuf = new byte[ccm.GetOutputSize(C2.Length) + 10];

            Array.Copy(C2, 0, inBuf, 10, C2.Length);

            int len = ccm.ProcessPacket(inBuf, 10, C2.Length, outBuf, 10);
            byte[] output = ccm.ProcessPacket(C2, 0, C2.Length);

            if (len != output.Length || !IsEqual(output, outBuf, 10))
            {
                Fail("decryption output incorrect");
            }

            // encryption with output specified, non-zero offset. A fresh instance is used because
            // re-initialising the decryption cipher above for encryption with the same key+nonce is
            // now rejected by the nonce-reuse guard.
            CcmBlockCipher encCcm = new CcmBlockCipher(AesUtilities.CreateEngine());
            encCcm.Init(true, new AeadParameters(new KeyParameter(K2), 48, N2, A2));

            int inLen = len;
            inBuf = outBuf;
            outBuf = new byte[encCcm.GetOutputSize(inLen) + 10];

            len = encCcm.ProcessPacket(inBuf, 10, inLen, outBuf, 10);
            output = encCcm.ProcessPacket(inBuf, 10, inLen);

            if (len != output.Length || !IsEqual(output, outBuf, 10))
            {
                Fail("encryption output incorrect");
            }

            //
            // exception tests
            //

            try
            {
                ccm.Init(false, new AeadParameters(new KeyParameter(K1), 32, N2, A2));

                ccm.ProcessPacket(C2, 0, C2.Length);

                Fail("invalid cipher text not picked up");
            }
            catch (InvalidCipherTextException)
            {
                // expected
            }

            try
            {
                ccm = new CcmBlockCipher(new DesEngine());

                Fail("incorrect block size not picked up");
            }
            catch (ArgumentException)
            {
                // expected
            }

            try
            {
                ccm.Init(false, new KeyParameter(K1));

                Fail("illegal argument not picked up");
            }
            catch (ArgumentException)
            {
                // expected
            }

            // For small number of allowed blocks, validate boundary
            // conditions are properly handled. Zero and greater will
            // fail as size bound is a strict inequality.
            int[] offsets = new int[]{ -10, -2, -1, 0, 1, 10 };
            int[] ns = new int[]{ 13, 12 };
            for (int i = 0; i != ns.Length; i++)
            {
                int n_len = ns[i];
                for (int j = 0; j != offsets.Length; j++)
                {
                    int offset = offsets[j];
                    try
                    {
                        // A fresh cipher per iteration: re-initialising one instance for encryption
                        // with the same key+nonce is now rejected by the nonce-reuse guard.
                        CcmBlockCipher bccm = new CcmBlockCipher(AesUtilities.CreateEngine());
                        bccm.Init(true, new AeadParameters(new KeyParameter(K1), 128, new byte[n_len]));

                        // Encrypt up to 2^(8q) + offset. Note that message length
                        // must be strictly less than 2^(8q) so offset=0 will not
                        // work (per SP 800-38C Section A.1 Length Requirements).
                        int q = 15 - n_len;
                        int size = 1 << (8 * q);
                        inBuf = new byte[size + offset];

                        outBuf = new byte[bccm.GetOutputSize(inBuf.Length)];
                        len = bccm.ProcessPacket(inBuf, 0, inBuf.Length, outBuf, 0);

                        if (offset >= 0)
                        {
                            Fail("expected to fail to encrypt boundary bytes n=" + n_len + "size=" + size + " offset=" + offset);
                        }
                        else
                        {
                            // Decrypt should also succeed if encryption succeeded.
                            bccm.Init(false, new AeadParameters(new KeyParameter(K1), 128, new byte[n_len]));
                            output = bccm.ProcessPacket(outBuf, 0, outBuf.Length);

                            if (output.Length != inBuf.Length || !Arrays.AreEqual(inBuf, output))
                            {
                                Fail("encryption output incorrect");
                            }
                        }
                    }
                    catch (Exception e)
                    {
                        if (offset< 0)
                        {
                            Fail("unexpected failure to encrypt boundary bytes n=" + n_len + " offset=" + offset + " msg=" + e.Message);
                        }
                    }
                }
            }

            AeadTestUtilities.TestReset(this, new CcmBlockCipher(AesUtilities.CreateEngine()),
                new CcmBlockCipher(AesUtilities.CreateEngine()), new AeadParameters(new KeyParameter(K1), 32, N2));
            AeadTestUtilities.TestTampering(this, new CcmBlockCipher(AesUtilities.CreateEngine()),
                new AeadParameters(new KeyParameter(K1), 32, N2));
            AeadTestUtilities.TestOutputSizes(this, new CcmBlockCipher(AesUtilities.CreateEngine()),
                new AeadParameters(new KeyParameter(K1), 32, N2));
            AeadTestUtilities.TestBufferSizeChecks(this, new CcmBlockCipher(AesUtilities.CreateEngine()),
                new AeadParameters(new KeyParameter(K1), 32, N2));
        }

        private void CheckVectors(int count, byte[] k, int macSize, byte[] n, byte[] a, byte[] p,
            byte[] t, byte[] c)
        {
            byte[] fa = new byte[a.Length / 2];
            byte[] la = new byte[a.Length - (a.Length / 2)];
            Array.Copy(a, 0, fa, 0, fa.Length);
            Array.Copy(a, fa.Length, la, 0, la.Length);

            // A fresh cipher per case: re-initialising one instance for encryption with the same
            // key+nonce is now rejected by the nonce-reuse guard.
            CheckVectors(count, new CcmBlockCipher(AesUtilities.CreateEngine()), "all initial associated data", k, macSize, n, a, null, p, t, c);
            CheckVectors(count, new CcmBlockCipher(AesUtilities.CreateEngine()), "subsequent associated data", k, macSize, n, null, a, p, t, c);
            CheckVectors(count, new CcmBlockCipher(AesUtilities.CreateEngine()), "split associated data", k, macSize, n, fa, la, p, t, c);

            // Key reuse: re-initialising the same instance for encryption with the same key+nonce (here
            // via a null key, i.e. key re-use) is now rejected (nonce reuse is catastrophic for CCM).
            CcmBlockCipher reuse = new CcmBlockCipher(AesUtilities.CreateEngine());
            reuse.Init(true, new AeadParameters(new KeyParameter(k), macSize, n, a));
            byte[] enc = new byte[reuse.GetOutputSize(p.Length)];
            int len = reuse.ProcessBytes(p, 0, p.Length, enc, 0);
            reuse.DoFinal(enc, len);
            try
            {
                reuse.Init(true, new AeadParameters(null, macSize, n, a));
                Fail("CCM nonce reuse not detected on re-init for encryption in test " + count);
            }
            catch (ArgumentException e)
            {
                IsTrue("wrong CCM nonce-reuse message: " + e.Message,
                    "cannot reuse nonce for CCM encryption".Equals(e.Message));
            }
        }

        private void CheckVectors(int count, CcmBlockCipher ccm, string additionalDataType, byte[] k, int macSize,
            byte[] n, byte[] a, byte[] sa, byte[] p, byte[] t, byte[] c)
        {
            KeyParameter keyParam = (k == null) ? null : new KeyParameter(k);

            ccm.Init(true, new AeadParameters(keyParam, macSize, n, a));

            byte[] enc = new byte[c.Length];

            if (sa != null)
            {
                ccm.ProcessAadBytes(sa, 0, sa.Length);
            }

            int len = ccm.ProcessBytes(p, 0, p.Length, enc, 0);

            len += ccm.DoFinal(enc, len);

            //ccm.Init(true, new AeadParameters(new KeyParameter(k), macSize, n, a));
            //
            //byte[] enc = ccm.ProcessPacket(p, 0, p.Length);

            if (!AreEqual(c, enc))
            {
                Fail("encrypted stream fails to match in test " + count + " with " + additionalDataType);
            }

            ccm.Init(false, new AeadParameters(new KeyParameter(k), macSize, n, a));

            byte[] tmp = new byte[enc.Length];

            if (sa != null)
            {
                ccm.ProcessAadBytes(sa, 0, sa.Length);
            }

            len = ccm.ProcessBytes(enc, 0, enc.Length, tmp, 0);

            len += ccm.DoFinal(tmp, len);

            byte[] dec = new byte[len];

            Array.Copy(tmp, 0, dec, 0, len);

            if (!AreEqual(p, dec))
            {
                Fail("decrypted stream fails to match in test " + count + " with " + additionalDataType,
                    Hex.ToHexString(p), Hex.ToHexString(dec));
            }

            if (!AreEqual(t, ccm.GetMac()))
            {
                Fail("MAC fails to match in test " + count + " with " + additionalDataType);
            }
        }

        private void IVParamTest(int count, CcmBlockCipher ccm, byte[] k, byte[] n)
        {
            byte[] p = Encoding.ASCII.GetBytes("hello world!!");

            ccm.Init(true, new ParametersWithIV(new KeyParameter(k), n));

            byte[] enc = new byte[p.Length + 8];

            int len = ccm.ProcessBytes(p, 0, p.Length, enc, 0);

            len += ccm.DoFinal(enc, len);

            ccm.Init(false, new ParametersWithIV(new KeyParameter(k), n));

            byte[] tmp = new byte[enc.Length];

            len = ccm.ProcessBytes(enc, 0, enc.Length, tmp, 0);

            len += ccm.DoFinal(tmp, len);

            byte[] dec = new byte[len];

            Array.Copy(tmp, 0, dec, 0, len);

            if (!AreEqual(p, dec))
            {
                Fail("decrypted stream fails to match in test " + count);
            }
        }

        [Test]
        public void TestFunction()
        {
            string resultText = Perform().ToString();

            Assert.AreEqual(Name + ": Okay", resultText);
        }

        [Test]
        public void InvalidTagLength()
        {
            foreach (int macSizeBits in new int[]{ 0, 8, 24, 40, 56, 72, 88, 104, 120, 136 })
            {
                // Rejected on encryption...
                Assert.Throws<ArgumentException>(() =>
                    new CcmBlockCipher(AesUtilities.CreateEngine()).Init(forEncryption: true,
                        new AeadParameters(new KeyParameter(K1), macSizeBits, N1, A1)));

                // ...and decryption
                Assert.Throws<ArgumentException>(() =>
                    new CcmBlockCipher(AesUtilities.CreateEngine()).Init(forEncryption: false,
                        new AeadParameters(new KeyParameter(K1), macSizeBits, N1, A1)));
            }
        }

        [Test]
        public void NoUnverifiedPlaintextOnFailure()
        {
            CcmBlockCipher ccm = new CcmBlockCipher(AesUtilities.CreateEngine());
            ccm.Init(false, new AeadParameters(new KeyParameter(K2), 48, N2, A2));

            // Corrupt the authentication tag so verification fails; the ciphertext body is unchanged.
            byte[] tampered = Arrays.Clone(C2);
            tampered[tampered.Length - 1] ^= 0x01;

            byte[] output = new byte[ccm.GetOutputSize(tampered.Length)];
            Arrays.Fill(output, (byte)0x55);

            try
            {
                ccm.ProcessPacket(tampered, 0, tampered.Length, output, 0);
                Fail("tampered CCM ciphertext must not verify");
            }
            catch (InvalidCipherTextException)
            {
                // On a tag-check failure the caller's output buffer must not be left holding the
                // unverified CTR plaintext.
                for (int i = 0; i != output.Length; i++)
                {
                    if (output[i] != (byte)0x55)
                    {
                        Fail("CCM left unverified plaintext in the output buffer on tag failure");
                    }
                }
            }
        }

        [Test]
        public void ValidTagLength()
        {
            byte[] plaintext = Hex.Decode("202122232425262728292a2b2c2d2e2f3031323334353637");

            for (int macSizeBits = 32; macSizeBits <= 128; macSizeBits += 16)
            {
                var enc = new CcmBlockCipher(AesUtilities.CreateEngine());
                enc.Init(forEncryption: true, new AeadParameters(new KeyParameter(K1), macSizeBits, N1, A1));
                byte[] ct = enc.ProcessPacket(plaintext, 0, plaintext.Length);

                var dec = new CcmBlockCipher(AesUtilities.CreateEngine());
                dec.Init(forEncryption: false, new AeadParameters(new KeyParameter(K1), macSizeBits, N1, A1));
                byte[] recovered = dec.ProcessPacket(ct, 0, ct.Length);

                Assert.That(Arrays.AreEqual(plaintext, recovered));
            }
        }

        private static bool IsEqual(byte[] exp, byte[] other, int off)
        {
            for (int i = 0; i != exp.Length; i++)
            {
                if (exp[i] != other[off + i])
                    return false;
            }

            return true;
        }
    }
}
