using System;
using System.Collections.Generic;
using System.IO;

using NUnit.Framework;

using Org.BouncyCastle.Crypto.Digests;
using Org.BouncyCastle.Crypto.Engines;
using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.Utilities;
using Org.BouncyCastle.Utilities.Encoders;
using Org.BouncyCastle.Utilities.Test;

namespace Org.BouncyCastle.Crypto.Tests
{
    [TestFixture]
    public class IsapTest
        : SimpleTest
    {
        public override string Name => "ISAP";

        [Test]
        public override void PerformTest()
        {
            IsapEngine isapEngine = new IsapEngine(IsapEngine.IsapType.ISAP_K_128A);
            ImplTestExceptions(isapEngine);
            ImplTestParameters(isapEngine, 16, 16, 16);
            isapEngine = new IsapEngine(IsapEngine.IsapType.ISAP_K_128);
            ImplTestExceptions(isapEngine);
            ImplTestParameters(isapEngine, 16, 16, 16);
            isapEngine = new IsapEngine(IsapEngine.IsapType.ISAP_A_128A);
            ImplTestExceptions(isapEngine);
            ImplTestParameters(isapEngine, 16, 16, 16);
            isapEngine = new IsapEngine(IsapEngine.IsapType.ISAP_A_128);
            ImplTestExceptions(isapEngine);
            ImplTestParameters(isapEngine, 16, 16, 16);
            ImplTestExceptions(new IsapDigest(), 32);
            ImplTestVectors("isapa128av20", IsapEngine.IsapType.ISAP_A_128A);
            ImplTestVectors("isapa128v20", IsapEngine.IsapType.ISAP_A_128);
            ImplTestVectors("isapk128av20", IsapEngine.IsapType.ISAP_K_128A);
            ImplTestVectors("isapk128v20", IsapEngine.IsapType.ISAP_K_128);
            ImplTestVectors();
        }

        private void ImplTestVectors(string filename, IsapEngine.IsapType isapType)
        {
            Random random = new Random();
            IsapEngine isapEngine = new IsapEngine(isapType);
            var buf = new Dictionary<string, string>();
            //TestSampler sampler = new TestSampler();
            using (var src = new StreamReader(SimpleTest.GetTestDataAsStream("crypto.isap." + filename + "_LWC_AEAD_KAT_128_128.txt")))
            {
                Dictionary<string, string> map = new Dictionary<string, string>();
                string line;
                while ((line = src.ReadLine()) != null)
                {
                    var data = line.Split(' ');
                    if (data.Length == 1)
                    {
                        byte[] key = Hex.Decode(map["Key"]);
                        byte[] nonce = Hex.Decode(map["Nonce"]);
                        byte[] ad = Hex.Decode(map["AD"]);
                        byte[] pt = Hex.Decode(map["PT"]);
                        byte[] ct = Hex.Decode(map["CT"]);
                        map.Clear();

                        var parameters = new ParametersWithIV(new KeyParameter(key), nonce);

                        // Encrypt
                        {
                            isapEngine.Init(true, parameters);

                            var rv = new byte[isapEngine.GetOutputSize(pt.Length)];
                            random.NextBytes(rv); // should overwrite any existing data

                            isapEngine.ProcessAadBytes(ad, 0, ad.Length);
                            int len = isapEngine.ProcessBytes(pt, 0, pt.Length, rv, 0);
                            len += isapEngine.DoFinal(rv, len);

                            Assert.True(Arrays.AreEqual(rv, 0, len, ct, 0, ct.Length));
                        }

                        // Decrypt
                        {
                            isapEngine.Init(false, parameters);

                            var rv = new byte[isapEngine.GetOutputSize(ct.Length)];
                            random.NextBytes(rv); // should overwrite any existing data

                            isapEngine.ProcessAadBytes(ad, 0, ad.Length);
                            int len = isapEngine.ProcessBytes(ct, 0, ct.Length, rv, 0);
                            len += isapEngine.DoFinal(rv, len);

                            Assert.True(Arrays.AreEqual(rv, 0, len, pt, 0, pt.Length));
                        }
                    }
                    else
                    {
                        if (data.Length >= 3)
                        {
                            map[data[0].Trim()] = data[2].Trim();
                        }
                        else
                        {
                            map[data[0].Trim()] = "";
                        }
                    }
                }
            }
        }

        private void ImplTestVectors()
        {
            IsapDigest isap = new IsapDigest();
            var buf = new Dictionary<string, string>();
            //TestSampler sampler = new TestSampler();
            using (var src = new StreamReader(SimpleTest.GetTestDataAsStream("crypto.isap.LWC_HASH_KAT_256.txt")))
            {
                string line;
                string[] data;
                byte[] ptByte;
                Dictionary<string, string> map = new Dictionary<string, string>();
                while ((line = src.ReadLine()) != null)
                {
                    data = line.Split(' ');
                    if (data.Length == 1)
                    {
                        ptByte = Hex.Decode(map["Msg"]);
                        isap.BlockUpdate(ptByte, 0, ptByte.Length);
                        byte[] hash = new byte[32];
                        isap.DoFinal(hash, 0);
                        Assert.True(Arrays.AreEqual(hash, Hex.Decode(map["MD"])));
                        map.Clear();
                        isap.Reset();
                    }
                    else
                    {
                        if (data.Length >= 3)
                        {
                            map[data[0].Trim()] = data[2].Trim();
                        }
                        else
                        {
                            map[data[0].Trim()] = "";
                        }

                    }
                }
            }
        }

        private void ImplTestExceptions(IsapEngine isapEngine)
        {
            int keySize = isapEngine.GetKeyBytesSize(), ivSize = isapEngine.GetIVBytesSize();
            int offset;
            byte[] k = new byte[keySize];
            byte[] iv = new byte[ivSize];
            byte[] m = Array.Empty<byte>();
            ICipherParameters param = new ParametersWithIV(new KeyParameter(k), iv);
            try
            {
                isapEngine.ProcessBytes(m, 0, m.Length, null, 0);
                Assert.Fail(isapEngine.AlgorithmName + " need to be initialized before ProcessBytes");
            }
            catch (ArgumentException)
            {
                //expected
            }

            try
            {
                isapEngine.ProcessByte((byte)0, null, 0);
                Assert.Fail(isapEngine.AlgorithmName + " need to be initialized before ProcessByte");
            }
            catch (ArgumentException)
            {
                //expected
            }

            try
            {
                isapEngine.Reset();
                Assert.Fail(isapEngine.AlgorithmName + " need to be initialized before Reset");
            }
            catch (ArgumentException)
            {
                //expected
            }

            try
            {
                isapEngine.DoFinal(null, m.Length);
                Assert.Fail(isapEngine.AlgorithmName + " need to be initialized before DoFinal");
            }
            catch (ArgumentException)
            {
                //expected
            }

            try
            {
                isapEngine.GetMac();
                isapEngine.GetOutputSize(0);
                isapEngine.GetUpdateOutputSize(0);
            }
            catch (ArgumentException)
            {
                Assert.Fail(isapEngine.AlgorithmName + " functions can be called before initialization");
            }
            Random rand = new Random();
            int randomNum;
            while ((randomNum = rand.Next(100)) == keySize) ;
            byte[] k1 = new byte[randomNum];
            while ((randomNum = rand.Next(100)) == ivSize) ;
            byte[] iv1 = new byte[randomNum];
            try
            {
                isapEngine.Init(true, new ParametersWithIV(new KeyParameter(k1), iv));
                Assert.Fail(isapEngine.AlgorithmName + " k size does not match");
            }
            catch (ArgumentException)
            {
                //expected
            }
            try
            {
                isapEngine.Init(true, new ParametersWithIV(new KeyParameter(k), iv1));
                Assert.Fail(isapEngine.AlgorithmName + "iv size does not match");
            }
            catch (ArgumentException)
            {
                //expected
            }

            isapEngine.Init(true, param);
            byte[] c1 = new byte[isapEngine.GetOutputSize(m.Length)];
            try
            {
                isapEngine.DoFinal(c1, m.Length);
            }
            catch (Exception)
            {
                Assert.Fail(isapEngine.AlgorithmName + " allows no input for AAD and plaintext");
            }
            byte[] mac2 = isapEngine.GetMac();
            if (mac2 == null)
            {
                Assert.Fail("mac should not be empty after Dofinal");
            }
            if (!Arrays.AreEqual(mac2, c1))
            {
                Assert.Fail("mac should be equal when calling Dofinal and GetMac");
            }
            isapEngine.ProcessAadByte(0x00);
            byte[] mac1 = new byte[isapEngine.GetOutputSize(0)];
            isapEngine.DoFinal(mac1, 0);
            if (Arrays.AreEqual(mac1, mac2))
            {
                Assert.Fail("mac should not match");
            }
            isapEngine.Reset();
            isapEngine.ProcessBytes(new byte[16], 0, 16, new byte[16], 0);
            //try
            //{
            //    aeadBlockCipher.ProcessAadByte((byte)0);
            //    Assert.Fail("ProcessAadByte(s) cannot be called after encryption/decryption");
            //}
            //catch (ArgumentException)
            //{
            //    //expected
            //}
            //try
            //{
            //    aeadBlockCipher.ProcessAadBytes(new byte[] { 0 }, 0, 1);
            //    Assert.Fail("ProcessAadByte(s) cannot be called once only");
            //}
            //catch (ArgumentException)
            //{
            //    //expected
            //}

            isapEngine.Reset();
            try
            {
                isapEngine.ProcessAadBytes(new byte[] { 0 }, 1, 1);
                Assert.Fail("input for ProcessAadBytes is too short");
            }
            catch (DataLengthException)
            {
                //expected
            }
            try
            {
                isapEngine.ProcessBytes(new byte[] { 0 }, 1, 1, c1, 0);
                Assert.Fail("input for ProcessBytes is too short");
            }
            catch (DataLengthException)
            {
                //expected
            }
            try
            {
                int inputSize = rand.Next(32, 64);
                int outputSize = isapEngine.GetUpdateOutputSize(inputSize);
                isapEngine.ProcessBytes(new byte[inputSize], 0, inputSize, new byte[outputSize], 1);
                Assert.Fail("output for ProcessBytes is too short");
            }
            catch (OutputLengthException)
            {
                //expected
            }
            try
            {
                isapEngine.DoFinal(new byte[2], 2);
                Assert.Fail("output for DoFinal is too short");
            }
            catch (OutputLengthException)
            {
                //expected
            }

            mac1 = new byte[isapEngine.GetOutputSize(0)];
            mac2 = new byte[isapEngine.GetOutputSize(0)];
            isapEngine.Reset();
            isapEngine.ProcessAadBytes(new byte[] { 0, 0 }, 0, 2);
            isapEngine.DoFinal(mac1, 0);
            isapEngine.Reset();
            isapEngine.ProcessAadByte((byte)0);
            isapEngine.ProcessAadByte((byte)0);
            isapEngine.DoFinal(mac2, 0);
            if (!Arrays.AreEqual(mac1, mac2))
            {
                Assert.Fail("mac should match for the same AAD with different ways of inputting");
            }

            byte[] c2 = new byte[isapEngine.GetOutputSize(10)];
            byte[] c3 = new byte[isapEngine.GetOutputSize(10) + 2];
            byte[] aad2 = { 0, 1, 2, 3, 4 };
            byte[] aad3 = { 0, 0, 1, 2, 3, 4, 5 };
            byte[] m2 = { 0, 1, 2, 3, 4, 5, 6, 7, 8, 9 };
            byte[] m3 = { 0, 0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10 };
            byte[] m4 = new byte[m2.Length];
            isapEngine.Reset();
            isapEngine.ProcessAadBytes(aad2, 0, aad2.Length);
            offset = isapEngine.ProcessBytes(m2, 0, m2.Length, c2, 0);
            isapEngine.DoFinal(c2, offset);
            isapEngine.Reset();
            isapEngine.ProcessAadBytes(aad3, 1, aad2.Length);
            offset = isapEngine.ProcessBytes(m3, 1, m2.Length, c3, 1);
            isapEngine.DoFinal(c3, offset + 1);
            byte[] c3_partial = new byte[c2.Length];
            Array.Copy(c3, 1, c3_partial, 0, c2.Length);
            if (!Arrays.AreEqual(c2, c3_partial))
            {
                Assert.Fail("mac should match for the same AAD and message with different offset for both input and output");
            }
            isapEngine.Reset();
            isapEngine.Init(false, param);
            isapEngine.ProcessAadBytes(aad2, 0, aad2.Length);
            offset = isapEngine.ProcessBytes(c2, 0, c2.Length, m4, 0);
            offset += isapEngine.DoFinal(m4, offset);
            if (!Arrays.AreEqual(m2, m4))
            {
                Assert.Fail("The encryption and decryption does not recover the plaintext");
            }
            c2[c2.Length - 1] ^= 1;
            isapEngine.Reset();
            isapEngine.Init(false, param);
            isapEngine.ProcessAadBytes(aad2, 0, aad2.Length);
            offset = isapEngine.ProcessBytes(c2, 0, c2.Length, m4, 0);
            try
            {
                offset += isapEngine.DoFinal(m4, offset);
                Assert.Fail("The decryption should fail");
            }
            catch (InvalidCipherTextException)
            {
                //expected;
            }
            c2[c2.Length - 1] ^= 1;

            byte[] m7 = new byte[32 + rand.Next(32)];
            rand.NextBytes(m7);

            isapEngine.Init(true, param);
            byte[] c7 = new byte[isapEngine.GetOutputSize(m7.Length)];
            byte[] c8 = new byte[c7.Length];
            byte[] c9 = new byte[c7.Length];
            isapEngine.ProcessAadBytes(aad2, 0, aad2.Length);
            offset = isapEngine.ProcessBytes(m7, 0, m7.Length, c7, 0);
            offset += isapEngine.DoFinal(c7, offset);
            isapEngine.Reset();
            isapEngine.ProcessAadBytes(aad2, 0, aad2.Length);
            offset = isapEngine.ProcessBytes(m7, 0, m7.Length / 2, c8, 0);
            offset += isapEngine.ProcessBytes(m7, m7.Length / 2, m7.Length - m7.Length / 2, c8, offset);
            offset += isapEngine.DoFinal(c8, offset);
            isapEngine.Reset();
            int split = rand.Next(1, m7.Length);
            isapEngine.ProcessAadBytes(aad2, 0, aad2.Length);
            offset = isapEngine.ProcessBytes(m7, 0, split, c9, 0);
            offset += isapEngine.ProcessBytes(m7, split, m7.Length - split, c9, offset);
            isapEngine.DoFinal(c9, offset);
            if (!Arrays.AreEqual(c7, c8) || !Arrays.AreEqual(c7, c9))
            {
                Assert.Fail("Splitting input of plaintext should output the same ciphertext");
            }
            // NOTE: .NET Core 3.1 has Span<T>, but is tested against our .NET Standard 2.0 assembly.
//#if NETCOREAPP2_1_OR_GREATER || NETSTANDARD2_1_OR_GREATER
#if NET6_0_OR_GREATER || NETSTANDARD2_1_OR_GREATER
            Span<byte> c4_1 = new byte[c2.Length];
            Span<byte> c4_2 = new byte[c2.Length];
            ReadOnlySpan<byte> m5 = new ReadOnlySpan<byte>(m2);
            ReadOnlySpan<byte> aad4 = new ReadOnlySpan<byte>(aad2);
            isapEngine.Init(true, param);
            isapEngine.ProcessAadBytes(aad4);
            offset = isapEngine.ProcessBytes(m5, c4_1);
            isapEngine.DoFinal(c4_2);
            byte[] c5 = new byte[c2.Length];
            c4_1[..offset].CopyTo(c5);
            c4_2[..(c5.Length - offset)].CopyTo(c5.AsSpan(offset));
            if (!Arrays.AreEqual(c2, c5))
            {
                Assert.Fail("mac should match for the same AAD and message with different offset for both input and output");
            }
            isapEngine.Reset();
            isapEngine.Init(false, param);
            Span<byte> m6_1 = new byte[m2.Length];
            Span<byte> m6_2 = new byte[m2.Length];
            ReadOnlySpan<byte> c6 = new ReadOnlySpan<byte>(c2);
            isapEngine.ProcessAadBytes(aad4);
            offset = isapEngine.ProcessBytes(c6, m6_1);
            isapEngine.DoFinal(m6_2);
            byte[] m6 = new byte[m2.Length];
            m6_1[..offset].CopyTo(m6);
            m6_2[..(m6.Length - offset)].CopyTo(m6.AsSpan(offset));
            if (!Arrays.AreEqual(m2, m6))
            {
                Assert.Fail("mac should match for the same AAD and message with different offset for both input and output");
            }
#endif
        }

        private void ImplTestParameters(IsapEngine isapEngine, int keySize, int ivSize, int macSize)
        {
            Assert.AreEqual(keySize, isapEngine.GetKeyBytesSize(),
                "key bytes of " + isapEngine.AlgorithmName + " is not correct");
            Assert.AreEqual(ivSize, isapEngine.GetIVBytesSize(),
                "iv bytes of " + isapEngine.AlgorithmName + " is not correct");

            var parameters = new ParametersWithIV(new KeyParameter(new byte[keySize]), new byte[ivSize]);

            isapEngine.Init(true, parameters);
            Assert.AreEqual(macSize, isapEngine.GetOutputSize(0),
                "GetOutputSize of " + isapEngine.AlgorithmName + " is incorrect for encryption");

            isapEngine.Init(false, parameters);
            Assert.AreEqual(0, isapEngine.GetOutputSize(macSize),
                "GetOutputSize of " + isapEngine.AlgorithmName + " is incorrect for decryption");
        }

        private void ImplTestExceptions(IsapDigest isapDigest, int digestsize)
        {
            if (isapDigest.GetDigestSize() != digestsize)
            {
                Assert.Fail(isapDigest.AlgorithmName + ": digest size is not correct");
            }

            try
            {
                isapDigest.BlockUpdate(new byte[1], 1, 1);
                Assert.Fail(isapDigest.AlgorithmName + ": input for BlockUpdate is too short");
            }
            catch (DataLengthException)
            {
                //expected
            }
            try
            {
                isapDigest.DoFinal(new byte[isapDigest.GetDigestSize() - 1], 2);
                Assert.Fail(isapDigest.AlgorithmName + ": output for DoFinal is too short");
            }
            catch (OutputLengthException)
            {
                //expected
            }
        }
    }
}
