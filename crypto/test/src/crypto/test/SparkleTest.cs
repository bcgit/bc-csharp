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
    public class SparkleTest
    {
        [Test, Explicit]
        public void BenchDigest_ESCH256()
        {
            ImplBenchDigest(SparkleDigest.SparkleParameters.ESCH256);
        }

        [Test, Explicit]
        public void BenchDigest_ESCH384()
        {
            ImplBenchDigest(SparkleDigest.SparkleParameters.ESCH384);
        }

        [Test, Explicit]
        public void BenchEngineAuth_SCHWAEMM128_128()
        {
            ImplBenchEngineAuth(SparkleEngine.SparkleParameters.SCHWAEMM128_128);
        }

        [Test, Explicit]
        public void BenchEngineAuth_SCHWAEMM192_192()
        {
            ImplBenchEngineAuth(SparkleEngine.SparkleParameters.SCHWAEMM192_192);
        }

        [Test, Explicit]
        public void BenchEngineAuth_SCHWAEMM256_128()
        {
            ImplBenchEngineAuth(SparkleEngine.SparkleParameters.SCHWAEMM256_128);
        }

        [Test, Explicit]
        public void BenchEngineAuth_SCHWAEMM256_256()
        {
            ImplBenchEngineAuth(SparkleEngine.SparkleParameters.SCHWAEMM256_256);
        }

        [Test, Explicit]
        public void BenchEngineDecrypt_SCHWAEMM128_128()
        {
            ImplBenchEngineCrypt(SparkleEngine.SparkleParameters.SCHWAEMM128_128, false);
        }

        [Test, Explicit]
        public void BenchEngineDecrypt_SCHWAEMM192_192()
        {
            ImplBenchEngineCrypt(SparkleEngine.SparkleParameters.SCHWAEMM192_192, false);
        }

        [Test, Explicit]
        public void BenchEngineDecrypt_SCHWAEMM256_128()
        {
            ImplBenchEngineCrypt(SparkleEngine.SparkleParameters.SCHWAEMM256_128, false);
        }

        [Test, Explicit]
        public void BenchEngineDecrypt_SCHWAEMM256_256()
        {
            ImplBenchEngineCrypt(SparkleEngine.SparkleParameters.SCHWAEMM256_256, false);
        }

        [Test, Explicit]
        public void BenchEngineEncrypt_SCHWAEMM128_128()
        {
            ImplBenchEngineCrypt(SparkleEngine.SparkleParameters.SCHWAEMM128_128, true);
        }

        [Test, Explicit]
        public void BenchEngineEncrypt_SCHWAEMM192_192()
        {
            ImplBenchEngineCrypt(SparkleEngine.SparkleParameters.SCHWAEMM192_192, true);
        }

        [Test, Explicit]
        public void BenchEngineEncrypt_SCHWAEMM256_128()
        {
            ImplBenchEngineCrypt(SparkleEngine.SparkleParameters.SCHWAEMM256_128, true);
        }

        [Test, Explicit]
        public void BenchEngineEncrypt_SCHWAEMM256_256()
        {
            ImplBenchEngineCrypt(SparkleEngine.SparkleParameters.SCHWAEMM256_256, true);
        }

        [Test]
        public void TestExceptionsDigest_ESCH256()
        {
            ImplTestExceptionsDigest(SparkleDigest.SparkleParameters.ESCH256);
        }

        [Test]
        public void TestExceptionsDigest_ESCH384()
        {
            ImplTestExceptionsDigest(SparkleDigest.SparkleParameters.ESCH384);
        }

        [Test]
        public void TestExceptionsEngine_SCHWAEMM128_128()
        {
            ImplTestExceptionsEngine(SparkleEngine.SparkleParameters.SCHWAEMM128_128);
        }

        [Test]
        public void TestExceptionsEngine_SCHWAEMM192_192()
        {
            ImplTestExceptionsEngine(SparkleEngine.SparkleParameters.SCHWAEMM192_192);
        }

        [Test]
        public void TestExceptionsEngine_SCHWAEMM256_128()
        {
            ImplTestExceptionsEngine(SparkleEngine.SparkleParameters.SCHWAEMM256_128);
        }

        [Test]
        public void TestExceptionsEngine_SCHWAEMM256_256()
        {
            ImplTestExceptionsEngine(SparkleEngine.SparkleParameters.SCHWAEMM256_256);
        }

        [Test]
        public void TestParametersDigest_ESCH256()
        {
            ImplTestParametersDigest(SparkleDigest.SparkleParameters.ESCH256, 32);
        }

        [Test]
        public void TestParametersDigest_ESCH384()
        {
            ImplTestParametersDigest(SparkleDigest.SparkleParameters.ESCH384, 48);
        }

        [Test]
        public void TestParametersEngine_SCHWAEMM128_128()
        {
            ImplTestParametersEngine(SparkleEngine.SparkleParameters.SCHWAEMM128_128, 16, 16, 16);
        }

        [Test]
        public void TestParametersEngine_SCHWAEMM192_192()
        {
            ImplTestParametersEngine(SparkleEngine.SparkleParameters.SCHWAEMM192_192, 24, 24, 24);
        }

        [Test]
        public void TestParametersEngine_SCHWAEMM256_128()
        {
            ImplTestParametersEngine(SparkleEngine.SparkleParameters.SCHWAEMM256_128, 16, 32, 16);
        }

        [Test]
        public void TestParametersEngine_SCHWAEMM256_256()
        {
            ImplTestParametersEngine(SparkleEngine.SparkleParameters.SCHWAEMM256_256, 32, 32, 32);
        }

        [Test]
        public void TestVectorsDigest_ESCH256()
        {
            ImplTestVectorsDigest(SparkleDigest.SparkleParameters.ESCH256, "256");
        }

        [Test]
        public void TestVectorsDigest_ESCH384()
        {
            ImplTestVectorsDigest(SparkleDigest.SparkleParameters.ESCH384, "384");
        }

        [Test]
        public void TestVectorsEngine_SCHWAEMM128_128()
        {
            ImplTestVectorsEngine(SparkleEngine.SparkleParameters.SCHWAEMM128_128, "128_128");
        }

        [Test]
        public void TestVectorsEngine_SCHWAEMM192_192()
        {
            ImplTestVectorsEngine(SparkleEngine.SparkleParameters.SCHWAEMM192_192, "192_192");
        }

        [Test]
        public void TestVectorsEngine_SCHWAEMM256_128()
        {
            ImplTestVectorsEngine(SparkleEngine.SparkleParameters.SCHWAEMM256_128, "128_256");
        }

        [Test]
        public void TestVectorsEngine_SCHWAEMM256_256()
        {
            ImplTestVectorsEngine(SparkleEngine.SparkleParameters.SCHWAEMM256_256, "256_256");
        }

        private static SparkleDigest CreateDigest(SparkleDigest.SparkleParameters sparkleParameters)
        {
            return new SparkleDigest(sparkleParameters);
        }

        private static SparkleEngine CreateEngine(SparkleEngine.SparkleParameters sparkleParameters)
        {
            return new SparkleEngine(sparkleParameters);
        }

        private static void ImplBenchDigest(SparkleDigest.SparkleParameters sparkleParameters)
        {
            var sparkle = CreateDigest(sparkleParameters);

            byte[] data = new byte[1024];
            for (int i = 0; i < 1024; ++i)
            {
                for (int j = 0; j < 1024; ++j)
                {
                    // NOTE: .NET Core 3.1 has Span<T>, but is tested against our .NET Standard 2.0 assembly.
//#if NETCOREAPP2_1_OR_GREATER || NETSTANDARD2_1_OR_GREATER
#if NET6_0_OR_GREATER || NETSTANDARD2_1_OR_GREATER
                    sparkle.BlockUpdate(data);
#else
                    sparkle.BlockUpdate(data, 0, 1024);
#endif
                }

                // NOTE: .NET Core 3.1 has Span<T>, but is tested against our .NET Standard 2.0 assembly.
//#if NETCOREAPP2_1_OR_GREATER || NETSTANDARD2_1_OR_GREATER
#if NET6_0_OR_GREATER || NETSTANDARD2_1_OR_GREATER
                sparkle.DoFinal(data);
#else
                sparkle.DoFinal(data, 0);
#endif
            }
        }

        private static void ImplBenchEngineAuth(SparkleEngine.SparkleParameters sparkleParameters)
        {
            var sparkle = CreateEngine(sparkleParameters);
            InitEngine(sparkle, true);

            byte[] data = new byte[1024];
            for (int i = 0; i < 1024 * 1024; ++i)
            {
                // NOTE: .NET Core 3.1 has Span<T>, but is tested against our .NET Standard 2.0 assembly.
//#if NETCOREAPP2_1_OR_GREATER || NETSTANDARD2_1_OR_GREATER
#if NET6_0_OR_GREATER || NETSTANDARD2_1_OR_GREATER
                sparkle.ProcessAadBytes(data);
#else
                sparkle.ProcessAadBytes(data, 0, 1024);
#endif
            }
        }

        private static void ImplBenchEngineCrypt(SparkleEngine.SparkleParameters sparkleParameters, bool forEncryption)
        {
            var sparkle = CreateEngine(sparkleParameters);
            InitEngine(sparkle, forEncryption);

            byte[] data = new byte[1024 + 64];
            for (int i = 0; i < 1024 * 1024; ++i)
            {
                // NOTE: .NET Core 3.1 has Span<T>, but is tested against our .NET Standard 2.0 assembly.
//#if NETCOREAPP2_1_OR_GREATER || NETSTANDARD2_1_OR_GREATER
#if NET6_0_OR_GREATER || NETSTANDARD2_1_OR_GREATER
                sparkle.ProcessBytes(data.AsSpan(0, 1024), data);
#else
                sparkle.ProcessBytes(data, 0, 1024, data, 0);
#endif
            }
        }

        private static void ImplTestExceptionsDigest(SparkleDigest.SparkleParameters sparkleParameters)
        {
            var sparkle = new SparkleDigest(sparkleParameters);

            try
            {
                sparkle.BlockUpdate(new byte[1], 1, 1);
                Assert.Fail(sparkle.AlgorithmName + ": input for BlockUpdate is too short");
            }
            catch (DataLengthException)
            {
                //expected
            }

            try
            {
                sparkle.DoFinal(new byte[sparkle.GetDigestSize() - 1], 2);
                Assert.Fail(sparkle.AlgorithmName + ": output for Dofinal is too short");
            }
            catch (DataLengthException)
            {
                //expected
            }
        }

        private void ImplTestExceptionsEngine(SparkleEngine.SparkleParameters sparkleParameters)
        {
            var sparkle = new SparkleEngine(sparkleParameters);

            int keysize = sparkle.GetKeyBytesSize(), ivsize = sparkle.GetIVBytesSize();
            int offset;
            byte[] k = new byte[keysize];
            byte[] iv = new byte[ivsize];
            byte[] m = Array.Empty<byte>();
            var param = new ParametersWithIV(new KeyParameter(k), iv);
            try
            {
                sparkle.ProcessBytes(m, 0, m.Length, null, 0);
                Assert.Fail(sparkle.AlgorithmName + " needs to be initialized before ProcessBytes");
            }
            catch (InvalidOperationException)
            {
                //expected
            }

            try
            {
                sparkle.ProcessByte(0x00, null, 0);
                Assert.Fail(sparkle.AlgorithmName + " needs to be initialized before ProcessByte");
            }
            catch (InvalidOperationException)
            {
                //expected
            }

            try
            {
                sparkle.Reset();
                Assert.Fail(sparkle.AlgorithmName + " needs to be initialized before Reset");
            }
            catch (InvalidOperationException)
            {
                //expected
            }

            try
            {
                sparkle.DoFinal(null, m.Length);
                Assert.Fail(sparkle.AlgorithmName + " needs to be initialized before DoFinal");
            }
            catch (InvalidOperationException)
            {
                //expected
            }

            try
            {
                sparkle.GetMac();
                sparkle.GetOutputSize(0);
                sparkle.GetUpdateOutputSize(0);
            }
            catch (InvalidOperationException)
            {
                //expected
                Assert.Fail(sparkle.AlgorithmName + " functions can be called before initialization");
            }

            Random rand = new Random();
            int randomNum;
            while ((randomNum = rand.Next(100)) == keysize) ;
            byte[] k1 = new byte[randomNum];
            while ((randomNum = rand.Next(100)) == ivsize) ;
            byte[] iv1 = new byte[randomNum];
            try
            {
                sparkle.Init(true, new ParametersWithIV(new KeyParameter(k1), iv));
                Assert.Fail(sparkle.AlgorithmName + " k size does not match");
            }
            catch (ArgumentException)
            {
                //expected
            }
            try
            {
                sparkle.Init(true, new ParametersWithIV(new KeyParameter(k), iv1));
                Assert.Fail(sparkle.AlgorithmName + "iv size does not match");
            }
            catch (ArgumentException)
            {
                //expected
            }

            sparkle.Init(true, param);
            byte[] c1 = new byte[sparkle.GetOutputSize(m.Length)];
            try
            {
                sparkle.DoFinal(c1, m.Length);
            }
            catch (Exception)
            {
                Assert.Fail(sparkle.AlgorithmName + " allows no input for AAD and plaintext");
            }
            byte[] mac2 = sparkle.GetMac();
            if (mac2 == null)
            {
                Assert.Fail("mac should not be empty after DoFinal");
            }
            if (!Arrays.AreEqual(mac2, c1))
            {
                Assert.Fail("mac should be equal when calling DoFinal and GetMac");
            }

            // TODO Maybe use a different IV for this
            sparkle.Init(true, param);
            sparkle.ProcessAadByte((byte)0);
            byte[] mac1 = new byte[sparkle.GetOutputSize(0)];
            sparkle.DoFinal(mac1, 0);
            if (Arrays.AreEqual(mac1, mac2))
            {
                Assert.Fail("mac should not match");
            }

            // TODO Maybe use a different IV for this
            sparkle.Init(true, param);
            sparkle.ProcessByte(0, null, 0);
            try
            {
                sparkle.ProcessAadByte(0x00);
                Assert.Fail("ProcessAadByte cannot be called after encryption/decryption");
            }
            catch (InvalidOperationException)
            {
                //expected
            }
            try
            {
                sparkle.ProcessAadBytes(new byte[1], 0, 1);
                Assert.Fail("ProcessAadBytes cannot be called after encryption/decryption");
            }
            catch (InvalidOperationException)
            {
                //expected
            }

            // TODO Maybe use a different IV for this
            sparkle.Init(true, param);
            try
            {
                sparkle.ProcessAadBytes(new byte[1], 1, 1);
                Assert.Fail("input for ProcessAadBytes is too short");
            }
            catch (DataLengthException)
            {
                //expected
            }
            try
            {
                sparkle.ProcessBytes(new byte[1], 1, 1, c1, 0);
                Assert.Fail("input for ProcessBytes is too short");
            }
            catch (DataLengthException)
            {
                //expected
            }
            try
            {
                sparkle.DoFinal(new byte[2], 2);
                Assert.Fail("output for DoFinal is too short");
            }
            catch (OutputLengthException)
            {
                //expected
            }

            ImplTestExceptionsGetUpdateOutputSize(sparkle, false, param, 100);
            ImplTestExceptionsGetUpdateOutputSize(sparkle, true, param, 100);

            mac1 = new byte[sparkle.GetOutputSize(0)];
            mac2 = new byte[sparkle.GetOutputSize(0)];

            // TODO Maybe use a different IV for this
            sparkle.Init(true, param);
            sparkle.ProcessAadBytes(new byte[2], 0, 2);
            sparkle.DoFinal(mac1, 0);

            // TODO Maybe use a different IV for this
            sparkle.Init(true, param);
            sparkle.ProcessAadByte(0x00);
            sparkle.ProcessAadByte(0x00);
            sparkle.DoFinal(mac2, 0);

            if (!Arrays.AreEqual(mac1, mac2))
            {
                Assert.Fail("mac should match for the same AAD with different ways of inputting");
            }

            byte[] aad2 = { 0, 1, 2, 3, 4 };
            byte[] aad3 = { 0, 0, 1, 2, 3, 4, 5 };
            byte[] m2 = { 0, 1, 2, 3, 4, 5, 6, 7, 8, 9 };
            byte[] m3 = { 0, 0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10 };
            byte[] m4 = new byte[m2.Length];
            byte[] c2 = new byte[sparkle.GetOutputSize(m2.Length)];
            byte[] c3 = new byte[sparkle.GetOutputSize(m3.Length)];

            // TODO Maybe use a different IV for this
            sparkle.Init(true, param);
            sparkle.ProcessAadBytes(aad2, 0, aad2.Length);
            offset = sparkle.ProcessBytes(m2, 0, m2.Length, c2, 0);
            sparkle.DoFinal(c2, offset);

            // TODO Maybe use a different IV for this
            sparkle.Init(true, param);
            sparkle.ProcessAadBytes(aad3, 1, aad2.Length);
            offset = sparkle.ProcessBytes(m3, 1, m2.Length, c3, 1);
            sparkle.DoFinal(c3, offset + 1);

            byte[] c3_partial = new byte[c2.Length];
            Array.Copy(c3, 1, c3_partial, 0, c2.Length);
            if (!Arrays.AreEqual(c2, c3_partial))
            {
                Assert.Fail("mac should match for the same AAD and message with different offset for both input and output");
            }

            sparkle.Init(false, param);
            sparkle.ProcessAadBytes(aad2, 0, aad2.Length);
            offset = sparkle.ProcessBytes(c2, 0, c2.Length, m4, 0);
            sparkle.DoFinal(m4, offset);
            if (!Arrays.AreEqual(m2, m4))
            {
                Assert.Fail("The encryption and decryption does not recover the plaintext");
            }

            c2[c2.Length - 1] ^= 1;

            sparkle.ProcessAadBytes(aad2, 0, aad2.Length);
            offset = sparkle.ProcessBytes(c2, 0, c2.Length, m4, 0);
            try
            {
                sparkle.DoFinal(m4, offset);
                Assert.Fail("The decryption should fail");
            }
            catch (InvalidCipherTextException)
            {
                //expected;
            }
            c2[c2.Length - 1] ^= 1;

            byte[] m7 = new byte[32 + rand.Next(32)];
            rand.NextBytes(m7);

            // TODO Maybe use a different IV for this
            sparkle.Init(true, param);
            byte[] c7 = new byte[sparkle.GetOutputSize(m7.Length)];
            byte[] c8 = new byte[c7.Length];
            byte[] c9 = new byte[c7.Length];
            sparkle.Init(true, param);
            sparkle.ProcessAadBytes(aad2, 0, aad2.Length);
            offset = sparkle.ProcessBytes(m7, 0, m7.Length, c7, 0);
            sparkle.DoFinal(c7, offset);

            // TODO Maybe use a different IV for this
            sparkle.Init(true, param);
            sparkle.ProcessAadBytes(aad2, 0, aad2.Length);
            offset = sparkle.ProcessBytes(m7, 0, m7.Length / 2, c8, 0);
            offset += sparkle.ProcessBytes(m7, m7.Length / 2, m7.Length - m7.Length / 2, c8, offset);
            offset += sparkle.DoFinal(c8, offset);

            // TODO Maybe use a different IV for this
            sparkle.Init(true, param);
            int split = rand.Next(1, m7.Length);
            sparkle.ProcessAadBytes(aad2, 0, aad2.Length);
            offset = sparkle.ProcessBytes(m7, 0, split, c9, 0);
            offset += sparkle.ProcessBytes(m7, split, m7.Length - split, c9, offset);
            offset += sparkle.DoFinal(c9, offset);
            if (!Arrays.AreEqual(c7, c8) || !Arrays.AreEqual(c7, c9))
            {
                Assert.Fail("Splitting input of plaintext should output the same ciphertext");
            }

            // NOTE: .NET Core 3.1 has Span<T>, but is tested against our .NET Standard 2.0 assembly.
//#if NETCOREAPP2_1_OR_GREATER || NETSTANDARD2_1_OR_GREATER
#if NET6_0_OR_GREATER || NETSTANDARD2_1_OR_GREATER
            // TODO Maybe use a different IV for this
            sparkle.Init(true, param);
            Span<byte> c4 = new byte[sparkle.GetOutputSize(m2.Length)];
            sparkle.ProcessAadBytes(aad2);
            offset = sparkle.ProcessBytes(m2, c4);
            offset += sparkle.DoFinal(c4[offset..]);
            if (!c4[..offset].SequenceEqual(c2))
            {
                Assert.Fail("Encryption should match for the same AAD and message with/without Span-based API");
            }

            sparkle.Init(false, param);
            Span<byte> m6 = new byte[m2.Length];
            sparkle.ProcessAadBytes(aad2);
            offset = sparkle.ProcessBytes(c2, m6);
            offset += sparkle.DoFinal(m6[offset..]);
            if (!m6[..offset].SequenceEqual(m2))
            {
                Assert.Fail("Decryption should match for the same AAD and message with/without Span-based API");
            }
#endif
        }

        private static void ImplTestExceptionsGetUpdateOutputSize(SparkleEngine sparkle, bool forEncryption,
            ICipherParameters parameters, int maxInputSize)
        {
            // TODO Maybe use a different IV for this
            sparkle.Init(forEncryption, parameters);

            int maxOutputSize = sparkle.GetUpdateOutputSize(maxInputSize);

            byte[] input = new byte[maxInputSize];
            byte[] output = new byte[maxOutputSize];

            for (int inputSize = 0; inputSize <= maxInputSize; ++inputSize)
            {
                // TODO Maybe use a different IV for this
                sparkle.Init(forEncryption, parameters);

                int outputSize = sparkle.GetUpdateOutputSize(inputSize);
                if (outputSize > 0)
                {
                    try
                    {
                        sparkle.ProcessBytes(input, 0, inputSize, output, maxOutputSize - outputSize + 1);
                        Assert.Fail("output for ProcessBytes is too short");
                    }
                    catch (OutputLengthException)
                    {
                        //expected
                    }
                }
                else
                {
                    sparkle.ProcessBytes(input, 0, inputSize, null, 0);
                }
            }
        }

        private static void ImplTestParametersDigest(SparkleDigest.SparkleParameters sparkleParameters, int digestSize)
        {
            var sparkle = CreateDigest(sparkleParameters);

            Assert.AreEqual(digestSize, sparkle.GetDigestSize(),
                sparkle.AlgorithmName + ": GetDigestSize() is not correct");
        }

        private static void ImplTestParametersEngine(SparkleEngine.SparkleParameters sparkleParameters, int keySize,
            int ivSize, int macSize)
        {
            var sparkle = CreateEngine(sparkleParameters);

            Assert.AreEqual(keySize, sparkle.GetKeyBytesSize(),
                "key bytes of " + sparkle.AlgorithmName + " is not correct");
            Assert.AreEqual(ivSize, sparkle.GetIVBytesSize(),
                "iv bytes of " + sparkle.AlgorithmName + " is not correct");

            var parameters = new ParametersWithIV(new KeyParameter(new byte[keySize]), new byte[ivSize]);

            sparkle.Init(true, parameters);
            Assert.AreEqual(macSize, sparkle.GetOutputSize(0),
                "GetOutputSize of " + sparkle.AlgorithmName + " is incorrect for encryption");

            sparkle.Init(false, parameters);
            Assert.AreEqual(0, sparkle.GetOutputSize(macSize),
                "GetOutputSize of " + sparkle.AlgorithmName + " is incorrect for decryption");
        }

        private static void ImplTestVectorsDigest(SparkleDigest.SparkleParameters sparkleParameters, string filename)
        {
            Random random = new Random();
            var sparkle = CreateDigest(sparkleParameters);
            var buf = new Dictionary<string, string>();
            using (var src = new StreamReader(
                SimpleTest.GetTestDataAsStream("crypto.sparkle.LWC_HASH_KAT_" + filename + ".txt")))
            {
                string line;
                while ((line = src.ReadLine()) != null)
                {
                    int a = line.IndexOf('=');
                    if (a < 0)
                    {
                        byte[] ptByte = Hex.Decode(buf["Msg"]);
                        byte[] expected = Hex.Decode(buf["MD"]);
                        buf.Clear();

                        byte[] hash = new byte[sparkle.GetDigestSize()];

                        sparkle.BlockUpdate(ptByte, 0, ptByte.Length);
                        sparkle.DoFinal(hash, 0);
                        Assert.IsTrue(Arrays.AreEqual(expected, hash));

                        if (ptByte.Length > 1)
                        {
                            int split = random.Next(1, ptByte.Length - 1);
                            sparkle.BlockUpdate(ptByte, 0, split);
                            sparkle.BlockUpdate(ptByte, split, ptByte.Length - split);
                            sparkle.DoFinal(hash, 0);
                            Assert.IsTrue(Arrays.AreEqual(expected, hash));
                        }
                    }
                    else
                    {
                        buf[line.Substring(0, a).Trim()] = line.Substring(a + 1).Trim();
                    }
                }
            }
        }

        private static void ImplTestVectorsEngine(SparkleEngine.SparkleParameters sparkleParameters, string filename)
        {
            Random random = new Random();
            var sparkle = CreateEngine(sparkleParameters);
            var buf = new Dictionary<string, string>();
            using (var src = new StreamReader(
                SimpleTest.GetTestDataAsStream("crypto.sparkle.LWC_AEAD_KAT_" + filename + ".txt")))
            {
                string line;
                while ((line = src.ReadLine()) != null)
                {
                    var data = line.Split(' ');
                    if (data.Length == 1)
                    {
                        byte[] key = Hex.Decode(buf["Key"]);
                        byte[] nonce = Hex.Decode(buf["Nonce"]);
                        byte[] ad = Hex.Decode(buf["AD"]);
                        byte[] pt = Hex.Decode(buf["PT"]);
                        byte[] ct = Hex.Decode(buf["CT"]);
                        buf.Clear();

                        var parameters = new ParametersWithIV(new KeyParameter(key), nonce);

                        // Encrypt
                        {
                            sparkle.Init(true, parameters);

                            var rv = new byte[sparkle.GetOutputSize(pt.Length)];
                            random.NextBytes(rv); // should overwrite any existing data

                            sparkle.ProcessAadBytes(ad, 0, ad.Length);
                            int len = sparkle.ProcessBytes(pt, 0, pt.Length, rv, 0);
                            len += sparkle.DoFinal(rv, len);

                            Assert.True(Arrays.AreEqual(rv, 0, len, ct, 0, ct.Length));
                        }

                        // Decrypt
                        {
                            sparkle.Init(false, parameters);

                            var rv = new byte[sparkle.GetOutputSize(ct.Length)];
                            random.NextBytes(rv); // should overwrite any existing data

                            sparkle.ProcessAadBytes(ad, 0, ad.Length);
                            int len = sparkle.ProcessBytes(ct, 0, ct.Length, rv, 0);
                            len += sparkle.DoFinal(rv, len);

                            Assert.True(Arrays.AreEqual(rv, 0, len, pt, 0, pt.Length));
                        }
                    }
                    else
                    {
                        if (data.Length >= 3)
                        {
                            buf[data[0].Trim()] = data[2].Trim();
                        }
                        else
                        {
                            buf[data[0].Trim()] = "";
                        }

                    }
                }
            }
        }

        private static void InitEngine(SparkleEngine sparkle, bool forEncryption)
        {
            int keySize = sparkle.GetKeyBytesSize();
            int ivSize = sparkle.GetIVBytesSize();
            int macSize = keySize * 8;

            var parameters = new AeadParameters(new KeyParameter(new byte[keySize]), macSize, new byte[ivSize], null);
            sparkle.Init(forEncryption, parameters);
        }
    }
}
