using System;
using System.Collections.Generic;
using System.IO;

using NUnit.Framework;

using Org.BouncyCastle.Crypto.Digests;
using Org.BouncyCastle.Crypto.Engines;
using Org.BouncyCastle.Crypto.Modes;
using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.Utilities;
using Org.BouncyCastle.Utilities.Encoders;
using Org.BouncyCastle.Utilities.Test;

namespace Org.BouncyCastle.Crypto.Tests
{
    [TestFixture]
    public class SparkleTest
        : SimpleTest
    {
        public override string Name => "Sparkle";

        [Test]
        public override void PerformTest()
        {
            SparkleEngine sparkleEngine = new SparkleEngine(SparkleEngine.SparkleParameters.SCHWAEMM128_128);
            ImplTestExceptions(sparkleEngine);
            ImplTestParameters(sparkleEngine, 16, 16, 16, 16);
            sparkleEngine = new SparkleEngine(SparkleEngine.SparkleParameters.SCHWAEMM192_192);
            ImplTestExceptions(sparkleEngine);
            ImplTestParameters(sparkleEngine, 24, 24, 24, 24);
            sparkleEngine = new SparkleEngine(SparkleEngine.SparkleParameters.SCHWAEMM256_128);
            ImplTestExceptions(sparkleEngine);
            ImplTestParameters(sparkleEngine, 16, 32, 16, 32);
            sparkleEngine = new SparkleEngine(SparkleEngine.SparkleParameters.SCHWAEMM256_256);
            ImplTestExceptions(sparkleEngine);
            ImplTestParameters(sparkleEngine, 32, 32, 32, 32);
            ImplTestExceptions(new SparkleDigest(SparkleDigest.SparkleParameters.ESCH256), 32);
            ImplTestExceptions(new SparkleDigest(SparkleDigest.SparkleParameters.ESCH384), 48);
            ImplTestVectors("128_128", SparkleEngine.SparkleParameters.SCHWAEMM128_128);
            ImplTestVectors("192_192", SparkleEngine.SparkleParameters.SCHWAEMM192_192);
            ImplTestVectors("128_256", SparkleEngine.SparkleParameters.SCHWAEMM256_128);
            ImplTestVectors("256_256", SparkleEngine.SparkleParameters.SCHWAEMM256_256);
            ImplTestVectors("256", SparkleDigest.SparkleParameters.ESCH256);
            ImplTestVectors("384", SparkleDigest.SparkleParameters.ESCH384);
        }

        private void ImplTestVectors(string filename, SparkleEngine.SparkleParameters SparkleType)
        {
            SparkleEngine Sparkle = new SparkleEngine(SparkleType);
            ICipherParameters param;
            var buf = new Dictionary<string, string>();
            using (var src = new StreamReader(SimpleTest.GetTestDataAsStream("crypto.sparkle.LWC_AEAD_KAT_" + filename + ".txt")))
            {
                Dictionary<string, string> map = new Dictionary<string, string>();
                string line;
                while ((line = src.ReadLine()) != null)
                {
                    var data = line.Split(' ');
                    if (data.Length == 1)
                    {
                        //if (!map["Count"].Equals("562"))
                        //{
                        //    continue;
                        //}
                        byte[] key = Hex.Decode(map["Key"]);
                        byte[] nonce = Hex.Decode(map["Nonce"]);
                        byte[] ad = Hex.Decode(map["AD"]);
                        byte[] pt = Hex.Decode(map["PT"]);
                        byte[] ct = Hex.Decode(map["CT"]);
                        param = new ParametersWithIV(new KeyParameter(key), nonce);
                        Sparkle.Init(true, param);
                        Sparkle.ProcessAadBytes(ad, 0, ad.Length);
                        byte[] rv = new byte[Sparkle.GetOutputSize(pt.Length)];
                        int len = Sparkle.ProcessBytes(pt, 0, pt.Length, rv, 0);
                        Sparkle.DoFinal(rv, len);
                        Assert.True(Arrays.AreEqual(rv, ct));
                        Sparkle.Reset();
                        Sparkle.Init(false, param);
                        //Decrypt
                        Sparkle.ProcessAadBytes(ad, 0, ad.Length);
                        rv = new byte[pt.Length + 16];
                        len = Sparkle.ProcessBytes(ct, 0, ct.Length, rv, 0);
                        Sparkle.DoFinal(rv, len);
                        byte[] pt_recovered = new byte[pt.Length];
                        Array.Copy(rv, 0, pt_recovered, 0, pt.Length);
                        Assert.True(Arrays.AreEqual(pt, pt_recovered));
                        map.Clear();
                        Sparkle.Reset();

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

        private void ImplTestVectors(String filename, SparkleDigest.SparkleParameters SparkleType)
        {
            SparkleDigest Sparkle = new SparkleDigest(SparkleType);
            var buf = new Dictionary<string, string>();
            //TestSampler sampler = new TestSampler();
            using (var src = new StreamReader(SimpleTest.GetTestDataAsStream("crypto.sparkle.LWC_HASH_KAT_" + filename + ".txt")))
            {
                Dictionary<string, string> map = new Dictionary<string, string>();
                string line;
                while ((line = src.ReadLine()) != null)
                {
                    var data = line.Split(' ');
                    if (data.Length == 1)
                    {
                       var ptByte = Hex.Decode(map["Msg"]);
                        Sparkle.BlockUpdate(ptByte, 0, ptByte.Length);
                        byte[] hash = new byte[Sparkle.GetDigestSize()];
                        Sparkle.DoFinal(hash, 0);
                        Assert.True(Arrays.AreEqual(hash, Hex.Decode(map["MD"])));
                        map.Clear();
                        Sparkle.Reset();
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

        private void ImplTestExceptions(SparkleEngine sparkleEngine)
        {
            int blocksize = sparkleEngine.GetBlockSize();
            int keysize = sparkleEngine.GetKeyBytesSize(), ivsize = sparkleEngine.GetIVBytesSize();
            byte[] k = new byte[keysize];
            byte[] iv = new byte[ivsize];
            byte[] m = new byte[0];
            byte[] c1 = new byte[sparkleEngine.GetOutputSize(m.Length)];
            var param = new ParametersWithIV(new KeyParameter(k), iv);
            try
            {
                sparkleEngine.ProcessBytes(m, 0, m.Length, c1, 0);
                Assert.Fail(sparkleEngine.AlgorithmName + " needs to be initialized before ProcessBytes");
            }
            catch (ArgumentException)
            {
                //expected
            }

            try
            {
                sparkleEngine.ProcessByte((byte)0, c1, 0);
                Assert.Fail(sparkleEngine.AlgorithmName + " needs to be initialized before ProcessByte");
            }
            catch (ArgumentException)
            {
                //expected
            }

            try
            {
                sparkleEngine.Reset();
                Assert.Fail(sparkleEngine.AlgorithmName + " needs to be initialized before Reset");
            }
            catch (ArgumentException)
            {
                //expected
            }

            try
            {
                sparkleEngine.DoFinal(c1, m.Length);
                Assert.Fail(sparkleEngine.AlgorithmName + " needs to be initialized before DoFinal");
            }
            catch (ArgumentException)
            {
                //expected
            }

            try
            {
                sparkleEngine.GetMac();
                sparkleEngine.GetOutputSize(0);
                sparkleEngine.GetUpdateOutputSize(0);
            }
            catch (ArgumentException)
            {
                //expected
                Assert.Fail(sparkleEngine.AlgorithmName + " functions can be called before initialization");
            }
            Random rand = new Random();
            int randomNum;
            while ((randomNum = rand.Next(100)) == keysize) ;
            byte[] k1 = new byte[randomNum];
            while ((randomNum = rand.Next(100)) == ivsize) ;
            byte[] iv1 = new byte[randomNum];
            try
            {
                sparkleEngine.Init(true, new ParametersWithIV(new KeyParameter(k1), iv));
                Assert.Fail(sparkleEngine.AlgorithmName + " k size does not match");
            }
            catch (ArgumentException)
            {
                //expected
            }
            try
            {
                sparkleEngine.Init(true, new ParametersWithIV(new KeyParameter(k), iv1));
                Assert.Fail(sparkleEngine.AlgorithmName + "iv size does not match");
            }
            catch (ArgumentException)
            {
                //expected
            }


            sparkleEngine.Init(true, param);
            try
            {
                sparkleEngine.DoFinal(c1, m.Length);
            }
            catch (Exception)
            {
                Assert.Fail(sparkleEngine.AlgorithmName + " allows no input for AAD and plaintext");
            }
            byte[] mac2 = sparkleEngine.GetMac();
            if (mac2 == null)
            {
                Assert.Fail("mac should not be empty after DoFinal");
            }
            if (!Arrays.AreEqual(mac2, c1))
            {
                Assert.Fail("mac should be equal when calling DoFinal and GetMac");
            }
            sparkleEngine.ProcessAadByte((byte)0);
            byte[] mac1 = new byte[sparkleEngine.GetOutputSize(0)];
            sparkleEngine.DoFinal(mac1, 0);
            if (Arrays.AreEqual(mac1, mac2))
            {
                Assert.Fail("mac should not match");
            }
            sparkleEngine.Reset();
            sparkleEngine.ProcessBytes(new byte[blocksize+1], 0, blocksize+1, new byte[blocksize+1], 0);
            try
            {
                sparkleEngine.ProcessAadByte((byte)0);
                Assert.Fail("ProcessAadByte(s) cannot be called after encryption/decryption");
            }
            catch (ArgumentException)
            {
                //expected
            }
            try
            {
                sparkleEngine.ProcessAadBytes(new byte[] { 0 }, 0, 1);
                Assert.Fail("ProcessAadByte(s) cannot be called once only");
            }
            catch (ArgumentException)
            {
                //expected
            }

            sparkleEngine.Reset();
            try
            {
                sparkleEngine.ProcessAadBytes(new byte[] { 0 }, 1, 1);
                Assert.Fail("input for ProcessAadBytes is too short");
            }
            catch (DataLengthException)
            {
                //expected
            }
            try
            {
                sparkleEngine.ProcessBytes(new byte[] { 0 }, 1, 1, c1, 0);
                Assert.Fail("input for ProcessBytes is too short");
            }
            catch (DataLengthException)
            {
                //expected
            }
            try
            {
                sparkleEngine.ProcessBytes(new byte[blocksize+1], 0, blocksize+1, new byte[blocksize+1], blocksize >> 1);
                Assert.Fail("output for ProcessBytes is too short");
            }
            catch (OutputLengthException)
            {
                //expected
            }
            try
            {
                sparkleEngine.DoFinal(new byte[2], 2);
                Assert.Fail("output for DoFinal is too short");
            }
            catch (OutputLengthException)
            {
                //expected
            }

            mac1 = new byte[sparkleEngine.GetOutputSize(0)];
            mac2 = new byte[sparkleEngine.GetOutputSize(0)];
            sparkleEngine.Reset();
            sparkleEngine.ProcessAadBytes(new byte[] { 0, 0 }, 0, 2);
            sparkleEngine.DoFinal(mac1, 0);
            sparkleEngine.Reset();
            sparkleEngine.ProcessAadByte((byte)0);
            sparkleEngine.ProcessAadByte((byte)0);
            sparkleEngine.DoFinal(mac2, 0);
            if (!Arrays.AreEqual(mac1, mac2))
            {
                Assert.Fail("mac should match for the same AAD with different ways of inputing");
            }

            byte[] c2 = new byte[sparkleEngine.GetOutputSize(10)];
            byte[] c3 = new byte[sparkleEngine.GetOutputSize(10) + 2];
            byte[] aad2 = { 0, 1, 2, 3, 4 };
            byte[] aad3 = { 0, 0, 1, 2, 3, 4, 5 };
            byte[] m2 = { 0, 1, 2, 3, 4, 5, 6, 7, 8, 9 };
            byte[] m3 = { 0, 0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10 };
            byte[] m4 = new byte[m2.Length];
            sparkleEngine.Reset();
            sparkleEngine.ProcessAadBytes(aad2, 0, aad2.Length);
            int offset = sparkleEngine.ProcessBytes(m2, 0, m2.Length, c2, 0);
            sparkleEngine.DoFinal(c2, offset);
            sparkleEngine.Reset();
            sparkleEngine.ProcessAadBytes(aad3, 1, aad2.Length);
            offset = sparkleEngine.ProcessBytes(m3, 1, m2.Length, c3, 1);
            sparkleEngine.DoFinal(c3, offset + 1);
            byte[] c3_partial = new byte[c2.Length];
            Array.Copy(c3, 1, c3_partial, 0, c2.Length);
            if (!Arrays.AreEqual(c2, c3_partial))
            {
                Assert.Fail("mac should match for the same AAD and message with different offset for both input and output");
            }
            sparkleEngine.Reset();
            sparkleEngine.Init(false, param);
            sparkleEngine.ProcessAadBytes(aad2, 0, aad2.Length);
            offset = sparkleEngine.ProcessBytes(c2, 0, c2.Length, m4, 0);
            sparkleEngine.DoFinal(m4, offset);
            if (!Arrays.AreEqual(m2, m4))
            {
                Assert.Fail("The encryption and decryption does not recover the plaintext");
            }
            c2[c2.Length - 1] ^= 1;
            sparkleEngine.Reset();
            sparkleEngine.Init(false, param);
            sparkleEngine.ProcessAadBytes(aad2, 0, aad2.Length);
            offset = sparkleEngine.ProcessBytes(c2, 0, c2.Length, m4, 0);
            try
            {
                sparkleEngine.DoFinal(m4, offset);
                Assert.Fail("The decryption should fail");
            }
            catch (InvalidCipherTextException)
            {
                //expected;
            }
            c2[c2.Length - 1] ^= 1;

            byte[] m7 = new byte[blocksize * 2];
            for (int i = 0; i < m7.Length; ++i)
            {
                m7[i] = (byte)rand.Next();
            }
            byte[] c7 = new byte[sparkleEngine.GetOutputSize(m7.Length)];
            byte[] c8 = new byte[c7.Length];
            byte[] c9 = new byte[c7.Length];
            sparkleEngine.Init(true, param);
            sparkleEngine.ProcessAadBytes(aad2, 0, aad2.Length);
            offset = sparkleEngine.ProcessBytes(m7, 0, m7.Length, c7, 0);
            sparkleEngine.DoFinal(c7, offset);
            sparkleEngine.Reset();
            sparkleEngine.ProcessAadBytes(aad2, 0, aad2.Length);
            offset = sparkleEngine.ProcessBytes(m7, 0, blocksize, c8, 0);
            offset += sparkleEngine.ProcessBytes(m7, blocksize, m7.Length - blocksize, c8, offset);
            sparkleEngine.DoFinal(c8, offset);
            sparkleEngine.Reset();
            int split = rand.Next(blocksize * 2);
            sparkleEngine.ProcessAadBytes(aad2, 0, aad2.Length);
            offset = sparkleEngine.ProcessBytes(m7, 0, split, c9, 0);
            offset += sparkleEngine.ProcessBytes(m7, split, m7.Length - split, c9, offset);
            sparkleEngine.DoFinal(c9, offset);
            if (!Arrays.AreEqual(c7, c8) || !Arrays.AreEqual(c7, c9))
            {
                Assert.Fail("Splitting input of plaintext should output the same ciphertext");
            }
#if NET6_0_OR_GREATER || NETSTANDARD2_1_OR_GREATER
            Span<byte> c4_1 = new byte[c2.Length];
            Span<byte> c4_2 = new byte[c2.Length];
            ReadOnlySpan<byte> m5 = new ReadOnlySpan<byte>(m2);
            ReadOnlySpan<byte> aad4 = new ReadOnlySpan<byte>(aad2);
            sparkleEngine.Init(true, param);
            sparkleEngine.ProcessAadBytes(aad4);
            offset = sparkleEngine.ProcessBytes(m5, c4_1);
            sparkleEngine.DoFinal(c4_2);
            byte[] c5 = new byte[c2.Length];
            Array.Copy(c4_1.ToArray(), 0, c5, 0, offset);
            Array.Copy(c4_2.ToArray(), 0, c5, offset, c5.Length - offset);
            if (!Arrays.AreEqual(c2, c5))
            {
                Assert.Fail("mac should match for the same AAD and message with different offset for both input and output");
            }
            sparkleEngine.Reset();
            sparkleEngine.Init(false, param);
            Span<byte> m6_1 = new byte[m2.Length];
            Span<byte> m6_2 = new byte[m2.Length];
            ReadOnlySpan<byte> c6 = new ReadOnlySpan<byte>(c2);
            sparkleEngine.ProcessAadBytes(aad4);
            offset = sparkleEngine.ProcessBytes(c6, m6_1);
            sparkleEngine.DoFinal(m6_2);
            byte[] m6 = new byte[m2.Length];
            Array.Copy(m6_1.ToArray(), 0, m6, 0, offset);
            Array.Copy(m6_2.ToArray(), 0, m6, offset, m6.Length - offset);
            if (!Arrays.AreEqual(m2, m6))
            {
                Assert.Fail("mac should match for the same AAD and message with different offset for both input and output");
            }
#endif
        }

        private void ImplTestParameters(SparkleEngine sparkleEngine, int keySize, int ivSize, int macSize, int blockSize)
        {
            if (sparkleEngine.GetKeyBytesSize() != keySize)
            {
                Assert.Fail("key bytes of " + sparkleEngine.AlgorithmName + " is not correct");
            }
            if (sparkleEngine.GetIVBytesSize() != ivSize)
            {
                Assert.Fail("iv bytes of " + sparkleEngine.AlgorithmName + " is not correct");
            }
            if (sparkleEngine.GetOutputSize(0) != macSize)
            {
                Assert.Fail("mac bytes of " + sparkleEngine.AlgorithmName + " is not correct");
            }
            if (sparkleEngine.GetBlockSize() != blockSize)
            {
                Assert.Fail("block size of " + sparkleEngine.AlgorithmName + " is not correct");
            }
        }

        private void ImplTestExceptions(SparkleDigest sparkleDigest, int digestsize)
        {
            if (sparkleDigest.GetDigestSize() != digestsize)
            {
                Assert.Fail(sparkleDigest.AlgorithmName + ": digest size is not correct");
            }

            try
            {
                sparkleDigest.BlockUpdate(new byte[1], 1, 1);
                Assert.Fail(sparkleDigest.AlgorithmName + ": input for BlockUpdate is too short");
            }
            catch (DataLengthException)
            {
                //expected
            }
            try
            {
                sparkleDigest.DoFinal(new byte[sparkleDigest.GetDigestSize() - 1], 2);
                Assert.Fail(sparkleDigest.AlgorithmName + ": output for DoFinal is too short");
            }
            catch (OutputLengthException)
            {
                //expected
            }
        }
    }
}
