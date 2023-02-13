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
    public class XoodyakTest
        : SimpleTest
    {
        public override string Name => "Xoodyak";

        [Test]
        public override void PerformTest()
        {
            ImplTestVectorsHash();
            ImplTestVectors();
            XoodyakEngine xoodyakEngine = new XoodyakEngine();
            ImplTestExceptions(xoodyakEngine, xoodyakEngine.GetKeyBytesSize(), xoodyakEngine.GetIVBytesSize(), xoodyakEngine.GetBlockSize());
            ImplTestParameters(xoodyakEngine, 16, 16, 16, 24);
            ImplTestExceptions(new XoodyakDigest(), 32);
        }

        private void ImplTestVectors()
        {
            XoodyakEngine xoodyak = new XoodyakEngine();
            var buf = new Dictionary<string, string>();
            using (var src = new StreamReader(SimpleTest.GetTestDataAsStream("crypto.xoodyak.LWC_AEAD_KAT_128_128.txt")))
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

                        var param = new ParametersWithIV(new KeyParameter(key), nonce);
                        xoodyak.Init(true, param);
                        xoodyak.ProcessAadBytes(ad, 0, ad.Length);
                        byte[] rv = new byte[xoodyak.GetOutputSize(pt.Length)];
                        int len = xoodyak.ProcessBytes(pt, 0, pt.Length, rv, 0);
                        xoodyak.DoFinal(rv, len);
                        Assert.True(Arrays.AreEqual(rv, ct));
                        xoodyak.Reset();
                        xoodyak.Init(false, param);
                        //Decrypt
                        xoodyak.ProcessAadBytes(ad, 0, ad.Length);
                        rv = new byte[pt.Length + 16];
                        len = xoodyak.ProcessBytes(ct, 0, ct.Length, rv, 0);
                        xoodyak.DoFinal(rv, len);
                        byte[] pt_recovered = new byte[pt.Length];
                        Array.Copy(rv, 0, pt_recovered, 0, pt.Length);
                        Assert.True(Arrays.AreEqual(pt, pt_recovered));
                        xoodyak.Reset();
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
        private void ImplTestVectorsHash()
        {
            XoodyakDigest xoodyak = new XoodyakDigest();
            var buf = new Dictionary<string, string>();
            //TestSampler sampler = new TestSampler();
            using (var src = new StreamReader(SimpleTest.GetTestDataAsStream("crypto.xoodyak.LWC_HASH_KAT_256.txt")))
            {
                Dictionary<string, string> map = new Dictionary<string, string>();
                string line;
                while ((line = src.ReadLine()) != null)
                {
                    var data = line.Split(' ');
                    if (data.Length == 1)
                    {
                        var ptByte = Hex.Decode(map["Msg"]);
                        xoodyak.BlockUpdate(ptByte, 0, ptByte.Length);
                        byte[] hash = new byte[32];
                        xoodyak.DoFinal(hash, 0);
                        Assert.True(Arrays.AreEqual(hash, Hex.Decode(map["MD"])));
                        map.Clear();
                        xoodyak.Reset();
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

        private void ImplTestExceptions(XoodyakEngine xoodyakEngine, int keysize, int ivsize, int blocksize)
        {
            byte[] k = new byte[keysize];
            byte[] iv = new byte[ivsize];
            byte[] m = new byte[0];
            byte[] c1 = new byte[xoodyakEngine.GetOutputSize(m.Length)];
            var param = new ParametersWithIV(new KeyParameter(k), iv);
            try
            {
                xoodyakEngine.ProcessBytes(m, 0, m.Length, c1, 0);
                Assert.Fail(xoodyakEngine.AlgorithmName + " needs to be initialized before ProcessBytes");
            }
            catch (ArgumentException)
            {
                //expected
            }

            try
            {
                xoodyakEngine.ProcessByte((byte)0, c1, 0);
                Assert.Fail(xoodyakEngine.AlgorithmName + " needs to be initialized before ProcessByte");
            }
            catch (ArgumentException)
            {
                //expected
            }

            try
            {
                xoodyakEngine.Reset();
                Assert.Fail(xoodyakEngine.AlgorithmName + " needs to be initialized before Reset");
            }
            catch (ArgumentException)
            {
                //expected
            }

            try
            {
                xoodyakEngine.DoFinal(c1, m.Length);
                Assert.Fail(xoodyakEngine.AlgorithmName + " needs to be initialized before DoFinal");
            }
            catch (ArgumentException)
            {
                //expected
            }

            try
            {
                xoodyakEngine.GetMac();
                xoodyakEngine.GetOutputSize(0);
                xoodyakEngine.GetUpdateOutputSize(0);
            }
            catch (ArgumentException)
            {
                //expected
                Assert.Fail(xoodyakEngine.AlgorithmName + " functions can be called before initialization");
            }
            Random rand = new Random();
            int randomNum;
            while ((randomNum = rand.Next(100)) == keysize) ;
            byte[] k1 = new byte[randomNum];
            while ((randomNum = rand.Next(100)) == ivsize) ;
            byte[] iv1 = new byte[randomNum];
            try
            {
                xoodyakEngine.Init(true, new ParametersWithIV(new KeyParameter(k1), iv));
                Assert.Fail(xoodyakEngine.AlgorithmName + " k size does not match");
            }
            catch (ArgumentException)
            {
                //expected
            }
            try
            {
                xoodyakEngine.Init(true, new ParametersWithIV(new KeyParameter(k), iv1));
                Assert.Fail(xoodyakEngine.AlgorithmName + "iv size does not match");
            }
            catch (ArgumentException)
            {
                //expected
            }


            xoodyakEngine.Init(true, param);
            try
            {
                xoodyakEngine.DoFinal(c1, m.Length);
            }
            catch (Exception)
            {
                Assert.Fail(xoodyakEngine.AlgorithmName + " allows no input for AAD and plaintext");
            }
            byte[] mac2 = xoodyakEngine.GetMac();
            if (mac2 == null)
            {
                Assert.Fail("mac should not be empty after DoFinal");
            }
            if (!Arrays.AreEqual(mac2, c1))
            {
                Assert.Fail("mac should be equal when calling DoFinal and GetMac");
            }
            xoodyakEngine.ProcessAadByte((byte)0);
            byte[] mac1 = new byte[xoodyakEngine.GetOutputSize(0)];
            xoodyakEngine.DoFinal(mac1, 0);
            if (Arrays.AreEqual(mac1, mac2))
            {
                Assert.Fail("mac should not match");
            }
            xoodyakEngine.Reset();
            xoodyakEngine.ProcessBytes(new byte[blocksize], 0, blocksize, new byte[blocksize], 0);
            try
            {
                xoodyakEngine.ProcessAadByte((byte)0);
                Assert.Fail("ProcessAadByte(s) cannot be called after encryption/decryption");
            }
            catch (ArgumentException)
            {
                //expected
            }
            try
            {
                xoodyakEngine.ProcessAadBytes(new byte[] { 0 }, 0, 1);
                Assert.Fail("ProcessAadByte(s) cannot be called once only");
            }
            catch (ArgumentException)
            {
                //expected
            }

            xoodyakEngine.Reset();
            try
            {
                xoodyakEngine.ProcessAadBytes(new byte[] { 0 }, 1, 1);
                Assert.Fail("input for ProcessAadBytes is too short");
            }
            catch (DataLengthException)
            {
                //expected
            }
            try
            {
                xoodyakEngine.ProcessBytes(new byte[] { 0 }, 1, 1, c1, 0);
                Assert.Fail("input for ProcessBytes is too short");
            }
            catch (DataLengthException)
            {
                //expected
            }
            try
            {
                xoodyakEngine.ProcessBytes(new byte[blocksize], 0, blocksize, new byte[blocksize], blocksize >> 1);
                Assert.Fail("output for ProcessBytes is too short");
            }
            catch (OutputLengthException)
            {
                //expected
            }
            try
            {
                xoodyakEngine.DoFinal(new byte[2], 2);
                Assert.Fail("output for DoFinal is too short");
            }
            catch (OutputLengthException)
            {
                //expected
            }

            mac1 = new byte[xoodyakEngine.GetOutputSize(0)];
            mac2 = new byte[xoodyakEngine.GetOutputSize(0)];
            xoodyakEngine.Reset();
            xoodyakEngine.ProcessAadBytes(new byte[] { 0, 0 }, 0, 2);
            xoodyakEngine.DoFinal(mac1, 0);
            xoodyakEngine.Reset();
            xoodyakEngine.ProcessAadByte((byte)0);
            xoodyakEngine.ProcessAadByte((byte)0);
            xoodyakEngine.DoFinal(mac2, 0);
            if (!Arrays.AreEqual(mac1, mac2))
            {
                Assert.Fail("mac should match for the same AAD with different ways of inputting");
            }

            byte[] c2 = new byte[xoodyakEngine.GetOutputSize(10)];
            byte[] c3 = new byte[xoodyakEngine.GetOutputSize(10) + 2];
            byte[] aad2 = { 0, 1, 2, 3, 4 };
            byte[] aad3 = { 0, 0, 1, 2, 3, 4, 5 };
            byte[] m2 = { 0, 1, 2, 3, 4, 5, 6, 7, 8, 9 };
            byte[] m3 = { 0, 0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10 };
            byte[] m4 = new byte[m2.Length];
            xoodyakEngine.Reset();
            xoodyakEngine.ProcessAadBytes(aad2, 0, aad2.Length);
            int offset = xoodyakEngine.ProcessBytes(m2, 0, m2.Length, c2, 0);
            xoodyakEngine.DoFinal(c2, offset);
            xoodyakEngine.Reset();
            xoodyakEngine.ProcessAadBytes(aad3, 1, aad2.Length);
            offset = xoodyakEngine.ProcessBytes(m3, 1, m2.Length, c3, 1);
            xoodyakEngine.DoFinal(c3, offset + 1);
            byte[] c3_partial = new byte[c2.Length];
            Array.Copy(c3, 1, c3_partial, 0, c2.Length);
            if (!Arrays.AreEqual(c2, c3_partial))
            {
                Assert.Fail("mac should match for the same AAD and message with different offset for both input and output");
            }
            xoodyakEngine.Reset();
            xoodyakEngine.Init(false, param);
            xoodyakEngine.ProcessAadBytes(aad2, 0, aad2.Length);
            offset = xoodyakEngine.ProcessBytes(c2, 0, c2.Length, m4, 0);
            xoodyakEngine.DoFinal(m4, offset);
            if (!Arrays.AreEqual(m2, m4))
            {
                Assert.Fail("The encryption and decryption does not recover the plaintext");
            }
            c2[c2.Length - 1] ^= 1;
            xoodyakEngine.Reset();
            xoodyakEngine.Init(false, param);
            xoodyakEngine.ProcessAadBytes(aad2, 0, aad2.Length);
            offset = xoodyakEngine.ProcessBytes(c2, 0, c2.Length, m4, 0);
            try
            {
                xoodyakEngine.DoFinal(m4, offset);
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
            byte[] c7 = new byte[xoodyakEngine.GetOutputSize(m7.Length)];
            byte[] c8 = new byte[c7.Length];
            byte[] c9 = new byte[c7.Length];
            xoodyakEngine.Init(true, param);
            xoodyakEngine.ProcessAadBytes(aad2, 0, aad2.Length);
            offset = xoodyakEngine.ProcessBytes(m7, 0, m7.Length, c7, 0);
            xoodyakEngine.DoFinal(c7, offset);
            xoodyakEngine.Reset();
            xoodyakEngine.ProcessAadBytes(aad2, 0, aad2.Length);
            offset = xoodyakEngine.ProcessBytes(m7, 0, blocksize, c8, 0);
            offset += xoodyakEngine.ProcessBytes(m7, blocksize, m7.Length - blocksize, c8, offset);
            xoodyakEngine.DoFinal(c8, offset);
            xoodyakEngine.Reset();
            int split = rand.Next(blocksize * 2);
            xoodyakEngine.ProcessAadBytes(aad2, 0, aad2.Length);
            offset = xoodyakEngine.ProcessBytes(m7, 0, split, c9, 0);
            offset += xoodyakEngine.ProcessBytes(m7, split, m7.Length - split, c9, offset);
            xoodyakEngine.DoFinal(c9, offset);
            if (!Arrays.AreEqual(c7, c8) || !Arrays.AreEqual(c7, c9))
            {
                Assert.Fail("Splitting input of plaintext should output the same ciphertext");
            }
#if NET6_0_OR_GREATER || NETSTANDARD2_1_OR_GREATER
            Span<byte> c4_1 = new byte[c2.Length];
            Span<byte> c4_2 = new byte[c2.Length];
            ReadOnlySpan<byte> m5 = new ReadOnlySpan<byte>(m2);
            ReadOnlySpan<byte> aad4 = new ReadOnlySpan<byte>(aad2);
            xoodyakEngine.Init(true, param);
            xoodyakEngine.ProcessAadBytes(aad4);
            offset = xoodyakEngine.ProcessBytes(m5, c4_1);
            xoodyakEngine.DoFinal(c4_2);
            byte[] c5 = new byte[c2.Length];
            c4_1[..offset].CopyTo(c5);
            c4_2[..(c5.Length - offset)].CopyTo(c5.AsSpan(offset));
            if (!Arrays.AreEqual(c2, c5))
            {
                Assert.Fail("mac should match for the same AAD and message with different offset for both input and output");
            }
            xoodyakEngine.Reset();
            xoodyakEngine.Init(false, param);
            Span<byte> m6_1 = new byte[m2.Length];
            Span<byte> m6_2 = new byte[m2.Length];
            ReadOnlySpan<byte> c6 = new ReadOnlySpan<byte>(c2);
            xoodyakEngine.ProcessAadBytes(aad4);
            offset = xoodyakEngine.ProcessBytes(c6, m6_1);
            xoodyakEngine.DoFinal(m6_2);
            byte[] m6 = new byte[m2.Length];
            m6_1[..offset].CopyTo(m6);
            m6_2[..(m6.Length - offset)].CopyTo(m6.AsSpan(offset));
            if (!Arrays.AreEqual(m2, m6))
            {
                Assert.Fail("mac should match for the same AAD and message with different offset for both input and output");
            }
#endif

        }

        private void ImplTestParameters(XoodyakEngine xoodyak, int keySize, int ivSize, int macSize, int blockSize)
        {
            if (xoodyak.GetKeyBytesSize() != keySize)
            {
                Assert.Fail("key bytes of " + xoodyak.AlgorithmName + " is not correct");
            }
            if (xoodyak.GetIVBytesSize() != ivSize)
            {
                Assert.Fail("iv bytes of " + xoodyak.AlgorithmName + " is not correct");
            }
            if (xoodyak.GetOutputSize(0) != macSize)
            {
                Assert.Fail("mac bytes of " + xoodyak.AlgorithmName + " is not correct");
            }
            if (xoodyak.GetBlockSize() != blockSize)
            {
                Assert.Fail("block size of " + xoodyak.AlgorithmName + " is not correct");
            }
        }

        private void ImplTestExceptions(XoodyakDigest xoodyakDigest, int digestsize)
        {
            if (xoodyakDigest.GetDigestSize() != digestsize)
            {
                Assert.Fail(xoodyakDigest.AlgorithmName + ": digest size is not correct");
            }

            try
            {
                xoodyakDigest.BlockUpdate(new byte[1], 1, 1);
                Assert.Fail(xoodyakDigest.AlgorithmName + ": input for BlockUpdate is too short");
            }
            catch (DataLengthException)
            {
                //expected
            }
            try
            {
                xoodyakDigest.DoFinal(new byte[xoodyakDigest.GetDigestSize() - 1], 2);
                Assert.Fail(xoodyakDigest.AlgorithmName + ": output for DoFinal is too short");
            }
            catch (OutputLengthException)
            {
                //expected
            }
        }
    }
}
