using System;
using NUnit.Framework;
using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.Utilities;
using Org.BouncyCastle.Utilities.Encoders;
using Org.BouncyCastle.Utilities.Test;
using System.Collections.Generic;
using System.IO;
using Org.BouncyCastle.Crypto.Engines;
using Org.BouncyCastle.Crypto.Digests;
using Org.BouncyCastle.Crypto.Modes;

namespace BouncyCastle.Crypto.Tests
{
    [TestFixture]
    public class XoodyakTest : SimpleTest
    {
        public override string Name
        {
            get { return "Xoodyak"; }
        }

        [Test]
        public override void PerformTest()
        {
            testVectorsHash();
            testVectors();
            XoodyakEngine xoodyak = new XoodyakEngine();
            testExceptions(xoodyak, xoodyak.GetKeyBytesSize(), xoodyak.GetIVBytesSize(), xoodyak.GetBlockSize());
            testParameters(xoodyak, 16, 16, 16, 24);
            testExceptions(new XoodyakDigest(), 32);
        }

        private void testVectors()
        {
            XoodyakEngine xoodyak = new XoodyakEngine();
            ICipherParameters param;
            var buf = new Dictionary<string, string>();
            //TestSampler sampler = new TestSampler();
            using (var src = new StreamReader(SimpleTest.GetTestDataAsStream("crypto.xoodyak.LWC_AEAD_KAT_128_128.txt")))
            {
                string line;
                string[] data;
                byte[] ptByte, adByte;
                byte[] rv;
                Dictionary<string, string> map = new Dictionary<string, string>();
                while ((line = src.ReadLine()) != null)
                {
                    data = line.Split(' ');
                    if (data.Length == 1)
                    {
                        byte[] key = Hex.Decode(map["Key"]);
                        byte[] nonce = Hex.Decode(map["Nonce"]);
                        byte[] ad = Hex.Decode(map["AD"]);
                        byte[] pt = Hex.Decode(map["PT"]);
                        byte[] ct = Hex.Decode(map["CT"]);
                        param = new ParametersWithIV(new KeyParameter(key), nonce);
                        xoodyak.Init(true, param);
                        xoodyak.ProcessAadBytes(ad, 0, ad.Length);
                        rv = new byte[xoodyak.GetOutputSize(pt.Length)];
                        int len = xoodyak.ProcessBytes(pt, 0, pt.Length, rv, 0);
                        //byte[] mac = new byte[16];
                        xoodyak.DoFinal(rv, len);
                        //foreach(byte b in Hex.Decode(map["CT"]))
                        //{
                        //    Console.Write(b.ToString("X2"));
                        //}
                        //Console.WriteLine();
                        //foreach (byte b in Arrays.Concatenate(rv, mac))
                        //{
                        //    Console.Write(b.ToString("X2"));
                        //}
                        //Console.WriteLine();
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
                        //Console.WriteLine(map["Count"] + " pass");
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
        private void testVectorsHash()
        {
            XoodyakDigest xoodyak = new XoodyakDigest();
            ICipherParameters param;
            var buf = new Dictionary<string, string>();
            //TestSampler sampler = new TestSampler();
            using (var src = new StreamReader(SimpleTest.GetTestDataAsStream("crypto.xoodyak.LWC_HASH_KAT_256.txt")))
            {
                string line;
                string[] data;
                byte[] ptByte, adByte;
                byte[] rv;
                Dictionary<string, string> map = new Dictionary<string, string>();
                while ((line = src.ReadLine()) != null)
                {
                    data = line.Split(' ');
                    if (data.Length == 1)
                    {
                        ptByte = Hex.Decode(map["Msg"]);
                        xoodyak.BlockUpdate(ptByte, 0, ptByte.Length);
                        byte[] hash = new byte[32];
                        xoodyak.DoFinal(hash, 0);
                        Assert.True(Arrays.AreEqual(hash, Hex.Decode(map["MD"])));
                        //Console.WriteLine(map["Count"] + " pass");
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

        private void testExceptions(IAeadBlockCipher aeadBlockCipher, int keysize, int ivsize, int blocksize)
        {
            ICipherParameters param;
            byte[] k = new byte[keysize];
            byte[] iv = new byte[ivsize];
            byte[] m = new byte[0];
            byte[] c1 = new byte[aeadBlockCipher.GetOutputSize(m.Length)];
            param = new ParametersWithIV(new KeyParameter(k), iv);
            try
            {
                aeadBlockCipher.ProcessBytes(m, 0, m.Length, c1, 0);
                Assert.Fail(aeadBlockCipher.AlgorithmName + " need to be initialed before ProcessBytes");
            }
            catch (ArgumentException e)
            {
                //expected
            }

            try
            {
                aeadBlockCipher.ProcessByte((byte)0, c1, 0);
                Assert.Fail(aeadBlockCipher.AlgorithmName + " need to be initialed before ProcessByte");
            }
            catch (ArgumentException e)
            {
                //expected
            }

            try
            {
                aeadBlockCipher.Reset();
                Assert.Fail(aeadBlockCipher.AlgorithmName + " need to be initialed before reset");
            }
            catch (ArgumentException e)
            {
                //expected
            }

            try
            {
                aeadBlockCipher.DoFinal(c1, m.Length);
                Assert.Fail(aeadBlockCipher.AlgorithmName + " need to be initialed before dofinal");
            }
            catch (ArgumentException e)
            {
                //expected
            }

            try
            {
                aeadBlockCipher.GetMac();
                aeadBlockCipher.GetOutputSize(0);
                aeadBlockCipher.GetUpdateOutputSize(0);
            }
            catch (ArgumentException e)
            {
                //expected
                Assert.Fail(aeadBlockCipher.AlgorithmName + " functions can be called before initialisation");
            }
            Random rand = new Random();
            int randomNum;
            while ((randomNum = rand.Next(100)) == keysize) ;
            byte[] k1 = new byte[randomNum];
            while ((randomNum = rand.Next(100)) == ivsize) ;
            byte[] iv1 = new byte[randomNum];
            try
            {
                aeadBlockCipher.Init(true, new ParametersWithIV(new KeyParameter(k1), iv));
                Assert.Fail(aeadBlockCipher.AlgorithmName + " k size does not match");
            }
            catch (ArgumentException e)
            {
                //expected
            }
            try
            {
                aeadBlockCipher.Init(true, new ParametersWithIV(new KeyParameter(k), iv1));
                Assert.Fail(aeadBlockCipher.AlgorithmName + "iv size does not match");
            }
            catch (ArgumentException e)
            {
                //expected
            }


            aeadBlockCipher.Init(true, param);
            try
            {
                aeadBlockCipher.DoFinal(c1, m.Length);
            }
            catch (Exception e)
            {
                Assert.Fail(aeadBlockCipher.AlgorithmName + " allows no input for AAD and plaintext");
            }
            byte[] mac2 = aeadBlockCipher.GetMac();
            if (mac2 == null)
            {
                Assert.Fail("mac should not be empty after dofinal");
            }
            if (!Arrays.AreEqual(mac2, c1))
            {
                Assert.Fail("mac should be equal when calling dofinal and getMac");
            }
            aeadBlockCipher.ProcessAadByte((byte)0);
            byte[] mac1 = new byte[aeadBlockCipher.GetOutputSize(0)];
            aeadBlockCipher.DoFinal(mac1, 0);
            if (Arrays.AreEqual(mac1, mac2))
            {
                Assert.Fail("mac should not match");
            }
            aeadBlockCipher.Reset();
            aeadBlockCipher.ProcessBytes(new byte[blocksize], 0, blocksize, new byte[blocksize], 0);
            try
            {
                aeadBlockCipher.ProcessAadByte((byte)0);
                Assert.Fail("ProcessAadByte(s) cannot be called after encryption/decryption");
            }
            catch (ArgumentException e)
            {
                //expected
            }
            try
            {
                aeadBlockCipher.ProcessAadBytes(new byte[] { 0 }, 0, 1);
                Assert.Fail("ProcessAadByte(s) cannot be called once only");
            }
            catch (ArgumentException e)
            {
                //expected
            }

            aeadBlockCipher.Reset();
            try
            {
                aeadBlockCipher.ProcessAadBytes(new byte[] { 0 }, 1, 1);
                Assert.Fail("input for ProcessAadBytes is too short");
            }
            catch (DataLengthException e)
            {
                //expected
            }
            try
            {
                aeadBlockCipher.ProcessBytes(new byte[] { 0 }, 1, 1, c1, 0);
                Assert.Fail("input for ProcessBytes is too short");
            }
            catch (DataLengthException e)
            {
                //expected
            }
            try
            {
                aeadBlockCipher.ProcessBytes(new byte[blocksize], 0, blocksize, new byte[blocksize], blocksize >> 1);
                Assert.Fail("output for ProcessBytes is too short");
            }
            catch (OutputLengthException e)
            {
                //expected
            }
            try
            {
                aeadBlockCipher.DoFinal(new byte[2], 2);
                Assert.Fail("output for dofinal is too short");
            }
            catch (DataLengthException e)
            {
                //expected
            }

            mac1 = new byte[aeadBlockCipher.GetOutputSize(0)];
            mac2 = new byte[aeadBlockCipher.GetOutputSize(0)];
            aeadBlockCipher.Reset();
            aeadBlockCipher.ProcessAadBytes(new byte[] { 0, 0 }, 0, 2);
            aeadBlockCipher.DoFinal(mac1, 0);
            aeadBlockCipher.Reset();
            aeadBlockCipher.ProcessAadByte((byte)0);
            aeadBlockCipher.ProcessAadByte((byte)0);
            aeadBlockCipher.DoFinal(mac2, 0);
            if (!Arrays.AreEqual(mac1, mac2))
            {
                Assert.Fail("mac should match for the same AAD with different ways of inputing");
            }

            byte[] c2 = new byte[aeadBlockCipher.GetOutputSize(10)];
            byte[] c3 = new byte[aeadBlockCipher.GetOutputSize(10) + 2];
            byte[] aad2 = { 0, 1, 2, 3, 4 };
            byte[] aad3 = { 0, 0, 1, 2, 3, 4, 5 };
            byte[] m2 = { 0, 1, 2, 3, 4, 5, 6, 7, 8, 9 };
            byte[] m3 = { 0, 0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10 };
            byte[] m4 = new byte[m2.Length];
            aeadBlockCipher.Reset();
            aeadBlockCipher.ProcessAadBytes(aad2, 0, aad2.Length);
            int offset = aeadBlockCipher.ProcessBytes(m2, 0, m2.Length, c2, 0);
            aeadBlockCipher.DoFinal(c2, offset);
            aeadBlockCipher.Reset();
            aeadBlockCipher.ProcessAadBytes(aad3, 1, aad2.Length);
            offset = aeadBlockCipher.ProcessBytes(m3, 1, m2.Length, c3, 1);
            aeadBlockCipher.DoFinal(c3, offset + 1);
            byte[] c3_partial = new byte[c2.Length];
            Array.Copy(c3, 1, c3_partial, 0, c2.Length);
            if (!Arrays.AreEqual(c2, c3_partial))
            {
                Assert.Fail("mac should match for the same AAD and message with different offset for both input and output");
            }
            aeadBlockCipher.Reset();
            aeadBlockCipher.Init(false, param);
            aeadBlockCipher.ProcessAadBytes(aad2, 0, aad2.Length);
            offset = aeadBlockCipher.ProcessBytes(c2, 0, c2.Length, m4, 0);
            aeadBlockCipher.DoFinal(m4, offset);
            if (!Arrays.AreEqual(m2, m4))
            {
                Assert.Fail("The encryption and decryption does not recover the plaintext");
            }
            Console.WriteLine(aeadBlockCipher.AlgorithmName + " test Exceptions pass");
            c2[c2.Length - 1] ^= 1;
            aeadBlockCipher.Reset();
            aeadBlockCipher.Init(false, param);
            aeadBlockCipher.ProcessAadBytes(aad2, 0, aad2.Length);
            offset = aeadBlockCipher.ProcessBytes(c2, 0, c2.Length, m4, 0);
            try
            {
                aeadBlockCipher.DoFinal(m4, offset);
                Assert.Fail("The decryption should fail");
            }
            catch (ArgumentException e)
            {
                //expected;
            }
            c2[c2.Length - 1] ^= 1;

            byte[] m7 = new byte[blocksize * 2];
            for (int i = 0; i < m7.Length; ++i)
            {
                m7[i] = (byte)rand.Next();
            }
            byte[] c7 = new byte[aeadBlockCipher.GetOutputSize(m7.Length)];
            byte[] c8 = new byte[c7.Length];
            byte[] c9 = new byte[c7.Length];
            aeadBlockCipher.Init(true, param);
            aeadBlockCipher.ProcessAadBytes(aad2, 0, aad2.Length);
            offset = aeadBlockCipher.ProcessBytes(m7, 0, m7.Length, c7, 0);
            aeadBlockCipher.DoFinal(c7, offset);
            aeadBlockCipher.Reset();
            aeadBlockCipher.ProcessAadBytes(aad2, 0, aad2.Length);
            offset = aeadBlockCipher.ProcessBytes(m7, 0, blocksize, c8, 0);
            offset += aeadBlockCipher.ProcessBytes(m7, blocksize, m7.Length - blocksize, c8, offset);
            aeadBlockCipher.DoFinal(c8, offset);
            aeadBlockCipher.Reset();
            int split = rand.Next(blocksize * 2);
            aeadBlockCipher.ProcessAadBytes(aad2, 0, aad2.Length);
            offset = aeadBlockCipher.ProcessBytes(m7, 0, split, c9, 0);
            offset += aeadBlockCipher.ProcessBytes(m7, split, m7.Length - split, c9, offset);
            aeadBlockCipher.DoFinal(c9, offset);
            if (!Arrays.AreEqual(c7, c8) || !Arrays.AreEqual(c7, c9))
            {
                Assert.Fail("Splitting input of plaintext should output the same ciphertext");
            }
#if NET6_0_OR_GREATER || NETSTANDARD2_1_OR_GREATER
            Span<byte> c4_1 = new byte[c2.Length];
            Span<byte> c4_2 = new byte[c2.Length];
            ReadOnlySpan<byte> m5 = new ReadOnlySpan<byte>(m2);
            ReadOnlySpan<byte> aad4 = new ReadOnlySpan<byte>(aad2);
            aeadBlockCipher.Init(true, param);
            aeadBlockCipher.ProcessAadBytes(aad4);
            offset = aeadBlockCipher.ProcessBytes(m5, c4_1);
            aeadBlockCipher.DoFinal(c4_2);
            byte[] c5 = new byte[c2.Length];
            Array.Copy(c4_1.ToArray(), 0, c5, 0, offset);
            Array.Copy(c4_2.ToArray(), 0, c5, offset, c5.Length - offset);
            if (!Arrays.AreEqual(c2, c5))
            {
                Assert.Fail("mac should match for the same AAD and message with different offset for both input and output");
            }
            aeadBlockCipher.Reset();
            aeadBlockCipher.Init(false, param);
            Span<byte> m6_1 = new byte[m2.Length];
            Span<byte> m6_2 = new byte[m2.Length];
            ReadOnlySpan<byte> c6 = new ReadOnlySpan<byte>(c2);
            aeadBlockCipher.ProcessAadBytes(aad4);
            offset = aeadBlockCipher.ProcessBytes(c6, m6_1);
            aeadBlockCipher.DoFinal(m6_2);
            byte[] m6 = new byte[m2.Length];
            Array.Copy(m6_1.ToArray(), 0, m6, 0, offset);
            Array.Copy(m6_2.ToArray(), 0, m6, offset, m6.Length - offset);
            if (!Arrays.AreEqual(m2, m6))
            {
                Assert.Fail("mac should match for the same AAD and message with different offset for both input and output");
            }
#endif

        }

        private void testParameters(XoodyakEngine xoodyak, int keySize, int ivSize, int macSize, int blockSize)
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
            Console.WriteLine(xoodyak.AlgorithmName + " test Parameters pass");
        }

        private void testExceptions(IDigest digest, int digestsize)
        {
            if (digest.GetDigestSize() != digestsize)
            {
                Assert.Fail(digest.AlgorithmName + ": digest size is not correct");
            }

            try
            {
                digest.BlockUpdate(new byte[1], 1, 1);
                Assert.Fail(digest.AlgorithmName + ": input for update is too short");
            }
            catch (DataLengthException e)
            {
                //expected
            }
            try
            {
                digest.DoFinal(new byte[digest.GetDigestSize() - 1], 2);
                Assert.Fail(digest.AlgorithmName + ": output for dofinal is too short");
            }
            catch (DataLengthException e)
            {
                //expected
            }
            Console.WriteLine(digest.AlgorithmName + " test Exceptions pass");
        }

    }
}
