using System;
using System.Collections.Generic;
using System.IO;

using NUnit.Framework;

using Org.BouncyCastle.Crypto.Engines;
using Org.BouncyCastle.Crypto.Modes;
using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.Utilities;
using Org.BouncyCastle.Utilities.Encoders;
using Org.BouncyCastle.Utilities.Test;

namespace Org.BouncyCastle.Crypto.Tests
{
    public class ElephantTest
        : SimpleTest
    {
        public override string Name => "Elephant";

        [Test]
        public override void PerformTest()
        {
            ImplTestVectors(ElephantEngine.ElephantParameters.elephant160, "v160");
            ImplTestVectors(ElephantEngine.ElephantParameters.elephant176, "v176");
            ImplTestVectors(ElephantEngine.ElephantParameters.elephant200, "v200");
            ElephantEngine elephantEngine = new ElephantEngine(ElephantEngine.ElephantParameters.elephant160);
            ImplTestExceptions(elephantEngine, elephantEngine.GetKeyBytesSize(), elephantEngine.GetIVBytesSize(), elephantEngine.GetBlockSize());
            ImplTestParameters(elephantEngine, 16, 12, 8, 20);
            elephantEngine = new ElephantEngine(ElephantEngine.ElephantParameters.elephant176);
            ImplTestExceptions(elephantEngine, elephantEngine.GetKeyBytesSize(), elephantEngine.GetIVBytesSize(), elephantEngine.GetBlockSize());
            ImplTestParameters(elephantEngine, 16, 12, 8, 22);
            elephantEngine = new ElephantEngine(ElephantEngine.ElephantParameters.elephant200);
            ImplTestExceptions(elephantEngine, elephantEngine.GetKeyBytesSize(), elephantEngine.GetIVBytesSize(), elephantEngine.GetBlockSize());
            ImplTestParameters(elephantEngine, 16, 12, 16, 25);
        }

        private void ImplTestVectors(ElephantEngine.ElephantParameters pbp, String filename)
        {
            ElephantEngine Elephant = new ElephantEngine(pbp);
            ICipherParameters param;
            var buf = new Dictionary<string, string>();
            using (var src = new StreamReader(SimpleTest.GetTestDataAsStream("crypto.elephant." + filename + "_LWC_AEAD_KAT_128_96.txt")))
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

                        param = new ParametersWithIV(new KeyParameter(key), nonce);
                        Elephant.Init(true, param);
                        Elephant.ProcessAadBytes(ad, 0, ad.Length);
                        byte[] rv = new byte[Elephant.GetOutputSize(pt.Length)];
                        int len = Elephant.ProcessBytes(pt, 0, pt.Length, rv, 0);
                        Elephant.DoFinal(rv, len);
                        Assert.True(Arrays.AreEqual(rv, ct));
                        Elephant.Reset();
                        Elephant.Init(false, param);
                        //Decrypt
                        Elephant.ProcessAadBytes(ad, 0, ad.Length);
                        rv = new byte[pt.Length + 16];
                        len = Elephant.ProcessBytes(ct, 0, ct.Length, rv, 0);
                        Elephant.DoFinal(rv, len);
                        byte[] pt_recovered = new byte[pt.Length];
                        Array.Copy(rv, 0, pt_recovered, 0, pt.Length);
                        Assert.True(Arrays.AreEqual(pt, pt_recovered));
                        Elephant.Reset();
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

        private void ImplTestExceptions(ElephantEngine elephantEngine, int keysize, int ivsize, int blocksize)
        {
            byte[] k = new byte[keysize];
            byte[] iv = new byte[ivsize];
            byte[] m = new byte[0];
            byte[] c1 = new byte[elephantEngine.GetOutputSize(m.Length)];
            var param = new ParametersWithIV(new KeyParameter(k), iv);
            //try
            //{
            //    aeadBlockCipher.ProcessBytes(m, 0, m.Length, c1, 0);
            //    Assert.Fail(aeadBlockCipher.AlgorithmName + " needs to be initialized before ProcessBytes");
            //}
            //catch (ArgumentException e)
            //{
            //    //expected
            //}

            //try
            //{
            //    aeadBlockCipher.ProcessByte((byte)0, c1, 0);
            //    Assert.Fail(aeadBlockCipher.AlgorithmName + " needs to be initialized before ProcessByte");
            //}
            //catch (ArgumentException e)
            //{
            //    //expected
            //}

            //try
            //{
            //    aeadBlockCipher.Reset();
            //    Assert.Fail(aeadBlockCipher.AlgorithmName + " needs to be initialized before Reset");
            //}
            //catch (ArgumentException e)
            //{
            //    //expected
            //}

            try
            {
                elephantEngine.DoFinal(c1, m.Length);
                Assert.Fail(elephantEngine.AlgorithmName + " needs to be initialized before DoFinal");
            }
            catch (ArgumentException)
            {
                //expected
            }

            try
            {
                elephantEngine.GetMac();
                elephantEngine.GetOutputSize(0);
                elephantEngine.GetUpdateOutputSize(0);
            }
            catch (ArgumentException)
            {
                //expected
                Assert.Fail(elephantEngine.AlgorithmName + " functions can be called before initialization");
            }
            Random rand = new Random();
            int randomNum;
            while ((randomNum = rand.Next(100)) == keysize) ;
            byte[] k1 = new byte[randomNum];
            while ((randomNum = rand.Next(100)) == ivsize) ;
            byte[] iv1 = new byte[randomNum];
            try
            {
                elephantEngine.Init(true, new ParametersWithIV(new KeyParameter(k1), iv));
                Assert.Fail(elephantEngine.AlgorithmName + " k size does not match");
            }
            catch (ArgumentException)
            {
                //expected
            }
            try
            {
                elephantEngine.Init(true, new ParametersWithIV(new KeyParameter(k), iv1));
                Assert.Fail(elephantEngine.AlgorithmName + "iv size does not match");
            }
            catch (ArgumentException)
            {
                //expected
            }


            elephantEngine.Init(true, param);
            try
            {
                elephantEngine.DoFinal(c1, m.Length);
            }
            catch (Exception)
            {
                Assert.Fail(elephantEngine.AlgorithmName + " allows no input for AAD and plaintext");
            }
            byte[] mac2 = elephantEngine.GetMac();
            if (mac2 == null)
            {
                Assert.Fail("mac should not be empty after dofinal");
            }
            if (!Arrays.AreEqual(mac2, c1))
            {
                Assert.Fail("mac should be equal when calling dofinal and getMac");
            }
            elephantEngine.ProcessAadByte((byte)0);
            byte[] mac1 = new byte[elephantEngine.GetOutputSize(0)];
            elephantEngine.DoFinal(mac1, 0);
            if (Arrays.AreEqual(mac1, mac2))
            {
                Assert.Fail("mac should not match");
            }
            //aeadBlockCipher.Reset();
            //aeadBlockCipher.ProcessBytes(new byte[blocksize], 0, blocksize, new byte[blocksize], 0);
            //try
            //{
            //    aeadBlockCipher.ProcessAadByte((byte)0);
            //    Assert.Fail("ProcessAadByte(s) cannot be called after encryption/decryption");
            //}
            //catch (ArgumentException e)
            //{
            //    //expected
            //}
            //try
            //{
            //    aeadBlockCipher.ProcessAadBytes(new byte[] { 0 }, 0, 1);
            //    Assert.Fail("ProcessAadByte(s) cannot be called once only");
            //}
            //catch (ArgumentException e)
            //{
            //    //expected
            //}

            elephantEngine.Reset();
            try
            {
                elephantEngine.ProcessAadBytes(new byte[] { 0 }, 1, 1);
                Assert.Fail("input for ProcessAadBytes is too short");
            }
            catch (DataLengthException)
            {
                //expected
            }
            try
            {
                elephantEngine.ProcessBytes(new byte[] { 0 }, 1, 1, c1, 0);
                Assert.Fail("input for ProcessBytes is too short");
            }
            catch (DataLengthException)
            {
                //expected
            }
            //try
            //{
            //    aeadBlockCipher.ProcessBytes(new byte[blocksize], 0, blocksize, new byte[blocksize], blocksize >> 1);
            //    Assert.Fail("output for ProcessBytes is too short");
            //}
            //catch (OutputLengthException)
            //{
            //    //expected
            //}
            try
            {
                elephantEngine.DoFinal(new byte[2], 2);
                Assert.Fail("output for DoFinal is too short");
            }
            catch (OutputLengthException)
            {
                //expected
            }

            mac1 = new byte[elephantEngine.GetOutputSize(0)];
            mac2 = new byte[elephantEngine.GetOutputSize(0)];
            elephantEngine.Reset();
            elephantEngine.ProcessAadBytes(new byte[] { 0, 0 }, 0, 2);
            elephantEngine.DoFinal(mac1, 0);
            elephantEngine.Reset();
            elephantEngine.ProcessAadByte((byte)0);
            elephantEngine.ProcessAadByte((byte)0);
            elephantEngine.DoFinal(mac2, 0);
            if (!Arrays.AreEqual(mac1, mac2))
            {
                Assert.Fail("mac should match for the same AAD with different ways of inputing");
            }

            byte[] c2 = new byte[elephantEngine.GetOutputSize(10)];
            byte[] c3 = new byte[elephantEngine.GetOutputSize(10) + 2];
            byte[] aad2 = { 0, 1, 2, 3, 4 };
            byte[] aad3 = { 0, 0, 1, 2, 3, 4, 5 };
            byte[] m2 = { 0, 1, 2, 3, 4, 5, 6, 7, 8, 9 };
            byte[] m3 = { 0, 0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10 };
            byte[] m4 = new byte[m2.Length];
            elephantEngine.Reset();
            elephantEngine.ProcessAadBytes(aad2, 0, aad2.Length);
            int offset = elephantEngine.ProcessBytes(m2, 0, m2.Length, c2, 0);
            elephantEngine.DoFinal(c2, offset);
            elephantEngine.Reset();
            elephantEngine.ProcessAadBytes(aad3, 1, aad2.Length);
            offset = elephantEngine.ProcessBytes(m3, 1, m2.Length, c3, 1);
            elephantEngine.DoFinal(c3, offset + 1);
            byte[] c3_partial = new byte[c2.Length];
            Array.Copy(c3, 1, c3_partial, 0, c2.Length);
            if (!Arrays.AreEqual(c2, c3_partial))
            {
                Assert.Fail("mac should match for the same AAD and message with different offset for both input and output");
            }
            elephantEngine.Reset();
            elephantEngine.Init(false, param);
            elephantEngine.ProcessAadBytes(aad2, 0, aad2.Length);
            offset = elephantEngine.ProcessBytes(c2, 0, c2.Length, m4, 0);
            elephantEngine.DoFinal(m4, offset);
            if (!Arrays.AreEqual(m2, m4))
            {
                Assert.Fail("The encryption and decryption does not recover the plaintext");
            }
            Console.WriteLine(elephantEngine.AlgorithmName + " test Exceptions pass");
            c2[c2.Length - 1] ^= 1;
            elephantEngine.Reset();
            elephantEngine.Init(false, param);
            elephantEngine.ProcessAadBytes(aad2, 0, aad2.Length);
            offset = elephantEngine.ProcessBytes(c2, 0, c2.Length, m4, 0);
            try
            {
                elephantEngine.DoFinal(m4, offset);
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
            byte[] c7 = new byte[elephantEngine.GetOutputSize(m7.Length)];
            byte[] c8 = new byte[c7.Length];
            byte[] c9 = new byte[c7.Length];
            elephantEngine.Init(true, param);
            elephantEngine.ProcessAadBytes(aad2, 0, aad2.Length);
            offset = elephantEngine.ProcessBytes(m7, 0, m7.Length, c7, 0);
            elephantEngine.DoFinal(c7, offset);
            elephantEngine.Reset();
            elephantEngine.ProcessAadBytes(aad2, 0, aad2.Length);
            offset = elephantEngine.ProcessBytes(m7, 0, blocksize, c8, 0);
            offset += elephantEngine.ProcessBytes(m7, blocksize, m7.Length - blocksize, c8, offset);
            elephantEngine.DoFinal(c8, offset);
            elephantEngine.Reset();
            int split = rand.Next(blocksize * 2);
            elephantEngine.ProcessAadBytes(aad2, 0, aad2.Length);
            offset = elephantEngine.ProcessBytes(m7, 0, split, c9, 0);
            offset += elephantEngine.ProcessBytes(m7, split, m7.Length - split, c9, offset);
            elephantEngine.DoFinal(c9, offset);
            if (!Arrays.AreEqual(c7, c8) || !Arrays.AreEqual(c7, c9))
            {
                Assert.Fail("Splitting input of plaintext should output the same ciphertext");
            }
#if NET6_0_OR_GREATER || NETSTANDARD2_1_OR_GREATER
            Span<byte> c4_1 = new byte[c2.Length];
            Span<byte> c4_2 = new byte[c2.Length];
            ReadOnlySpan<byte> m5 = new ReadOnlySpan<byte>(m2);
            ReadOnlySpan<byte> aad4 = new ReadOnlySpan<byte>(aad2);
            elephantEngine.Init(true, param);
            elephantEngine.ProcessAadBytes(aad4);
            offset = elephantEngine.ProcessBytes(m5, c4_1);
            elephantEngine.DoFinal(c4_2);
            byte[] c5 = new byte[c2.Length];
            c4_1[..offset].CopyTo(c5);
            c4_2[..(c5.Length - offset)].CopyTo(c5.AsSpan(offset));
            if (!Arrays.AreEqual(c2, c5))
            {
                Assert.Fail("mac should match for the same AAD and message with different offset for both input and output");
            }
            elephantEngine.Reset();
            elephantEngine.Init(false, param);
            Span<byte> m6_1 = new byte[m2.Length];
            Span<byte> m6_2 = new byte[m2.Length];
            ReadOnlySpan<byte> c6 = new ReadOnlySpan<byte>(c2);
            elephantEngine.ProcessAadBytes(aad4);
            offset = elephantEngine.ProcessBytes(c6, m6_1);
            elephantEngine.DoFinal(m6_2);
            byte[] m6 = new byte[m2.Length];
            m6_1[..offset].CopyTo(m6);
            m6_2[..(m6.Length - offset)].CopyTo(m6.AsSpan(offset));
            if (!Arrays.AreEqual(m2, m6))
            {
                Assert.Fail("mac should match for the same AAD and message with different offset for both input and output");
            }
#endif

        }

        private void ImplTestParameters(ElephantEngine Elephant, int keySize, int ivSize, int macSize, int blockSize)
        {
            if (Elephant.GetKeyBytesSize() != keySize)
            {
                Assert.Fail("key bytes of " + Elephant.AlgorithmName + " is not correct");
            }
            if (Elephant.GetIVBytesSize() != ivSize)
            {
                Assert.Fail("iv bytes of " + Elephant.AlgorithmName + " is not correct");
            }
            if (Elephant.GetOutputSize(0) != macSize)
            {
                Assert.Fail("mac bytes of " + Elephant.AlgorithmName + " is not correct");
            }
            if (Elephant.GetBlockSize() != blockSize)
            {
                Assert.Fail("block size of " + Elephant.AlgorithmName + " is not correct");
            }
            Console.WriteLine(Elephant.AlgorithmName + " test Parameters pass");
        }

    }
}

