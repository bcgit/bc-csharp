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
    [TestFixture]
    public class AsconTest : SimpleTest
    {
        public override string Name
        {
            get { return "ASCON AEAD"; }
        }

        [Test]
        public override void PerformTest()
        {
            AsconEngine Ascon = new AsconEngine(AsconEngine.AsconParameters.ascon80pq);
            testExceptions(Ascon, Ascon.GetKeyBytesSize(), Ascon.GetIVBytesSize(), Ascon.GetBlockSize());
            testParameters(Ascon, 20, 16, 16, 8);
            Ascon = new AsconEngine(AsconEngine.AsconParameters.ascon128a);
            testExceptions(Ascon, Ascon.GetKeyBytesSize(), Ascon.GetIVBytesSize(), Ascon.GetBlockSize());
            testParameters(Ascon, 16, 16, 16, 16);
            Ascon = new AsconEngine(AsconEngine.AsconParameters.ascon128);
            testExceptions(Ascon, Ascon.GetKeyBytesSize(), Ascon.GetIVBytesSize(), Ascon.GetBlockSize());
            testParameters(Ascon, 16, 16, 16, 8);
            testVectors(AsconEngine.AsconParameters.ascon80pq, "160_128");
            testVectors(AsconEngine.AsconParameters.ascon128a, "128_128_a");
            testVectors(AsconEngine.AsconParameters.ascon128, "128_128");
        }

        private void testVectors(AsconEngine.AsconParameters asconParameters, string filename)
        {
            AsconEngine Ascon = new AsconEngine(asconParameters);
            ICipherParameters param;
            var buf = new Dictionary<string, string>();
            //TestSampler sampler = new TestSampler();
            using (var src = new StreamReader(SimpleTest.GetTestDataAsStream("crypto.ascon.LWC_AEAD_KAT_" + filename + ".txt")))
            {
                string line;
                string[] data;
                byte[] rv;
                Dictionary<string, string> map = new Dictionary<string, string>();
                while ((line = src.ReadLine()) != null)
                {
                    data = line.Split(' ');
                    if (data.Length == 1)
                    {
                        //if (!map["Count"].Equals("265"))
                        //{
                        //    continue;
                        //}
                        byte[] key = Hex.Decode(map["Key"]);
                        byte[] nonce = Hex.Decode(map["Nonce"]);
                        byte[] ad = Hex.Decode(map["AD"]);
                        byte[] pt = Hex.Decode(map["PT"]);
                        byte[] ct = Hex.Decode(map["CT"]);
                        param = new ParametersWithIV(new KeyParameter(key), nonce);
                        Ascon.Init(true, param);
                        Ascon.ProcessAadBytes(ad, 0, ad.Length);
                        rv = new byte[Ascon.GetOutputSize(pt.Length)];
                        int len = Ascon.ProcessBytes(pt, 0, pt.Length, rv, 0);
                        //byte[] mac = new byte[16];
                        Ascon.DoFinal(rv, len);
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
                        Ascon.Reset();
                        Ascon.Init(false, param);
                        //Decrypt
                        Ascon.ProcessAadBytes(ad, 0, ad.Length);
                        rv = new byte[pt.Length + 16];
                        len = Ascon.ProcessBytes(ct, 0, ct.Length, rv, 0);
                        Ascon.DoFinal(rv, len);
                        byte[] pt_recovered = new byte[pt.Length];
                        Array.Copy(rv, 0, pt_recovered, 0, pt.Length);
                        Assert.True(Arrays.AreEqual(pt, pt_recovered));
                        //Console.WriteLine(map["Count"] + " pass");
                        map.Clear();

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
            Console.WriteLine("Ascon AEAD pass");
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
            catch (ArgumentException)
            {
                //expected
            }

            try
            {
                aeadBlockCipher.ProcessByte((byte)0, c1, 0);
                Assert.Fail(aeadBlockCipher.AlgorithmName + " need to be initialed before ProcessByte");
            }
            catch (ArgumentException)
            {
                //expected
            }

            try
            {
                aeadBlockCipher.Reset();
                Assert.Fail(aeadBlockCipher.AlgorithmName + " need to be initialed before reset");
            }
            catch (ArgumentException)
            {
                //expected
            }

            try
            {
                aeadBlockCipher.DoFinal(c1, m.Length);
                Assert.Fail(aeadBlockCipher.AlgorithmName + " need to be initialed before dofinal");
            }
            catch (ArgumentException)
            {
                //expected
            }

            try
            {
                aeadBlockCipher.GetMac();
                aeadBlockCipher.GetOutputSize(0);
                aeadBlockCipher.GetUpdateOutputSize(0);
            }
            catch (ArgumentException)
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
            catch (ArgumentException)
            {
                //expected
            }
            try
            {
                aeadBlockCipher.Init(true, new ParametersWithIV(new KeyParameter(k), iv1));
                Assert.Fail(aeadBlockCipher.AlgorithmName + "iv size does not match");
            }
            catch (ArgumentException)
            {
                //expected
            }


            aeadBlockCipher.Init(true, param);
            try
            {
                aeadBlockCipher.DoFinal(c1, m.Length);
            }
            catch (Exception)
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
            aeadBlockCipher.ProcessBytes(new byte[16], 0, 16, new byte[16], 0);
            try
            {
                aeadBlockCipher.ProcessAadByte((byte)0);
                Assert.Fail("ProcessAadByte(s) cannot be called after encryption/decryption");
            }
            catch (ArgumentException)
            {
                //expected
            }
            try
            {
                aeadBlockCipher.ProcessAadBytes(new byte[] { 0 }, 0, 1);
                Assert.Fail("ProcessAadByte(s) cannot be called once only");
            }
            catch (ArgumentException)
            {
                //expected
            }

            aeadBlockCipher.Reset();
            try
            {
                aeadBlockCipher.ProcessAadBytes(new byte[] { 0 }, 1, 1);
                Assert.Fail("input for ProcessAadBytes is too short");
            }
            catch (DataLengthException)
            {
                //expected
            }
            try
            {
                aeadBlockCipher.ProcessBytes(new byte[] { 0 }, 1, 1, c1, 0);
                Assert.Fail("input for ProcessBytes is too short");
            }
            catch (DataLengthException)
            {
                //expected
            }
            try
            {
                aeadBlockCipher.ProcessBytes(new byte[16], 0, 16, new byte[16], 8);
                Assert.Fail("output for ProcessBytes is too short");
            }
            catch (OutputLengthException)
            {
                //expected
            }
            try
            {
                aeadBlockCipher.DoFinal(new byte[2], 2);
                Assert.Fail("output for dofinal is too short");
            }
            catch (DataLengthException)
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
            catch (ArgumentException)
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
            // NOTE: .NET Core 3.1 has Span<T>, but is tested against our .NET Standard 2.0 assembly.
//#if NETCOREAPP2_1_OR_GREATER || NETSTANDARD2_1_OR_GREATER
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

        private void testParameters(AsconEngine ascon, int keySize, int ivSize, int macSize, int blockSize)
        {
            if (ascon.GetKeyBytesSize() != keySize)
            {
                Assert.Fail("key bytes of " + ascon.AlgorithmName + " is not correct");
            }
            if (ascon.GetIVBytesSize() != ivSize)
            {
                Assert.Fail("iv bytes of " + ascon.AlgorithmName + " is not correct");
            }
            if (ascon.GetOutputSize(0) != macSize)
            {
                Assert.Fail("mac bytes of " + ascon.AlgorithmName + " is not correct");
            }
            if (ascon.GetBlockSize() != blockSize)
            {
                Assert.Fail("block size of " + ascon.AlgorithmName + " is not correct");
            }
            Console.WriteLine(ascon.AlgorithmName + " test Parameters pass");
        }
    }
}