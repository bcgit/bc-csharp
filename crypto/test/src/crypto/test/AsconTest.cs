using System;
using System.Collections.Generic;
using System.IO;

using NUnit.Framework;

using Org.BouncyCastle.Crypto.Engines;
using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.Utilities;
using Org.BouncyCastle.Utilities.Encoders;
using Org.BouncyCastle.Utilities.Test;

namespace Org.BouncyCastle.Crypto.Tests
{
    [TestFixture]
    public class AsconTest
        : SimpleTest
    {
        public override string Name => "ASCON AEAD";

        [Test]
        public override void PerformTest()
        {
            AsconEngine asconEngine = new AsconEngine(AsconEngine.AsconParameters.ascon80pq);
            ImplTestExceptions(asconEngine);
            ImplTestParameters(asconEngine, 20, 16, 16);

            asconEngine = new AsconEngine(AsconEngine.AsconParameters.ascon128a);
            ImplTestExceptions(asconEngine);
            ImplTestParameters(asconEngine, 16, 16, 16);

            asconEngine = new AsconEngine(AsconEngine.AsconParameters.ascon128);
            ImplTestExceptions(asconEngine);
            ImplTestParameters(asconEngine, 16, 16, 16);

            ImplTestVectors(AsconEngine.AsconParameters.ascon80pq, "160_128");
            ImplTestVectors(AsconEngine.AsconParameters.ascon128a, "128_128_a");
            ImplTestVectors(AsconEngine.AsconParameters.ascon128, "128_128");
        }

        private void ImplTestVectors(AsconEngine.AsconParameters asconParameters, string filename)
        {
            Random random = new Random();
            AsconEngine Ascon = new AsconEngine(asconParameters);
            var buf = new Dictionary<string, string>();
            //TestSampler sampler = new TestSampler();
            using (var src = new StreamReader(SimpleTest.GetTestDataAsStream("crypto.ascon.LWC_AEAD_KAT_" + filename + ".txt")))
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

                        // Encrypt
                        {
                            Ascon.Init(true, param);

                            var rv = new byte[Ascon.GetOutputSize(pt.Length)];
                            random.NextBytes(rv); // should overwrite any existing data

                            Ascon.ProcessAadBytes(ad, 0, ad.Length);
                            int len = Ascon.ProcessBytes(pt, 0, pt.Length, rv, 0);
                            len += Ascon.DoFinal(rv, len);

                            Assert.True(Arrays.AreEqual(rv, 0, len, ct, 0, ct.Length));
                        }

                        // Decrypt
                        {
                            Ascon.Init(false, param);

                            var rv = new byte[Ascon.GetOutputSize(ct.Length)];
                            random.NextBytes(rv); // should overwrite any existing data

                            Ascon.ProcessAadBytes(ad, 0, ad.Length);
                            int len = Ascon.ProcessBytes(ct, 0, ct.Length, rv, 0);
                            len += Ascon.DoFinal(rv, len);

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

        private void ImplTestExceptions(AsconEngine asconEngine)
        {
            int keySize = asconEngine.GetKeyBytesSize(), ivSize = asconEngine.GetIVBytesSize();
            byte[] k = new byte[keySize];
            byte[] iv = new byte[ivSize];
            byte[] m = new byte[0];
            byte[] c1 = new byte[asconEngine.GetOutputSize(m.Length)];
            var param = new ParametersWithIV(new KeyParameter(k), iv);
            try
            {
                asconEngine.ProcessBytes(m, 0, m.Length, c1, 0);
                Assert.Fail(asconEngine.AlgorithmName + " need to be initialed before ProcessBytes");
            }
            catch (ArgumentException)
            {
                //expected
            }

            try
            {
                asconEngine.ProcessByte((byte)0, c1, 0);
                Assert.Fail(asconEngine.AlgorithmName + " need to be initialed before ProcessByte");
            }
            catch (ArgumentException)
            {
                //expected
            }

            try
            {
                asconEngine.Reset();
                Assert.Fail(asconEngine.AlgorithmName + " need to be initialed before reset");
            }
            catch (ArgumentException)
            {
                //expected
            }

            try
            {
                asconEngine.DoFinal(c1, m.Length);
                Assert.Fail(asconEngine.AlgorithmName + " need to be initialed before dofinal");
            }
            catch (ArgumentException)
            {
                //expected
            }

            try
            {
                asconEngine.GetMac();
                asconEngine.GetOutputSize(0);
                asconEngine.GetUpdateOutputSize(0);
            }
            catch (ArgumentException)
            {
                //expected
                Assert.Fail(asconEngine.AlgorithmName + " functions can be called before initialisation");
            }

            Random rand = new Random();
            int randomNum;
            while ((randomNum = rand.Next(100)) == keySize) ;
            byte[] k1 = new byte[randomNum];
            while ((randomNum = rand.Next(100)) == ivSize) ;
            byte[] iv1 = new byte[randomNum];
            try
            {
                asconEngine.Init(true, new ParametersWithIV(new KeyParameter(k1), iv));
                Assert.Fail(asconEngine.AlgorithmName + " k size does not match");
            }
            catch (ArgumentException)
            {
                //expected
            }
            try
            {
                asconEngine.Init(true, new ParametersWithIV(new KeyParameter(k), iv1));
                Assert.Fail(asconEngine.AlgorithmName + "iv size does not match");
            }
            catch (ArgumentException)
            {
                //expected
            }

            asconEngine.Init(true, param);
            try
            {
                asconEngine.DoFinal(c1, m.Length);
            }
            catch (Exception)
            {
                Assert.Fail(asconEngine.AlgorithmName + " allows no input for AAD and plaintext");
            }
            byte[] mac2 = asconEngine.GetMac();
            if (mac2 == null)
            {
                Assert.Fail("mac should not be empty after dofinal");
            }
            if (!Arrays.AreEqual(mac2, c1))
            {
                Assert.Fail("mac should be equal when calling dofinal and getMac");
            }
            asconEngine.ProcessAadByte((byte)0);
            byte[] mac1 = new byte[asconEngine.GetOutputSize(0)];
            asconEngine.DoFinal(mac1, 0);
            if (Arrays.AreEqual(mac1, mac2))
            {
                Assert.Fail("mac should not match");
            }
            asconEngine.Reset();
            asconEngine.ProcessBytes(new byte[16], 0, 16, new byte[16], 0);
            try
            {
                asconEngine.ProcessAadByte((byte)0);
                Assert.Fail("ProcessAadByte(s) cannot be called after encryption/decryption");
            }
            catch (ArgumentException)
            {
                //expected
            }
            try
            {
                asconEngine.ProcessAadBytes(new byte[] { 0 }, 0, 1);
                Assert.Fail("ProcessAadByte(s) cannot be called once only");
            }
            catch (ArgumentException)
            {
                //expected
            }

            asconEngine.Reset();
            try
            {
                asconEngine.ProcessAadBytes(new byte[] { 0 }, 1, 1);
                Assert.Fail("input for ProcessAadBytes is too short");
            }
            catch (DataLengthException)
            {
                //expected
            }
            try
            {
                asconEngine.ProcessBytes(new byte[] { 0 }, 1, 1, c1, 0);
                Assert.Fail("input for ProcessBytes is too short");
            }
            catch (DataLengthException)
            {
                //expected
            }
            try
            {
                asconEngine.ProcessBytes(new byte[16], 0, 16, new byte[16], 8);
                Assert.Fail("output for ProcessBytes is too short");
            }
            catch (OutputLengthException)
            {
                //expected
            }
            try
            {
                asconEngine.DoFinal(new byte[2], 2);
                Assert.Fail("output for dofinal is too short");
            }
            catch (DataLengthException)
            {
                //expected
            }

            mac1 = new byte[asconEngine.GetOutputSize(0)];
            mac2 = new byte[asconEngine.GetOutputSize(0)];
            asconEngine.Reset();
            asconEngine.ProcessAadBytes(new byte[] { 0, 0 }, 0, 2);
            asconEngine.DoFinal(mac1, 0);
            asconEngine.Reset();
            asconEngine.ProcessAadByte((byte)0);
            asconEngine.ProcessAadByte((byte)0);
            asconEngine.DoFinal(mac2, 0);
            if (!Arrays.AreEqual(mac1, mac2))
            {
                Assert.Fail("mac should match for the same AAD with different ways of inputing");
            }

            byte[] c2 = new byte[asconEngine.GetOutputSize(10)];
            byte[] c3 = new byte[asconEngine.GetOutputSize(10) + 2];
            byte[] aad2 = { 0, 1, 2, 3, 4 };
            byte[] aad3 = { 0, 0, 1, 2, 3, 4, 5 };
            byte[] m2 = { 0, 1, 2, 3, 4, 5, 6, 7, 8, 9 };
            byte[] m3 = { 0, 0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10 };
            byte[] m4 = new byte[m2.Length];
            asconEngine.Reset();
            asconEngine.ProcessAadBytes(aad2, 0, aad2.Length);
            int offset = asconEngine.ProcessBytes(m2, 0, m2.Length, c2, 0);
            asconEngine.DoFinal(c2, offset);
            asconEngine.Reset();
            asconEngine.ProcessAadBytes(aad3, 1, aad2.Length);
            offset = asconEngine.ProcessBytes(m3, 1, m2.Length, c3, 1);
            asconEngine.DoFinal(c3, offset + 1);
            byte[] c3_partial = new byte[c2.Length];
            Array.Copy(c3, 1, c3_partial, 0, c2.Length);
            if (!Arrays.AreEqual(c2, c3_partial))
            {
                Assert.Fail("mac should match for the same AAD and message with different offset for both input and output");
            }
            asconEngine.Reset();
            asconEngine.Init(false, param);
            asconEngine.ProcessAadBytes(aad2, 0, aad2.Length);
            offset = asconEngine.ProcessBytes(c2, 0, c2.Length, m4, 0);
            asconEngine.DoFinal(m4, offset);
            if (!Arrays.AreEqual(m2, m4))
            {
                Assert.Fail("The encryption and decryption does not recover the plaintext");
            }
            c2[c2.Length - 1] ^= 1;
            asconEngine.Reset();
            asconEngine.Init(false, param);
            asconEngine.ProcessAadBytes(aad2, 0, aad2.Length);
            offset = asconEngine.ProcessBytes(c2, 0, c2.Length, m4, 0);
            try
            {
                asconEngine.DoFinal(m4, offset);
                Assert.Fail("The decryption should fail");
            }
            catch (ArgumentException)
            {
                //expected;
            }
            c2[c2.Length - 1] ^= 1;

            byte[] m7 = new byte[32 + rand.Next(16)];
            rand.NextBytes(m7);

            byte[] c7 = new byte[asconEngine.GetOutputSize(m7.Length)];
            byte[] c8 = new byte[c7.Length];
            byte[] c9 = new byte[c7.Length];
            asconEngine.Init(true, param);
            asconEngine.ProcessAadBytes(aad2, 0, aad2.Length);
            offset = asconEngine.ProcessBytes(m7, 0, m7.Length, c7, 0);
            asconEngine.DoFinal(c7, offset);
            asconEngine.Reset();
            asconEngine.ProcessAadBytes(aad2, 0, aad2.Length);
            offset = asconEngine.ProcessBytes(m7, 0, m7.Length, c8, 0);
            offset += asconEngine.DoFinal(c8, offset);
            asconEngine.Reset();
            int split = rand.Next(1, m7.Length);
            asconEngine.ProcessAadBytes(aad2, 0, aad2.Length);
            offset = asconEngine.ProcessBytes(m7, 0, split, c9, 0);
            offset += asconEngine.ProcessBytes(m7, split, m7.Length - split, c9, offset);
            asconEngine.DoFinal(c9, offset);
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
            asconEngine.Init(true, param);
            asconEngine.ProcessAadBytes(aad4);
            offset = asconEngine.ProcessBytes(m5, c4_1);
            asconEngine.DoFinal(c4_2);
            byte[] c5 = new byte[c2.Length];
            Array.Copy(c4_1.ToArray(), 0, c5, 0, offset);
            Array.Copy(c4_2.ToArray(), 0, c5, offset, c5.Length - offset);
            if (!Arrays.AreEqual(c2, c5))
            {
                Assert.Fail("mac should match for the same AAD and message with different offset for both input and output");
            }
            asconEngine.Reset();
            asconEngine.Init(false, param);
            Span<byte> m6_1 = new byte[m2.Length];
            Span<byte> m6_2 = new byte[m2.Length];
            ReadOnlySpan<byte> c6 = new ReadOnlySpan<byte>(c2);
            asconEngine.ProcessAadBytes(aad4);
            offset = asconEngine.ProcessBytes(c6, m6_1);
            asconEngine.DoFinal(m6_2);
            byte[] m6 = new byte[m2.Length];
            Array.Copy(m6_1.ToArray(), 0, m6, 0, offset);
            Array.Copy(m6_2.ToArray(), 0, m6, offset, m6.Length - offset);
            if (!Arrays.AreEqual(m2, m6))
            {
                Assert.Fail("mac should match for the same AAD and message with different offset for both input and output");
            }
#endif
        }

        private void ImplTestParameters(AsconEngine asconEngine, int keySize, int ivSize, int macSize)
        {
            Assert.AreEqual(keySize, asconEngine.GetKeyBytesSize(),
                "key bytes of " + asconEngine.AlgorithmName + " is not correct");
            Assert.AreEqual(ivSize, asconEngine.GetIVBytesSize(),
                "iv bytes of " + asconEngine.AlgorithmName + " is not correct");
            Assert.AreEqual(macSize, asconEngine.GetOutputSize(0),
                "mac bytes of " + asconEngine.AlgorithmName + " is not correct");
        }
    }
}
