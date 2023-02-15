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
    public class AsconTest
        : SimpleTest
    {
        public override string Name => "ASCON";

        [Test, Explicit]
        public void BenchAuth80pq()
        {
            var parameters = new AeadParameters(new KeyParameter(new byte[20]), 128, new byte[16], null);
            var engine = new AsconEngine(AsconEngine.AsconParameters.ascon80pq);
            engine.Init(false, parameters);

            byte[] data = new byte[1024];
            for (int i = 0; i < 1024 * 1024; ++i)
            {
#if NET6_0_OR_GREATER
                engine.ProcessAadBytes(data.AsSpan(0, 1024));
#else
                engine.ProcessAadBytes(data, 0, 1024);
#endif
            }
        }

        [Test, Explicit]
        public void BenchDecrypt80pq()
        {
            var parameters = new AeadParameters(new KeyParameter(new byte[20]), 128, new byte[16], null);
            var engine = new AsconEngine(AsconEngine.AsconParameters.ascon80pq);
            engine.Init(false, parameters);

            byte[] data = new byte[1024];
            for (int i = 0; i < 1024 * 1024; ++i)
            {
#if NET6_0_OR_GREATER
                engine.ProcessBytes(data.AsSpan(0, 1024), data);
#else
                engine.ProcessBytes(data, 0, 1024, data, 0);
#endif
            }
        }

        [Test, Explicit]
        public void BenchEncrypt80pq()
        {
            var parameters = new AeadParameters(new KeyParameter(new byte[20]), 128, new byte[16], null);
            var engine = new AsconEngine(AsconEngine.AsconParameters.ascon80pq);
            engine.Init(true, parameters);

            byte[] data = new byte[engine.GetUpdateOutputSize(1024)];
            for (int i = 0; i < 1024 * 1024; ++i)
            {
#if NET6_0_OR_GREATER
                engine.ProcessBytes(data.AsSpan(0, 1024), data);
#else
                engine.ProcessBytes(data, 0, 1024, data, 0);
#endif
            }
        }

        [Test]
        public override void PerformTest()
        {
            ImplTestVectorsHash(AsconDigest.AsconParameters.AsconHashA, "asconhasha");
            ImplTestVectorsHash(AsconDigest.AsconParameters.AsconHash, "asconhash");
            ImplTestVectorsXof(AsconXof.AsconParameters.AsconXof, "asconxof");
            ImplTestVectorsXof(AsconXof.AsconParameters.AsconXofA, "asconxofa");

            ImplTestExceptions(new AsconDigest(AsconDigest.AsconParameters.AsconHashA), 32);
            ImplTestExceptions(new AsconDigest(AsconDigest.AsconParameters.AsconHash), 32);
            ImplTestExceptions(new AsconXof(AsconXof.AsconParameters.AsconXof), 32);
            ImplTestExceptions(new AsconXof(AsconXof.AsconParameters.AsconXofA), 32);

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
            AsconEngine asconEngine = new AsconEngine(asconParameters);
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

                        var parameters = new ParametersWithIV(new KeyParameter(key), nonce);

                        // Encrypt
                        {
                            asconEngine.Init(true, parameters);

                            var rv = new byte[asconEngine.GetOutputSize(pt.Length)];
                            random.NextBytes(rv); // should overwrite any existing data

                            asconEngine.ProcessAadBytes(ad, 0, ad.Length);
                            int len = asconEngine.ProcessBytes(pt, 0, pt.Length, rv, 0);
                            len += asconEngine.DoFinal(rv, len);

                            Assert.True(Arrays.AreEqual(rv, 0, len, ct, 0, ct.Length));
                        }

                        // Decrypt
                        {
                            asconEngine.Init(false, parameters);

                            var rv = new byte[asconEngine.GetOutputSize(ct.Length)];
                            random.NextBytes(rv); // should overwrite any existing data

                            asconEngine.ProcessAadBytes(ad, 0, ad.Length);
                            int len = asconEngine.ProcessBytes(ct, 0, ct.Length, rv, 0);
                            len += asconEngine.DoFinal(rv, len);

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
            int offset;
            byte[] k = new byte[keySize];
            byte[] iv = new byte[ivSize];
            byte[] m = Array.Empty<byte>();
            var param = new ParametersWithIV(new KeyParameter(k), iv);
            try
            {
                asconEngine.ProcessBytes(m, 0, m.Length, null, 0);
                Assert.Fail(asconEngine.AlgorithmName + " needs to be initialized before ProcessBytes");
            }
            catch (InvalidOperationException)
            {
                //expected
            }

            try
            {
                asconEngine.ProcessByte(0x00, null, 0);
                Assert.Fail(asconEngine.AlgorithmName + " needs to be initialized before ProcessByte");
            }
            catch (InvalidOperationException)
            {
                //expected
            }

            try
            {
                asconEngine.Reset();
                Assert.Fail(asconEngine.AlgorithmName + " needs to be initialized before Reset");
            }
            catch (InvalidOperationException)
            {
                //expected
            }

            try
            {
                asconEngine.DoFinal(null, m.Length);
                Assert.Fail(asconEngine.AlgorithmName + " needs to be initialized before DoFinal");
            }
            catch (InvalidOperationException)
            {
                //expected
            }

            try
            {
                asconEngine.GetMac();
                asconEngine.GetOutputSize(0);
                asconEngine.GetUpdateOutputSize(0);
            }
            catch (InvalidOperationException)
            {
                //expected
                Assert.Fail(asconEngine.AlgorithmName + " functions can be called before initialization");
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
            byte[] c1 = new byte[asconEngine.GetOutputSize(m.Length)];
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
                Assert.Fail("mac should not be empty after DoFinal");
            }
            if (!Arrays.AreEqual(mac2, c1))
            {
                Assert.Fail("mac should be equal when calling DoFinal and GetMac");
            }

            // TODO Maybe use a different IV for this
            asconEngine.Init(true, param);
            asconEngine.ProcessAadByte(0x00);
            byte[] mac1 = new byte[asconEngine.GetOutputSize(0)];
            asconEngine.DoFinal(mac1, 0);
            if (Arrays.AreEqual(mac1, mac2))
            {
                Assert.Fail("mac should not match");
            }

            // TODO Maybe use a different IV for this
            asconEngine.Init(true, param);
            asconEngine.ProcessByte(0, null, 0);
            try
            {
                asconEngine.ProcessAadByte(0x00);
                Assert.Fail("ProcessAadByte cannot be called after encryption/decryption");
            }
            catch (InvalidOperationException)
            {
                //expected
            }
            try
            {
                asconEngine.ProcessAadBytes(new byte[1], 0, 1);
                Assert.Fail("ProcessAadBytes cannot be called after encryption/decryption");
            }
            catch (InvalidOperationException)
            {
                //expected
            }

            // TODO Maybe use a different IV for this
            asconEngine.Init(true, param);
            try
            {
                asconEngine.ProcessAadBytes(new byte[1], 1, 1);
                Assert.Fail("input for ProcessAadBytes is too short");
            }
            catch (DataLengthException)
            {
                //expected
            }
            try
            {
                asconEngine.ProcessBytes(new byte[1], 1, 1, c1, 0);
                Assert.Fail("input for ProcessBytes is too short");
            }
            catch (DataLengthException)
            {
                //expected
            }

            try
            {
                int inputSize = rand.Next(32, 64);
                int outputSize = asconEngine.GetUpdateOutputSize(inputSize);
                asconEngine.ProcessBytes(new byte[inputSize], 0, inputSize, new byte[outputSize], 1);
                Assert.Fail("output for ProcessBytes is too short");
            }
            catch (OutputLengthException)
            {
                //expected
            }
            try
            {
                asconEngine.DoFinal(new byte[2], 2);
                Assert.Fail("output for DoFinal is too short");
            }
            catch (OutputLengthException)
            {
                //expected
            }

            mac1 = new byte[asconEngine.GetOutputSize(0)];
            mac2 = new byte[asconEngine.GetOutputSize(0)];

            // TODO Maybe use a different IV for this
            asconEngine.Init(true, param);
            asconEngine.ProcessAadBytes(new byte[2], 0, 2);
            asconEngine.DoFinal(mac1, 0);

            // TODO Maybe use a different IV for this
            asconEngine.Init(true, param);
            asconEngine.ProcessAadByte(0x00);
            asconEngine.ProcessAadByte(0x00);
            asconEngine.DoFinal(mac2, 0);

            if (!Arrays.AreEqual(mac1, mac2))
            {
                Assert.Fail("mac should match for the same AAD with different ways of inputting");
            }

            byte[] aad2 = { 0, 1, 2, 3, 4 };
            byte[] aad3 = { 0, 0, 1, 2, 3, 4, 5 };
            byte[] m2 = { 0, 1, 2, 3, 4, 5, 6, 7, 8, 9 };
            byte[] m3 = { 0, 0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10 };
            byte[] m4 = new byte[m2.Length];
            byte[] c2 = new byte[asconEngine.GetOutputSize(m2.Length)];
            byte[] c3 = new byte[asconEngine.GetOutputSize(m3.Length)];

            // TODO Maybe use a different IV for this
            asconEngine.Init(true, param);
            asconEngine.ProcessAadBytes(aad2, 0, aad2.Length);
            offset = asconEngine.ProcessBytes(m2, 0, m2.Length, c2, 0);
            asconEngine.DoFinal(c2, offset);

            // TODO Maybe use a different IV for this
            asconEngine.Init(true, param);
            asconEngine.ProcessAadBytes(aad3, 1, aad2.Length);
            offset = asconEngine.ProcessBytes(m3, 1, m2.Length, c3, 1);
            asconEngine.DoFinal(c3, offset + 1);

            byte[] c3_partial = new byte[c2.Length];
            Array.Copy(c3, 1, c3_partial, 0, c2.Length);
            if (!Arrays.AreEqual(c2, c3_partial))
            {
                Assert.Fail("mac should match for the same AAD and message with different offset for both input and output");
            }

            asconEngine.Init(false, param);
            asconEngine.ProcessAadBytes(aad2, 0, aad2.Length);
            offset = asconEngine.ProcessBytes(c2, 0, c2.Length, m4, 0);
            asconEngine.DoFinal(m4, offset);
            if (!Arrays.AreEqual(m2, m4))
            {
                Assert.Fail("The encryption and decryption does not recover the plaintext");
            }

            c2[c2.Length - 1] ^= 1;

            asconEngine.ProcessAadBytes(aad2, 0, aad2.Length);
            offset = asconEngine.ProcessBytes(c2, 0, c2.Length, m4, 0);
            try
            {
                asconEngine.DoFinal(m4, offset);
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
            asconEngine.Init(true, param);
            byte[] c7 = new byte[asconEngine.GetOutputSize(m7.Length)];
            byte[] c8 = new byte[c7.Length];
            byte[] c9 = new byte[c7.Length];
            asconEngine.ProcessAadBytes(aad2, 0, aad2.Length);
            offset = asconEngine.ProcessBytes(m7, 0, m7.Length, c7, 0);
            offset += asconEngine.DoFinal(c7, offset);

            // TODO Maybe use a different IV for this
            asconEngine.Init(true, param);
            asconEngine.ProcessAadBytes(aad2, 0, aad2.Length);
            offset = asconEngine.ProcessBytes(m7, 0, m7.Length / 2, c8, 0);
            offset += asconEngine.ProcessBytes(m7, m7.Length / 2, m7.Length - m7.Length / 2, c8, offset);
            offset += asconEngine.DoFinal(c8, offset);

            // TODO Maybe use a different IV for this
            asconEngine.Init(true, param);
            int split = rand.Next(1, m7.Length);
            asconEngine.ProcessAadBytes(aad2, 0, aad2.Length);
            offset = asconEngine.ProcessBytes(m7, 0, split, c9, 0);
            offset += asconEngine.ProcessBytes(m7, split, m7.Length - split, c9, offset);
            offset += asconEngine.DoFinal(c9, offset);
            if (!Arrays.AreEqual(c7, c8) || !Arrays.AreEqual(c7, c9))
            {
                Assert.Fail("Splitting input of plaintext should output the same ciphertext");
            }
            // NOTE: .NET Core 3.1 has Span<T>, but is tested against our .NET Standard 2.0 assembly.
            //#if NETCOREAPP2_1_OR_GREATER || NETSTANDARD2_1_OR_GREATER
#if NET6_0_OR_GREATER || NETSTANDARD2_1_OR_GREATER
            // TODO Maybe use a different IV for this
            asconEngine.Init(true, param);
            Span<byte> c4 = new byte[asconEngine.GetOutputSize(m2.Length)];
            asconEngine.ProcessAadBytes(aad2);
            offset = asconEngine.ProcessBytes(m2, c4);
            offset += asconEngine.DoFinal(c4[offset..]);
            if (!c4[..offset].SequenceEqual(c2))
            {
                Assert.Fail("Encryption should match for the same AAD and message with/without Span-based API");
            }

            asconEngine.Init(false, param);
            Span<byte> m6 = new byte[m2.Length];
            asconEngine.ProcessAadBytes(aad2);
            offset = asconEngine.ProcessBytes(c2, m6);
            offset += asconEngine.DoFinal(m6[offset..]);
            if (!m6[..offset].SequenceEqual(m2))
            {
                Assert.Fail("Decryption should match for the same AAD and message with/without Span-based API");
            }
#endif
        }

        private void ImplTestParameters(AsconEngine asconEngine, int keySize, int ivSize, int macSize)
        {
            Assert.AreEqual(keySize, asconEngine.GetKeyBytesSize(),
                "key bytes of " + asconEngine.AlgorithmName + " is not correct");
            Assert.AreEqual(ivSize, asconEngine.GetIVBytesSize(),
                "iv bytes of " + asconEngine.AlgorithmName + " is not correct");

            var parameters = new ParametersWithIV(new KeyParameter(new byte[keySize]), new byte[ivSize]);

            asconEngine.Init(true, parameters);
            Assert.AreEqual(macSize, asconEngine.GetOutputSize(0),
                "GetOutputSize of " + asconEngine.AlgorithmName + " is incorrect for encryption");

            asconEngine.Init(false, parameters);
            Assert.AreEqual(0, asconEngine.GetOutputSize(macSize),
                "GetOutputSize of " + asconEngine.AlgorithmName + " is incorrect for decryption");
        }

        private void ImplTestVectorsHash(AsconDigest.AsconParameters asconParameters, string filename)
        {
            AsconDigest ascon = new AsconDigest(asconParameters);
            var buf = new Dictionary<string, string>();
            using (var src = new StreamReader(
                SimpleTest.GetTestDataAsStream("crypto.ascon." + filename + "_LWC_HASH_KAT_256.txt")))
            {
                Dictionary<string, string> map = new Dictionary<string, string>();
                string line;
                while ((line = src.ReadLine()) != null)
                {
                    var data = line.Split(' ');
                    if (data.Length == 1)
                    {
                        byte[] ptByte = Hex.Decode(map["Msg"]);
                        byte[] expected = Hex.Decode(map["MD"]);
                        map.Clear();

                        ascon.BlockUpdate(ptByte, 0, ptByte.Length);
                        byte[] hash = new byte[ascon.GetDigestSize()];
                        ascon.DoFinal(hash, 0);
                        Assert.True(Arrays.AreEqual(expected, hash));
                        ascon.Reset();
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

        private void ImplTestVectorsXof(AsconXof.AsconParameters asconParameters, string filename)
        {
            AsconXof ascon = new AsconXof(asconParameters);
            var buf = new Dictionary<string, string>();
            using (var src = new StreamReader(
                SimpleTest.GetTestDataAsStream("crypto.ascon." + filename + "_LWC_HASH_KAT_256.txt")))
            {
                Dictionary<string, string> map = new Dictionary<string, string>();
                string line;
                while ((line = src.ReadLine()) != null)
                {
                    var data = line.Split(' ');
                    if (data.Length == 1)
                    {
                        byte[] ptByte = Hex.Decode(map["Msg"]);
                        byte[] expected = Hex.Decode(map["MD"]);
                        map.Clear();

                        ascon.BlockUpdate(ptByte, 0, ptByte.Length);
                        byte[] hash = new byte[ascon.GetDigestSize()];
                        ascon.DoFinal(hash, 0);
                        Assert.True(Arrays.AreEqual(expected, hash));
                        ascon.Reset();
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

        private void ImplTestExceptions(AsconDigest asconDigest, int digestSize)
        {
            Assert.AreEqual(digestSize, asconDigest.GetDigestSize(),
                asconDigest.AlgorithmName + ": digest size is not correct");

            try
            {
                asconDigest.BlockUpdate(new byte[1], 1, 1);
                Assert.Fail(asconDigest.AlgorithmName + ": input for BlockUpdate is too short");
            }
            catch (DataLengthException)
            {
                //expected
            }
            try
            {
                asconDigest.DoFinal(new byte[digestSize - 1], 2);
                Assert.Fail(asconDigest.AlgorithmName + ": output for DoFinal is too short");
            }
            catch (OutputLengthException)
            {
                //expected
            }
        }

        private void ImplTestExceptions(AsconXof asconXof, int digestSize)
        {
            Assert.AreEqual(digestSize, asconXof.GetDigestSize(),
                asconXof.AlgorithmName + ": digest size is not correct");

            try
            {
                asconXof.BlockUpdate(new byte[1], 1, 1);
                Assert.Fail(asconXof.AlgorithmName + ": input for BlockUpdate is too short");
            }
            catch (DataLengthException)
            {
                //expected
            }
            try
            {
                asconXof.DoFinal(new byte[digestSize - 1], 2);
                Assert.Fail(asconXof.AlgorithmName + ": output for DoFinal is too short");
            }
            catch (OutputLengthException)
            {
                //expected
            }
        }
    }
}
