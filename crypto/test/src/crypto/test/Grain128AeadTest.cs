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
    public class Grain128AeadTest
    {
        [Test]
        public void TestSplitUpdate()
        {
            byte[] Key = Hex.Decode("000102030405060708090A0B0C0D0E0F");
            byte[] Nonce = Hex.Decode("000102030405060708090A0B");
            byte[] PT = Hex.Decode("000102030405060708090A0B0C0D0E0F101112131415161718191A1B1C1D1E1F");
            byte[] AD = Hex.Decode("000102030405060708090A0B0C0D0E0F101112131415161718191A1B1C1D1E");
            byte[] CT = Hex.Decode("EAD60EF559493ACEF6A3C238C018835DE3ABB6AA621A9AA65EFAF7B9D05BBE6C0913DFC8674BACC9");

            Grain128AeadEngine grain = new Grain128AeadEngine();
            ParametersWithIV param = new ParametersWithIV(new KeyParameter(Key), Nonce);
            grain.Init(true, param);

            grain.ProcessAadBytes(AD, 0, 10);
            grain.ProcessAadByte(AD[10]);
            grain.ProcessAadBytes(AD, 11, AD.Length - 11);

            byte[] rv = new byte[CT.Length];
            int len = grain.ProcessBytes(PT, 0, 10, rv, 0);
            len += grain.ProcessByte(PT[10], rv, len);
            len += grain.ProcessBytes(PT, 11, PT.Length - 11, rv, len);

            grain.DoFinal(rv, len);

            Assert.True(Arrays.AreEqual(rv, CT));

            // NOTE: Need to re-create to avoid nonce re-use exception
            grain = new Grain128AeadEngine();
            grain.Init(true, param);

            grain.ProcessBytes(PT, 0, 10, rv, 0);

            try
            {
                grain.ProcessAadByte(0x01);
                Assert.Fail("no exception");
            }
            catch (InvalidOperationException e)
            {
                Assert.IsTrue(e.Message.Contains("associated data must be added before plaintext/ciphertext"));
            }

            try
            {
                grain.ProcessAadBytes(AD, 0, AD.Length);
                Assert.Fail("no exception");
            }
            catch (InvalidOperationException e)
            {
                Assert.IsTrue(e.Message.Contains("associated data must be added before plaintext/ciphertext"));
            }
        }

        [Test]
        public void TestLongAead()
        {
            byte[] Key = Hex.Decode("000102030405060708090A0B0C0D0E0F");
            byte[] Nonce = Hex.Decode("000102030405060708090A0B");
            byte[] PT = Hex.Decode("000102030405060708090A0B0C0D0E0F101112131415161718191A1B1C1D1E1F");
            byte[] AD = Hex.Decode(   // 186 bytes
                "000102030405060708090A0B0C0D0E0F101112131415161718191A1B1C1D1E1F202122232425262728292A2B2C2D2E2F303132333435363738393A3B3C3D3E3F404142434445464748494A4B4C4D4E4F505152535455565758595A5B5C5D5E5F606162636465666768696A6B6C6D6E6F707172737475767778797A7B7C7D7E7F808182838485868788898A8B8C8D8E8F909192939495969798999A9B9C9D9E9FA0A1A2A3A4A5A6A7A8A9AAABACADAEAFB0B1B2B3B4B5B6B7B8B9");
            byte[] CT = Hex.Decode("731DAA8B1D15317A1CCB4E3DD320095FB27E5BB2A10F2C669F870538637D4F162298C70430A2B560");

            Grain128AeadEngine grain = new Grain128AeadEngine();
            ParametersWithIV param = new ParametersWithIV(new KeyParameter(Key), Nonce);
            grain.Init(true, param);

            grain.ProcessAadBytes(AD, 0, AD.Length);

            byte[] rv = new byte[CT.Length];
            int len = grain.ProcessBytes(PT, 0, 10, rv, 0);
            len += grain.ProcessByte(PT[10], rv, len);
            len += grain.ProcessBytes(PT, 11, PT.Length - 11, rv, len);

            grain.DoFinal(rv, len);

            Assert.IsTrue(Arrays.AreEqual(rv, CT));

            // NOTE: Need to re-create to avoid nonce re-use exception
            grain = new Grain128AeadEngine();
            grain.Init(true, param);

            grain.ProcessBytes(PT, 0, 10, rv, 0);

            try
            {
                grain.ProcessAadByte(0x01);
                Assert.Fail("no exception");
            }
            catch (InvalidOperationException e)
            {
                Assert.IsTrue(e.Message.Contains("associated data must be added before plaintext/ciphertext"));
            }

            try
            {
                grain.ProcessAadBytes(AD, 0, AD.Length);
                Assert.Fail("no exception");
            }
            catch (InvalidOperationException e)
            {
                Assert.IsTrue(e.Message.Contains("associated data must be added before plaintext/ciphertext"));
            }
        }

        [Test]
        public void TestExceptions()

        {
            try
            {
                Grain128AeadEngine grain128 = new Grain128AeadEngine();

                grain128.Init(true, new KeyParameter(new byte[10]));
                Assert.Fail("no exception");
            }
            catch (ArgumentException e)
            {
                Assert.IsTrue(e.Message.Contains("Grain-128AEAD Init parameters must include an IV"));
            }

            try
            {
                Grain128AeadEngine grain128 = new Grain128AeadEngine();

                grain128.Init(true, new ParametersWithIV(new KeyParameter(new byte[10]), new byte[8]));
                Assert.Fail("no exception");
            }
            catch (ArgumentException e)
            {
                Assert.IsTrue(e.Message.Contains("Grain-128AEAD requires exactly 12 bytes of IV"));
            }

            try
            {
                Grain128AeadEngine grain128 = new Grain128AeadEngine();

                grain128.Init(true, new ParametersWithIV(new KeyParameter(new byte[10]), new byte[12]));
                Assert.Fail("no exception");
            }
            catch (ArgumentException e)
            {
                Assert.IsTrue(e.Message.Contains("Grain-128AEAD key must be 128 bits long"));
            }
        }

        [Test]
        public void TestVectors()
        {
            Random random = new Random();

            var data = new Dictionary<string, string>();
            using (var src = new StreamReader(SimpleTest.FindTestResource("crypto", "LWC_AEAD_KAT_128_96.txt")))
            {
                string line;
                while ((line = src.ReadLine()) != null)
                {
                    line = line.Trim();
                    if (line.StartsWith("#"))
                        continue;

                    if (line.Length > 0)
                    {
                        int a = line.IndexOf('=');
                        if (a >= 0)
                        {
                            data[line.Substring(0, a).Trim()] = line.Substring(a + 1).Trim();
                        }
                        continue;
                    }

                    if (data.Count > 0)
                    {
                        RunTestVector(random, data);
                        data.Clear();
                    }
                }

                if (data.Count > 0)
                {
                    RunTestVector(random, data);
                    data.Clear();
                }
            }
        }

        private static void RunTestVector(Random random, Dictionary<string, string> data)
        {
            byte[] key = Hex.Decode(data["Key"]);
            byte[] nonce = Hex.Decode(data["Nonce"]);
            byte[] pt = Hex.Decode(data["PT"]);
            byte[] ad = Hex.Decode(data["AD"]);
            byte[] ct = Hex.Decode(data["CT"]);

            var cipher = new Grain128AeadEngine();
            var parameters = new ParametersWithIV(new KeyParameter(key), nonce);

            // Encrypt
            {
                cipher.Init(true, parameters);

                byte[] rv = new byte[cipher.GetOutputSize(pt.Length)];
                random.NextBytes(rv); // should overwrite any existing data

                cipher.ProcessAadBytes(ad, 0, ad.Length);
                int len = cipher.ProcessBytes(pt, 0, pt.Length, rv, 0);
                len += cipher.DoFinal(rv, len);

                Assert.True(Arrays.AreEqual(rv, 0, len, ct, 0, ct.Length));
            }

            // Decrypt
            {
                cipher.Init(false, parameters);

                byte[] rv = new byte[cipher.GetOutputSize(ct.Length)];
                random.NextBytes(rv); // should overwrite any existing data

                cipher.ProcessAadBytes(ad, 0, ad.Length);
                int len = cipher.ProcessBytes(ct, 0, ct.Length, rv, 0);
                len += cipher.DoFinal(rv, len);

                Assert.True(Arrays.AreEqual(rv, 0, len, pt, 0, pt.Length));
            }
        }
    }
}
