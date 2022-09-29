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
    public class Grain128AeadTest : SimpleTest
    {
        public override string Name
        {
            get { return "Grain-128Aead"; }
        }

        [Test]
        public override void PerformTest()
        {
            testVectors();
            testSplitUpdate();
            testLongAead();
            testExceptions();
        }


        private void testVectors()
        {
            Grain128AeadEngine grain = new Grain128AeadEngine();
            ICipherParameters param;
            var buf = new Dictionary<string, string>();
            //TestSampler sampler = new TestSampler();
            using (var src = new StreamReader(SimpleTest.GetTestDataAsStream("crypto.LWC_Aead_KAT_128_96.txt")))
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
                        param = new ParametersWithIV(new KeyParameter(Hex.Decode(map["Key"])), Hex.Decode(map["Nonce"]));
                        grain.Init(true, param);
                        adByte = Hex.Decode(map["AD"]);
                        grain.ProcessAADBytes(adByte, 0, adByte.Length);
                        ptByte = Hex.Decode(map["PT"]);
                        rv = new byte[ptByte.Length];
                        grain.ProcessBytes(ptByte, 0, ptByte.Length, rv, 0);
                        byte[] mac = new byte[8];
                        grain.DoFinal(mac, 0);
                        Assert.True(Arrays.AreEqual(Arrays.Concatenate(rv, mac), Hex.Decode(map["CT"])));
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
        }

        private void testSplitUpdate()
        {
            byte[] Key = Hex.Decode("000102030405060708090A0B0C0D0E0F");
            byte[] Nonce = Hex.Decode("000102030405060708090A0B");
            byte[] PT = Hex.Decode("000102030405060708090A0B0C0D0E0F101112131415161718191A1B1C1D1E1F");
            byte[] AD = Hex.Decode("000102030405060708090A0B0C0D0E0F101112131415161718191A1B1C1D1E");
            byte[] CT = Hex.Decode("EAD60EF559493ACEF6A3C238C018835DE3ABB6AA621A9AA65EFAF7B9D05BBE6C0913DFC8674BACC9");

            Grain128AeadEngine grain = new Grain128AeadEngine();
            ParametersWithIV param = new ParametersWithIV(new KeyParameter(Key), Nonce);
            grain.Init(true, param);

            grain.ProcessAADBytes(AD, 0, 10);
            grain.ProcessAADByte(AD[10]);
            grain.ProcessAADBytes(AD, 11, AD.Length - 11);

            byte[] rv = new byte[CT.Length];
            int len = grain.ProcessBytes(PT, 0, 10, rv, 0);
            len += grain.ProcessByte(PT[10], rv, len);
            len += grain.ProcessBytes(PT, 11, PT.Length - 11, rv, len);

            grain.DoFinal(rv, len);

            Assert.True(Arrays.AreEqual(rv, CT));

            grain.ProcessBytes(PT, 0, 10, rv, 0);
            try
            {
                grain.ProcessAADByte((byte)0x01);
                Assert.Fail("no exception");
            }
            catch (ArgumentException e)
            {
                Assert.IsTrue(Contains(e.Message, "associated data must be added before plaintext/ciphertext"));
            }

            try
            {
                grain.ProcessAADBytes(AD, 0, AD.Length);
                Assert.Fail("no exception");
            }
            catch (ArgumentException e)
            {
                Assert.IsTrue(Contains(e.Message, "associated data must be added before plaintext/ciphertext"));
            }
        }

        private bool Contains(string message, string sub)
        {
            return message.IndexOf(sub) >= 0;
        }

        private void testLongAead()
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

            grain.ProcessAADBytes(AD, 0, AD.Length);

            byte[] rv = new byte[CT.Length];
            int len = grain.ProcessBytes(PT, 0, 10, rv, 0);
            len += grain.ProcessByte(PT[10], rv, len);
            len += grain.ProcessBytes(PT, 11, PT.Length - 11, rv, len);

            grain.DoFinal(rv, len);

            Assert.IsTrue(Arrays.AreEqual(rv, CT));

            grain.ProcessBytes(PT, 0, 10, rv, 0);
            try
            {
                grain.ProcessAADByte((byte)0x01);
                Assert.Fail("no exception");
            }
            catch (ArgumentException e)
            {
                Assert.IsTrue(Contains(e.Message, "associated data must be added before plaintext/ciphertext"));
            }

            try
            {
                grain.ProcessAADBytes(AD, 0, AD.Length);
                Assert.Fail("no exception");
            }
            catch (ArgumentException e)
            {
                Assert.IsTrue(Contains(e.Message, "associated data must be added before plaintext/ciphertext"));
            }
        }

        private void testExceptions()

        {
            try
            {
                Grain128AeadEngine grain128 = new Grain128AeadEngine();

                grain128.Init(true, new KeyParameter(new byte[10]));
                Assert.Fail("no exception");
            }
            catch (ArgumentException e)
            {
                Assert.IsTrue(Contains(e.Message, "Grain-128Aead Init parameters must include an IV"));
            }

            try
            {
                Grain128AeadEngine grain128 = new Grain128AeadEngine();

                grain128.Init(true, new ParametersWithIV(new KeyParameter(new byte[10]), new byte[8]));
                Assert.Fail("no exception");
            }
            catch (ArgumentException e)
            {
                Assert.IsTrue(Contains(e.Message, "Grain-128Aead requires exactly 12 bytes of IV"));
            }

            try
            {
                Grain128AeadEngine grain128 = new Grain128AeadEngine();

                grain128.Init(true, new ParametersWithIV(new KeyParameter(new byte[10]), new byte[12]));
                Assert.Fail("no exception");
            }
            catch (ArgumentException e)
            {
                Assert.IsTrue(Contains(e.Message, "Grain-128Aead key must be 128 bits long"));
            }
        }

    }
}

