using System;
using System.Text;

using NUnit.Framework;

using Org.BouncyCastle.Crypto.Macs;
using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.Utilities;
using Org.BouncyCastle.Utilities.Encoders;
using Org.BouncyCastle.Utilities.Test;

namespace Org.BouncyCastle.Crypto.Tests
{
    [TestFixture]
    public class KMacTest
        : SimpleTest
    {
        public override string Name
        {
            get { return "KMAC"; }
        }

        public override void PerformTest()
        {
            KMac kmac = new KMac(128,  new byte[0] { });

            Assert.AreEqual("KMAC128", kmac.AlgorithmName);

            kmac.Init(new KeyParameter(Hex.Decode(
                "404142434445464748494A4B4C4D4E4F505152535455565758595A5B5C5D5E5F")));

            kmac.BlockUpdate(Hex.Decode("00010203"), 0, 4);

            byte[] res = new byte[32];

            kmac.OutputFinal(res, 0, res.Length);

            Assert.IsTrue( Arrays.AreEqual(Hex.Decode("E5780B0D3EA6F7D3A429C5706AA43A00FADBD7D49628839E3187243F456EE14E"), res), "oops: " + Hex.ToHexString(res));

            kmac = new KMac(128, Encoding.ASCII.GetBytes("My Tagged Application"));

            kmac.Init(new KeyParameter(Hex.Decode(
                "404142434445464748494A4B4C4D4E4F505152535455565758595A5B5C5D5E5F")));

            kmac.BlockUpdate(Hex.Decode("00010203"), 0, 4);

            res = new byte[32];

            kmac.OutputFinal(res, 0, res.Length);

            Assert.IsTrue( Arrays.AreEqual(Hex.Decode("3B1FBA963CD8B0B59E8C1A6D71888B7143651AF8BA0A7070C0979E2811324AA5"), res), "oops: " + Hex.ToHexString(res));

            kmac = new KMac(128, Encoding.ASCII.GetBytes("My Tagged Application"));

            kmac.Init(new KeyParameter(Hex.Decode(
                "404142434445464748494A4B4C4D4E4F505152535455565758595A5B5C5D5E5F")));

            byte[] data = Hex.Decode(
                "000102030405060708090A0B0C0D0E0F101112131415161718191A1B1C1D1E1" +
                    "F202122232425262728292A2B2C2D2E2F303132333435363738393A3B3C3D3" +
                    "E3F404142434445464748494A4B4C4D4E4F505152535455565758595A5B5C5" +
                    "D5E5F606162636465666768696A6B6C6D6E6F707172737475767778797A7B7" +
                    "C7D7E7F808182838485868788898A8B8C8D8E8F909192939495969798999A9" +
                    "B9C9D9E9FA0A1A2A3A4A5A6A7A8A9AAABACADAEAFB0B1B2B3B4B5B6B7B8B9B" +
                    "ABBBCBDBEBFC0C1C2C3C4C5C6C7");
            kmac.BlockUpdate(data, 0, data.Length);

            res = new byte[32];

            kmac.OutputFinal(res, 0, res.Length);

            Assert.IsTrue(Arrays.AreEqual(Hex.Decode("1F5B4E6CCA02209E0DCB5CA635B89A15E271ECC760071DFD805FAA38F9729230"), res), "oops:" + Hex.ToHexString(res));

            kmac = new KMac(256, Encoding.ASCII.GetBytes("My Tagged Application"));

            Assert.AreEqual("KMAC256", kmac.AlgorithmName);

            kmac.Init(new KeyParameter(Hex.Decode("404142434445464748494A4B4C4D4E4F505152535455565758595A5B5C5D5E5F")));

            data = Hex.Decode("00 01 02 03");
            kmac.BlockUpdate(data, 0, data.Length);

            res = new byte[64];

            kmac.OutputFinal(res, 0, res.Length);

            Assert.IsTrue(Arrays.AreEqual(Hex.Decode("20C570C31346F703C9AC36C61C03CB64C3970D0CFC787E9B79599D273A68D2F7F69D4CC3DE9D104A351689F27CF6F5951F0103F33F4F24871024D9C27773A8DD"), res), "oops:" + Hex.ToHexString(res));

            kmac = new KMac(256, new byte[] { });

            kmac.Init(new KeyParameter(Hex.Decode(
                "404142434445464748494A4B4C4D4E4F505152535455565758595A5B5C5D5E5F")));

            data = Hex.Decode(
                "000102030405060708090A0B0C0D0E0F101112131415161718191A1B1C1D1E1" +
                    "F202122232425262728292A2B2C2D2E2F303132333435363738393A3B3C3D3" +
                    "E3F404142434445464748494A4B4C4D4E4F505152535455565758595A5B5C5" +
                    "D5E5F606162636465666768696A6B6C6D6E6F707172737475767778797A7B7" +
                    "C7D7E7F808182838485868788898A8B8C8D8E8F909192939495969798999A9" +
                    "B9C9D9E9FA0A1A2A3A4A5A6A7A8A9AAABACADAEAFB0B1B2B3B4B5B6B7B8B9B" +
                    "ABBBCBDBEBFC0C1C2C3C4C5C6C7");
            kmac.BlockUpdate(data, 0, data.Length);

            res = new byte[64];

            kmac.OutputFinal(res, 0, res.Length);

            Assert.IsTrue(Arrays.AreEqual(Hex.Decode("75358CF39E41494E949707927CEE0AF20A3FF553904C86B08F21CC414BCFD691589D27CF5E15369CBBFF8B9A4C2EB17800855D0235FF635DA82533EC6B759B69"), res), "oops:" + Hex.ToHexString(res));

            kmac = new KMac(256, Encoding.ASCII.GetBytes("My Tagged Application"));

            kmac.Init(new KeyParameter(Hex.Decode(
                "404142434445464748494A4B4C4D4E4F505152535455565758595A5B5C5D5E5F")));

            data = Hex.Decode(
                "000102030405060708090A0B0C0D0E0F101112131415161718191A1B1C1D1E1" +
                    "F202122232425262728292A2B2C2D2E2F303132333435363738393A3B3C3D3" +
                    "E3F404142434445464748494A4B4C4D4E4F505152535455565758595A5B5C5" +
                    "D5E5F606162636465666768696A6B6C6D6E6F707172737475767778797A7B7" +
                    "C7D7E7F808182838485868788898A8B8C8D8E8F909192939495969798999A9" +
                    "B9C9D9E9FA0A1A2A3A4A5A6A7A8A9AAABACADAEAFB0B1B2B3B4B5B6B7B8B9B" +
                    "ABBBCBDBEBFC0C1C2C3C4C5C6C7");
            kmac.BlockUpdate(data, 0, data.Length);

            res = new byte[64];

            kmac.OutputFinal(res, 0, res.Length);

            Assert.IsTrue(Arrays.AreEqual(Hex.Decode("B58618F71F92E1D56C1B8C55DDD7CD188B97B4CA4D99831EB2699A837DA2E4D970FBACFDE50033AEA585F1A2708510C32D07880801BD182898FE476876FC8965"), res), "oops:" + Hex.ToHexString(res));

            doFinalTest();
            longBlockTest();
            paddingCheckTest();

            checkKMAC(128, new KMac(128, new byte[0]), Hex.Decode("eeaabeef"));
            checkKMAC(256, new KMac(256, null), Hex.Decode("eeaabeef"));
            checkKMAC(128, new KMac(128, new byte[0]), Hex.Decode("eeaabeef"));
            checkKMAC(128, new KMac(128, null), Hex.Decode("eeaabeef"));
            checkKMAC(256, new KMac(256, null), Hex.Decode("eeaabeef"));

        }

        private void doFinalTest()
        {
            KMac kmac = new KMac(128, Encoding.ASCII.GetBytes("My Tagged Application"));

            kmac.Init(new KeyParameter(Hex.Decode(
                "404142434445464748494A4B4C4D4E4F505152535455565758595A5B5C5D5E5F")));

            kmac.BlockUpdate(Hex.Decode("00010203"), 0, 4);

            byte[] res = new byte[32];

            kmac.Output(res, 0, res.Length);

            Assert.IsTrue(Arrays.AreEqual(Hex.Decode("31a44527b4ed9f5c6101d11de6d26f0620aa5c341def41299657fe9df1a3b16c"), res), Hex.ToHexString(res));

            kmac.Output(res, 0, res.Length);

            Assert.IsTrue(!Arrays.AreEqual(Hex.Decode("31a44527b4ed9f5c6101d11de6d26f0620aa5c341def41299657fe9df1a3b16c"), res));

            kmac.OutputFinal(res, 0, res.Length);

            kmac.BlockUpdate(Hex.Decode("00010203"), 0, 4);

            kmac.OutputFinal(res, 0, res.Length);

            Assert.IsTrue(Arrays.AreEqual(Hex.Decode("3B1FBA963CD8B0B59E8C1A6D71888B7143651AF8BA0A7070C0979E2811324AA5"), res));

            kmac.BlockUpdate(Hex.Decode("00010203"), 0, 4);

            kmac.Output(res, 0, res.Length);

            Assert.IsTrue(Arrays.AreEqual(Hex.Decode("31a44527b4ed9f5c6101d11de6d26f0620aa5c341def41299657fe9df1a3b16c"), res));

            kmac.OutputFinal(res, 0, res.Length);

            Assert.IsTrue(Arrays.AreEqual(Hex.Decode("ffcb48c7620ccd67d1c83224186892cef2f2a99278d5cfdde10e48bdc89718c2"), res), Hex.ToHexString(res));
        }

        private void longBlockTest()
        {
            byte[] data = new byte[16000];
            byte[] res = new byte[64];

            for (int i = 0; i != data.Length; i++)
            {
                data[i] = (byte)i;
            }

            for (int i = 10000; i != data.Length; i++)
            {
                KMac kmac_ = new KMac(128, Arrays.CopyOfRange(data, 0, i));

                kmac_.Init(new KeyParameter(new byte[0]));

                kmac_.BlockUpdate(Hex.Decode("00010203"), 0, 4);

                kmac_.DoFinal(res, 0);
            }

            KMac kmac = new KMac(256, new byte[200]);

            kmac.Init(new KeyParameter(new byte[0]));

            kmac.BlockUpdate(Arrays.CopyOfRange(data, 0, 200), 0, 200);

            kmac.DoFinal(res, 0);

            Assert.IsTrue(Arrays.AreEqual(Hex.Decode("f9476d9b3e42bf23307af5ccb5287fd6f033b23c400566a2ebc5829bd119aa545cd9b6bde76ef61cd31c3c0f0aaf0945f44481e863b19e9c26fb46c8b2a8a9bb"), res), Hex.ToHexString(res));
        }

        private void paddingCheckTest()
        {
            byte[] data = Hex.Decode("01880204187B3E43EDA8D51EC181D37DDE5B17ECCDD8BE84C268DC6C9500700857");
            byte[] out_ = new byte[32];

            KMac k128 = new KMac(128, new byte[0]);
            k128.Init(new KeyParameter(new byte[163]));
            k128.BlockUpdate(data, 0, data.Length);
            k128.Output(out_, 0, out_.Length);

            Assert.IsTrue( Arrays.AreEqual(out_, Hex.Decode("6e6ab56468c7445f81c679f89f45c90a95a9c01afbaab5f7065b7e2e96f7d2bb")),"128 failed");

            KMac k256 = new KMac(256, new byte[0]);
            k256.Init(new KeyParameter(new byte[131]));
            k256.BlockUpdate(data, 0, data.Length);
            k256.Output(out_, 0, out_.Length);

            Assert.IsTrue(Arrays.AreEqual(out_, Hex.Decode("f6302d4f854b4872e811b37993b6bfe027258089b6a9fbb26a755b1ebfc0d830")), "256 failed");
        }

        private void checkKMAC(int bitSize, KMac kmac, byte[] msg)
        {
            KMac ref_ = new KMac(bitSize, null);

            ref_.Init(new KeyParameter(new byte[0]));
            kmac.Init(new KeyParameter(new byte[0]));

            ref_.BlockUpdate(msg, 0, msg.Length);
            kmac.BlockUpdate(msg, 0, msg.Length);

            byte[] res1 = new byte[32];
            byte[] res2 = new byte[32];

            ref_.OutputFinal(res1, 0, res1.Length);
            kmac.OutputFinal(res2, 0, res2.Length);

            Assert.IsTrue(Arrays.AreEqual(res1, res2));
        }

        [Test]
        public void TestFunction()
        {
            string resultText = Perform().ToString();

            Assert.AreEqual(Name + ": Okay", resultText);
        }
    }
}
