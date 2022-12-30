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

namespace BouncyCastle.Crypto.Tests
{
    [TestFixture]
    public class SparkleTest : SimpleTest
    {
        public override string Name
        {
            get { return "Sparkle"; }
        }

        [Test]
        public override void PerformTest()
        {
            testVectors("128_128", SparkleEngine.SparkleParameters.SCHWAEMM128_128);
            testVectors("192_192", SparkleEngine.SparkleParameters.SCHWAEMM192_192);
            testVectors("128_256", SparkleEngine.SparkleParameters.SCHWAEMM256_128);
            testVectors("256_256", SparkleEngine.SparkleParameters.SCHWAEMM256_256);
            testVectors("256", SparkleDigest.SparkleParameters.ESCH256);
            testVectors("384", SparkleDigest.SparkleParameters.ESCH384);
        }

        private void testVectors(String filename, SparkleEngine.SparkleParameters SparkleType)
        {
            SparkleEngine Sparkle = new SparkleEngine(SparkleType);
            ICipherParameters param;
            var buf = new Dictionary<string, string>();
            //TestSampler sampler = new TestSampler();
            using (var src = new StreamReader(SimpleTest.GetTestDataAsStream("crypto.sparkle.LWC_AEAD_KAT_" + filename + ".txt")))
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
                        //if (!map["Count"].Equals("2"))
                        //{
                        //    continue;
                        //}
                        param = new ParametersWithIV(new KeyParameter(Hex.Decode(map["Key"])), Hex.Decode(map["Nonce"]));
                        Sparkle.Init(true, param);
                        adByte = Hex.Decode(map["AD"]);
                        Sparkle.ProcessAadBytes(adByte, 0, adByte.Length);
                        ptByte = Hex.Decode(map["PT"]);
                        rv = new byte[Sparkle.GetOutputSize(ptByte.Length)];
                        Sparkle.ProcessBytes(ptByte, 0, ptByte.Length, rv, 0);
                        //byte[] mac = new byte[16];
                        Sparkle.DoFinal(rv, ptByte.Length);
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
                        Assert.True(Arrays.AreEqual(rv, Hex.Decode(map["CT"])));
                        //Console.WriteLine(map["Count"] + " pass");
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
            Console.WriteLine("Sparkle AEAD pass");
        }

        private void testVectors(String filename, SparkleDigest.SparkleParameters SparkleType)
        {
            SparkleDigest Sparkle = new SparkleDigest(SparkleType);
            var buf = new Dictionary<string, string>();
            //TestSampler sampler = new TestSampler();
            using (var src = new StreamReader(SimpleTest.GetTestDataAsStream("crypto.sparkle.LWC_HASH_KAT_" + filename + ".txt")))
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
                        Sparkle.BlockUpdate(ptByte, 0, ptByte.Length);
                        byte[] hash = new byte[Sparkle.GetDigestSize()];
                        Sparkle.DoFinal(hash, 0);
                        Assert.True(Arrays.AreEqual(hash, Hex.Decode(map["MD"])));
                        //Console.WriteLine(map["Count"] + " pass");
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
            Console.WriteLine("Sparkle Hash pass");
        }
    }
}
