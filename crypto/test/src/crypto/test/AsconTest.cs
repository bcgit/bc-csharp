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

namespace BouncyCastle.Crypto.Tests
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
                        Ascon.Init(true, param);
                        adByte = Hex.Decode(map["AD"]);
                        Ascon.ProcessAadBytes(adByte, 0, adByte.Length);
                        ptByte = Hex.Decode(map["PT"]);
                        rv = new byte[Ascon.GetOutputSize(ptByte.Length)];
                        Ascon.ProcessBytes(ptByte, 0, ptByte.Length, rv, 0);
                        //byte[] mac = new byte[16];
                        Ascon.DoFinal(rv, ptByte.Length);
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
                        Ascon.Reset();
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
    }
}
