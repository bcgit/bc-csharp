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
    public class ElephantTest : SimpleTest
    {
        public override string Name
        {
            get { return "Photon-Beetle"; }
        }

        [Test]
        public override void PerformTest()
        {
            testVectors(ElephantEngine.ElephantParameters.elephant160, "v160");
            testVectors(ElephantEngine.ElephantParameters.elephant176, "v176");
            testVectors(ElephantEngine.ElephantParameters.elephant200, "v200");
        }

        private void testVectors(ElephantEngine.ElephantParameters pbp, String filename)
        {
            ElephantEngine Elephant = new ElephantEngine(pbp);
            ICipherParameters param;
            var buf = new Dictionary<string, string>();
            //TestSampler sampler = new TestSampler();
            using (var src = new StreamReader(SimpleTest.GetTestDataAsStream("crypto.elephant." + filename + "_LWC_AEAD_KAT_128_96.txt")))
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
                        Elephant.Init(true, param);
                        adByte = Hex.Decode(map["AD"]);
                        Elephant.ProcessAadBytes(adByte, 0, adByte.Length);
                        ptByte = Hex.Decode(map["PT"]);
                        rv = new byte[Elephant.GetOutputSize(ptByte.Length)];
                        Elephant.ProcessBytes(ptByte, 0, ptByte.Length, rv, 0);
                        Elephant.DoFinal(rv, ptByte.Length);
                        //foreach (byte b in Hex.Decode(map["CT"]))
                        //{
                        //    Console.Write(b.ToString("X2"));
                        //}
                        //Console.WriteLine();
                        //foreach (byte b in rv)
                        //{
                        //    Console.Write(b.ToString("X2"));
                        //}
                        //Console.WriteLine();
                        Assert.True(Arrays.AreEqual(rv, Hex.Decode(map["CT"])));
                        //Console.WriteLine(map["Count"] + " pass");
                        map.Clear();
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
    }
}

