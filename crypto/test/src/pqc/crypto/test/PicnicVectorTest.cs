using System;
using System.Collections.Generic;
using System.IO;

using NUnit.Framework;

using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Pqc.Crypto.Picnic;
using Org.BouncyCastle.Pqc.Crypto.Utilities;
using Org.BouncyCastle.Utilities;
using Org.BouncyCastle.Utilities.Encoders;
using Org.BouncyCastle.Utilities.Test;

namespace Org.BouncyCastle.Pqc.Crypto.Tests
{
    [TestFixture]
    public class PicnicVectorTest
    {
        [Test]
        public void TestVectors()
        {
        // bool full = System.getProperty("test.full", "false").equals("true");
        bool full = false;
        string[] files;
        PicnicParameters[] parameters;
        if (full)
        {
            files = new []{
                    "picnicl1fs.rsp",
                    "picnicl1ur.rsp",
                    "picnicl3fs.rsp",
                    "picnicl3ur.rsp",
                    "picnicl5fs.rsp",
                    "picnicl5ur.rsp",
                    "picnic3l1.rsp",
                    "picnic3l3.rsp",
                    "picnic3l5.rsp",
                    "picnicl1full.rsp",
                    "picnicl3full.rsp",
                    "picnicl5full.rsp",

            };
            parameters = new []{
                    PicnicParameters.picnicl1fs,
                    PicnicParameters.picnicl1ur,
                    PicnicParameters.picnicl3fs,
                    PicnicParameters.picnicl3ur,
                    PicnicParameters.picnicl5fs,
                    PicnicParameters.picnicl5ur,
                    PicnicParameters.picnic3l1,
                    PicnicParameters.picnic3l3,
                    PicnicParameters.picnic3l5,
                    PicnicParameters.picnicl1full,
                    PicnicParameters.picnicl3full,
                    PicnicParameters.picnicl5full
            };
        }
        else
        {
            files = new []{
                    "picnicl1fs.rsp",
                    "picnic3l1.rsp",
                    "picnicl3ur.rsp",
                    "picnicl1full.rsp",
            };
            parameters = new PicnicParameters[]{
                    PicnicParameters.picnicl1fs,
                    PicnicParameters.picnic3l1,
                    PicnicParameters.picnicl3ur,
                    PicnicParameters.picnicl1full,
            };
        }


        for (int fileIndex = 0; fileIndex != files.Length; fileIndex++)
        {
            String name = files[fileIndex];
            Console.Write("testing: " + name);
            StreamReader src = new StreamReader(SimpleTest.GetTestDataAsStream("pqc.picnic." + name));

            String line = null;
            Dictionary<String, String> buf = new Dictionary<string, string>();
            // Random rnd = new Random();
            while ((line = src.ReadLine()) != null)
            {
                line = line.Trim();

                if (line.StartsWith("#"))
                {
                    continue;
                }
                if (line.Length == 0)
                {
                    if (buf.Count > 0)
                    {
                        String count = buf["count"];
                        if (!"0".Equals(count))
                        {
                            // randomly skip tests after zero.
                            // if (rnd.NextDouble())
                            // {
                            //     continue;
                            // }
                        }
                        Console.Write($"test case: {count}\n");
                        byte[] seed = Hex.Decode(buf["seed"]);      // seed for picnic secure random
                        int mlen = Int32.Parse(buf["mlen"]);   // message length
                        byte[] msg = Hex.Decode(buf["msg"]);        // message
                        byte[] pk = Hex.Decode(buf["pk"]);          // public key
                        byte[] sk = Hex.Decode(buf["sk"]);          // private key
                        int smlen = Int32.Parse(buf["smlen"]); // signature length
                        byte[] sigExpected = Hex.Decode(buf["sm"]);          // signature

//                        System.out.println("message: " + Hex.toHexString(msg));
                        NistSecureRandom random = new NistSecureRandom(seed, null);
                        PicnicParameters picnicParameters = parameters[fileIndex];


                        PicnicKeyPairGenerator kpGen = new PicnicKeyPairGenerator();
                        PicnicKeyGenerationParameters genParams = new PicnicKeyGenerationParameters(random, picnicParameters);
                        //
                        // Generate keys and test.
                        //
                        kpGen.Init(genParams);
                        AsymmetricCipherKeyPair kp = kpGen.GenerateKeyPair();


                        PicnicPublicKeyParameters pubParams = (PicnicPublicKeyParameters) PublicKeyFactory.CreateKey(SubjectPublicKeyInfoFactory.CreateSubjectPublicKeyInfo(kp.Public));
                        PicnicPrivateKeyParameters privParams = (PicnicPrivateKeyParameters) PrivateKeyFactory.CreateKey(PrivateKeyInfoFactory.CreatePrivateKeyInfo(kp.Private));

//                        System.out.println("pk = " + Hex.toHexString(pubParams.getEncoded()).toUpperCase());
//                        System.out.println("sk = " + Hex.toHexString(privParams.getEncoded()).toUpperCase());

                        Assert.True(Arrays.AreEqual(pk, pubParams.GetEncoded()), name + " " + count + ": public key");
                        Assert.True(Arrays.AreEqual(sk, privParams.GetEncoded()), name + " " + count + ": secret key");


                        //
                        // Signature test
                        //
                        PicnicSigner signer = new PicnicSigner(random);

                        signer.Init(true, privParams);

                        byte[] sigGenerated = signer.GenerateSignature(msg);

                        // Console.WriteLine("expected:\t" + Hex.ToHexString(sigExpected));
                        // Console.WriteLine("generated:\t" + Hex.ToHexString(sigGenerated));

                        Assert.True(smlen == sigGenerated.Length, name + " " + count + ": signature length");

                        signer.Init(false, pubParams);

                        Assert.True(signer.VerifySignature(msg, sigGenerated), (name + " " + count + ": signature verify"));
                        Assert.True(Arrays.AreEqual(sigExpected, sigGenerated), name + " " + count + ": signature gen match");

                    }
                    buf.Clear();

                    continue;
                }

                int a = line.IndexOf('=');
                if (a > -1)
                {
                    buf[line.Substring(0, a).Trim()] =  line.Substring(a + 1).Trim();
                }
            }
            Console.Write("testing successful!");
        }
    }
    }
}