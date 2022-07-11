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
        private static readonly Dictionary<string, PicnicParameters> parameters = new Dictionary<string, PicnicParameters>()
        {
            { "picnicl1fs.rsp", PicnicParameters.picnicl1fs },
            { "picnicl1ur.rsp", PicnicParameters.picnicl1ur },
            { "picnicl3fs.rsp", PicnicParameters.picnicl3fs },
            { "picnicl3ur.rsp", PicnicParameters.picnicl3ur },
            { "picnicl5fs.rsp", PicnicParameters.picnicl5fs },
            { "picnicl5ur.rsp", PicnicParameters.picnicl5ur },
            { "picnic3l1.rsp", PicnicParameters.picnic3l1 },
            { "picnic3l3.rsp", PicnicParameters.picnic3l3 },
            { "picnic3l5.rsp", PicnicParameters.picnic3l5 },
            { "picnicl1full.rsp", PicnicParameters.picnicl1full },
            { "picnicl3full.rsp", PicnicParameters.picnicl3full },
            { "picnicl5full.rsp", PicnicParameters.picnicl5full },
        };

        private static readonly string[] TestVectorFilesBasic =
        {
            "picnicl1fs.rsp",
            "picnicl3ur.rsp",
            "picnic3l1.rsp",
            "picnicl1full.rsp",
        };

        private static readonly string[] TestVectorFilesExtra =
        {
            "picnicl1ur.rsp",
            "picnicl3fs.rsp",
            "picnicl5fs.rsp",
            "picnicl5ur.rsp",
            "picnic3l3.rsp",
            "picnic3l5.rsp",
            "picnicl3full.rsp",
            "picnicl5full.rsp",
        };

        [TestCaseSource(nameof(TestVectorFilesBasic))]
        [Parallelizable(ParallelScope.All)]
        public void TestVectorsBasic(string testVectorFile)
        {
            RunTestVectorFile(testVectorFile);
        }

        [Explicit, TestCaseSource(nameof(TestVectorFilesExtra))]
        [Parallelizable(ParallelScope.All)]
        public void TestVectorsExtra(string testVectorFile)
        {
            RunTestVectorFile(testVectorFile);
        }

        private static void RunTestVector(string name, IDictionary<string, string> buf)
        {
            string count = buf["count"];
            byte[] seed = Hex.Decode(buf["seed"]);      // seed for picnic secure random
            int mlen = int.Parse(buf["mlen"]);          // message length
            byte[] msg = Hex.Decode(buf["msg"]);        // message
            byte[] pk = Hex.Decode(buf["pk"]);          // public key
            byte[] sk = Hex.Decode(buf["sk"]);          // private key
            int smlen = int.Parse(buf["smlen"]);        // signature length
            byte[] sigExpected = Hex.Decode(buf["sm"]); // signature

            NistSecureRandom random = new NistSecureRandom(seed, null);
            PicnicParameters picnicParameters = parameters[name];

            PicnicKeyPairGenerator kpGen = new PicnicKeyPairGenerator();
            PicnicKeyGenerationParameters genParams = new PicnicKeyGenerationParameters(random, picnicParameters);

            //
            // Generate keys and test.
            //
            kpGen.Init(genParams);
            AsymmetricCipherKeyPair kp = kpGen.GenerateKeyPair();


            PicnicPublicKeyParameters pubParams = (PicnicPublicKeyParameters)PublicKeyFactory.CreateKey(SubjectPublicKeyInfoFactory.CreateSubjectPublicKeyInfo(kp.Public));
            PicnicPrivateKeyParameters privParams = (PicnicPrivateKeyParameters)PrivateKeyFactory.CreateKey(PrivateKeyInfoFactory.CreatePrivateKeyInfo(kp.Private));

            Assert.True(Arrays.AreEqual(pk, pubParams.GetEncoded()), name + " " + count + ": public key");
            Assert.True(Arrays.AreEqual(sk, privParams.GetEncoded()), name + " " + count + ": secret key");

            //
            // Signature test
            //
            PicnicSigner signer = new PicnicSigner(random);

            signer.Init(true, privParams);
            byte[] sigGenerated = signer.GenerateSignature(msg);
            Assert.True(smlen == sigGenerated.Length, name + " " + count + ": signature length");

            signer.Init(false, pubParams);
            Assert.True(signer.VerifySignature(msg, sigGenerated), (name + " " + count + ": signature verify"));
            Assert.True(Arrays.AreEqual(sigExpected, sigGenerated), name + " " + count + ": signature gen match");
        }

        private static void RunTestVectorFile(string name)
        {
            var buf = new Dictionary<string, string>();

            using (var src = new StreamReader(SimpleTest.GetTestDataAsStream("pqc.picnic." + name)))
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
                        if (a > -1)
                        {
                            buf[line.Substring(0, a).Trim()] = line.Substring(a + 1).Trim();
                        }
                        continue;
                    }

                    if (buf.Count > 0)
                    {
                        RunTestVector(name, buf);
                        buf.Clear();
                    }
                }

                if (buf.Count > 0)
                {
                    RunTestVector(name, buf);
                }
            }
        }
    }
}
