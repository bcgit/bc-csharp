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
        private static readonly Dictionary<string, PicnicParameters> Parameters = new Dictionary<string, PicnicParameters>()
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

        private static readonly IEnumerable<string> TestVectorFiles = Parameters.Keys;

        [TestCaseSource(nameof(TestVectorFiles))]
        [Parallelizable(ParallelScope.All)]
        public void TV(string testVectorFile)
        {
            RunTestVectorFile(testVectorFile);
        }

        private static void RunTestVector(string name, IDictionary<string, string> buf)
        {
            string count = buf["count"];
            byte[] seed = Hex.Decode(buf["seed"]);      // seed for SecureRandom
            int mlen = int.Parse(buf["mlen"]);          // message length
            byte[] msg = Hex.Decode(buf["msg"]);        // message
            byte[] pk = Hex.Decode(buf["pk"]);          // public key
            byte[] sk = Hex.Decode(buf["sk"]);          // private key
            int smlen = int.Parse(buf["smlen"]);        // signature length
            byte[] sigExpected = Hex.Decode(buf["sm"]); // signature

            NistSecureRandom random = new NistSecureRandom(seed, null);
            PicnicParameters picnicParameters = Parameters[name];

            PicnicKeyPairGenerator kpGen = new PicnicKeyPairGenerator();
            PicnicKeyGenerationParameters genParams = new PicnicKeyGenerationParameters(random, picnicParameters);

            //
            // Generate keys and test.
            //
            kpGen.Init(genParams);
            AsymmetricCipherKeyPair kp = kpGen.GenerateKeyPair();


            PicnicPublicKeyParameters pubParams = (PicnicPublicKeyParameters)PqcPublicKeyFactory.CreateKey(PqcSubjectPublicKeyInfoFactory.CreateSubjectPublicKeyInfo(kp.Public));
            PicnicPrivateKeyParameters privParams = (PicnicPrivateKeyParameters)PqcPrivateKeyFactory.CreateKey(PqcPrivateKeyInfoFactory.CreatePrivateKeyInfo(kp.Private));

            Assert.True(Arrays.AreEqual(pk, pubParams.GetEncoded()), name + " " + count + ": public key");
            Assert.True(Arrays.AreEqual(sk, privParams.GetEncoded()), name + " " + count + ": secret key");

            //
            // Signature test
            //
            PicnicSigner signer = new PicnicSigner();

            signer.Init(true, privParams);
            byte[] sigGenerated = signer.GenerateSignature(msg);
            byte[] attachedSig = Arrays.ConcatenateAll(UInt32_To_LE((uint)sigGenerated.Length), msg, sigGenerated);
            
            Assert.True(smlen == attachedSig.Length, name + " " + count + ": signature length");

            signer.Init(false, pubParams);
            Assert.True(signer.VerifySignature(msg, attachedSig), (name + " " + count + ": signature verify"));
            Assert.True(Arrays.AreEqual(sigExpected, attachedSig), name + " " + count + ": signature gen match");
        }

        private static byte[] UInt32_To_LE(uint n)
        {
            byte[] bs = new byte[4];
            bs[0] = (byte)(n);
            bs[1] = (byte)(n >> 8);
            bs[2] = (byte)(n >> 16);
            bs[3] = (byte)(n >> 24);
            return bs;
        }

        private static void RunTestVectorFile(string name)
        {
            var buf = new Dictionary<string, string>();
            TestSampler sampler = new TestSampler();
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
                        if (!sampler.SkipTest(buf["count"]))
                        {
                            RunTestVector(name, buf);
                        }
                        buf.Clear();
                    }
                }

                if (buf.Count > 0)
                {
                    if (!sampler.SkipTest(buf["count"]))
                    {
                        RunTestVector(name, buf);
                    }
                    buf.Clear();
                }
            }
        }
    }
}
