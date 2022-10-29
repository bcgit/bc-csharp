using System.Collections.Generic;
using System.IO;

using NUnit.Framework;

using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Pqc.Crypto.Crystals.Dilithium;
using Org.BouncyCastle.Pqc.Crypto.Utilities;
using Org.BouncyCastle.Utilities;
using Org.BouncyCastle.Utilities.Encoders;
using Org.BouncyCastle.Utilities.Test;

namespace Org.BouncyCastle.Pqc.Crypto.Tests
{
    [TestFixture]
    public class CrystalsDilithiumTest
    {
        private static readonly Dictionary<string, DilithiumParameters> Parameters = new Dictionary<string, DilithiumParameters>()
        {
            { "PQCsignKAT_Dilithium2.rsp", DilithiumParameters.Dilithium2 },
            { "PQCsignKAT_Dilithium3.rsp", DilithiumParameters.Dilithium3 },
            { "PQCsignKAT_Dilithium5.rsp", DilithiumParameters.Dilithium5 },
            { "PQCsignKAT_Dilithium2-AES.rsp", DilithiumParameters.Dilithium2Aes },
            { "PQCsignKAT_Dilithium3-AES.rsp", DilithiumParameters.Dilithium3Aes },
            { "PQCsignKAT_Dilithium5-AES.rsp", DilithiumParameters.Dilithium5Aes },
        };

        private static readonly string[] TestVectorFiles =
        {
            "PQCsignKAT_Dilithium2.rsp",
            "PQCsignKAT_Dilithium3.rsp",
            "PQCsignKAT_Dilithium5.rsp",
        };

        private static readonly string[] TestVectorFilesAes =
        {
            "PQCsignKAT_Dilithium2-AES.rsp",
            "PQCsignKAT_Dilithium3-AES.rsp",
            "PQCsignKAT_Dilithium5-AES.rsp",
        };

        [TestCaseSource(nameof(TestVectorFiles))]
        [Parallelizable(ParallelScope.All)]
        public void TV(string testVectorFile)
        {
            RunTestVectorFile(testVectorFile);
        }

        [TestCaseSource(nameof(TestVectorFilesAes))]
        [Parallelizable(ParallelScope.All)]
        public void TVAes(string testVectorFile)
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
            byte[] sm = Hex.Decode(buf["sm"]);          // signature

            NistSecureRandom random = new NistSecureRandom(seed, null);
            DilithiumParameters dilithiumparameters = Parameters[name];

            DilithiumKeyPairGenerator kpGen = new DilithiumKeyPairGenerator();
            DilithiumKeyGenerationParameters genParams =
                new DilithiumKeyGenerationParameters(random, dilithiumparameters);

            //
            // Generate keys and test.
            //
            kpGen.Init(genParams);
            AsymmetricCipherKeyPair ackp = kpGen.GenerateKeyPair();


            DilithiumPublicKeyParameters pubParams = (DilithiumPublicKeyParameters)ackp.Public;
            DilithiumPrivateKeyParameters privParams = (DilithiumPrivateKeyParameters)ackp.Private;

            //Console.WriteLine(string.Format("{0} Expected pk       = {1}", pk.Length, Convert.ToHexString(pk)));
            //Console.WriteLine(String.Format("{0} Actual Public key = {1}", pubParams.GetEncoded().Length, Convert.ToHexString(pubParams.GetEncoded())));

            pubParams = (DilithiumPublicKeyParameters)PublicKeyFactory.CreateKey(SubjectPublicKeyInfoFactory.CreateSubjectPublicKeyInfo(ackp.Public));
            privParams = (DilithiumPrivateKeyParameters)PrivateKeyFactory.CreateKey(PrivateKeyInfoFactory.CreatePrivateKeyInfo(ackp.Private));

            Assert.True(Arrays.AreEqual(pk, pubParams.GetEncoded()), name + " " + count + ": public key");
            Assert.True(Arrays.AreEqual(sk, privParams.GetEncoded()), name + " " + count + ": secret key");

            //
            // Signature test
            //
            DilithiumSigner signer = new DilithiumSigner();
            DilithiumPrivateKeyParameters skparam = (DilithiumPrivateKeyParameters)ackp.Private;

            signer.Init(true, skparam);
            byte[] sigGenerated = signer.GenerateSignature(msg);
            byte[] attachedSig = Arrays.ConcatenateAll(sigGenerated, msg);

            //
            // Verify
            //
            DilithiumSigner verifier = new DilithiumSigner();
            DilithiumPublicKeyParameters pkparam = pubParams;
            verifier.Init(false, pkparam);
                
            bool vrfyrespass = verifier.VerifySignature(msg, sigGenerated);
            sigGenerated[3]++; // changing the signature by 1 byte should cause it to fail
            bool vrfyresfail = verifier.VerifySignature(msg, sigGenerated);
            
            Assert.True(Arrays.AreEqual(attachedSig, sm), name + " " + count + " signature");
            //verify
            Assert.True(vrfyrespass, name + " " + count + " verify failed when should pass");
            Assert.False(vrfyresfail, name + " " + count + " verify passed when should fail");
        }

        public static void RunTestVectorFile(string name)
        {
            var buf = new Dictionary<string, string>();
            TestSampler sampler = new TestSampler();
            using (var src = new StreamReader(SimpleTest.GetTestDataAsStream("pqc.crystals.dilithium." + name)))
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
