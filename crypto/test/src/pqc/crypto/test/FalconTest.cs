using System;
using System.Collections.Generic;
using System.IO;

using NUnit.Framework;

using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.Pqc.Crypto.Falcon;
using Org.BouncyCastle.Utilities;
using Org.BouncyCastle.Utilities.Encoders;
using Org.BouncyCastle.Utilities.Test;

namespace Org.BouncyCastle.Pqc.Crypto.Tests
{
    [TestFixture]
    public class FalconTest
    {
        private static readonly Dictionary<string, FalconParameters> Parameters = new Dictionary<string, FalconParameters>()
        {
            { "falcon512-KAT.rsp", FalconParameters.falcon_512 },
            { "falcon1024-KAT.rsp", FalconParameters.falcon_1024 },
        };

        private static readonly string[] TestVectorFiles =
        {
            "falcon512-KAT.rsp",
            "falcon1024-KAT.rsp",
        };

        [Test]
        public void TestParameters()
        {
            Assert.AreEqual(9, FalconParameters.falcon_512.LogN);
            Assert.AreEqual(10, FalconParameters.falcon_1024.LogN);
        }

        [TestCaseSource(nameof(TestVectorFiles))]
        [Parallelizable(ParallelScope.All)]
        public void TV(string testVectorFile)
        {
            RunTestVectorFile(testVectorFile);
        }

        private static void RunTestVector(string name, IDictionary<string, string> buf)
        {
            string count = buf["count"];
            byte[] seed = Hex.Decode(buf["seed"]); // seed for SecureRandom
            byte[] pk = Hex.Decode(buf["pk"]);     // public key
            byte[] sk = Hex.Decode(buf["sk"]);     // private key
            byte[] sm = Hex.Decode(buf["sm"]);     // sm
            byte[] msg = Hex.Decode(buf["msg"]);     // message
            uint m_len = uint.Parse(buf["mlen"]);  // message length
            uint sm_len = uint.Parse(buf["smlen"]); // sm length

            NistSecureRandom random = new NistSecureRandom(seed, null);
            FalconParameters falconParameters = Parameters[name];

            // keygen
            FalconKeyGenerationParameters kparam = new FalconKeyGenerationParameters(random, falconParameters);
            FalconKeyPairGenerator kpg = new FalconKeyPairGenerator();
            kpg.Init(kparam);
            AsymmetricCipherKeyPair ackp = kpg.GenerateKeyPair();
            byte[] respk = ((FalconPublicKeyParameters)ackp.Public).GetEncoded();
            byte[] ressk = ((FalconPrivateKeyParameters)ackp.Private).GetEncoded();
                            
            //keygen
            Assert.True(Arrays.AreEqual(respk, 0, respk.Length, pk, 1, pk.Length), name + " " + count + " public key");
            Assert.True(Arrays.AreEqual(ressk, 0, ressk.Length, sk, 1, sk.Length), name + " " + count + " private key");

            // sign
            FalconSigner signer = new FalconSigner();
            ParametersWithRandom skwrand = new ParametersWithRandom(ackp.Private, random);
            signer.Init(true, skwrand);
            byte[] sig = signer.GenerateSignature(msg);
            byte[] ressm = new byte[2 + msg.Length + sig.Length - 1];
            ressm[0] = (byte)((sig.Length - 40 - 1) >> 8);
            ressm[1] = (byte)(sig.Length - 40 - 1);
            Array.Copy(sig, 1, ressm, 2, 40);
            Array.Copy(msg, 0, ressm, 2 + 40, msg.Length);
            Array.Copy(sig, 40 + 1, ressm, 2 + 40 + msg.Length, sig.Length - 40 - 1);

            // verify
            FalconSigner verifier = new FalconSigner();
            FalconPublicKeyParameters pkparam = (FalconPublicKeyParameters)ackp.Public;
            verifier.Init(false, pkparam);
            byte[] noncesig = new byte[sm_len - m_len - 2 + 1];
            noncesig[0] = (byte)(0x30 + falconParameters.LogN);
            Array.Copy(sm, 2, noncesig, 1, 40);
            Array.Copy(sm, 2 + 40 + m_len, noncesig, 40 + 1, sm_len - 2 - 40 - m_len);
            bool vrfyrespass = verifier.VerifySignature(msg, noncesig);
            noncesig[42]++; // changing the signature by 1 byte should cause it to fail
            bool vrfyresfail = verifier.VerifySignature(msg, noncesig);
                            
            //sign
            Assert.True(Arrays.AreEqual(ressm, sm), name + " " + count + " signature");
            //verify
            Assert.True(vrfyrespass, name + " " + count + " verify failed when should pass");
            Assert.False(vrfyresfail, name + " " + count + " verify passed when should fail");
        }

        private static void RunTestVectorFile(string name)
        {
            var buf = new Dictionary<string, string>();
            TestSampler sampler = new TestSampler();
            using (var src = new StreamReader(SimpleTest.GetTestDataAsStream("pqc.falcon." + name)))
            {
                string line;
                while ((line = src.ReadLine()) != null)
                {
                    line = line.Trim();
                    if (line.StartsWith("#"))
                        continue;

                    if (line.Length > 0)
                    {
                        int a = line.IndexOf("=");
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
