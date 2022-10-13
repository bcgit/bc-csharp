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
        [Test]
        public void TestVectors() {
            string[] files = {
                "falcon512-KAT.rsp",
                "falcon1024-KAT.rsp"
            };
            FalconParameters[] parameters = new FalconParameters[]{
                FalconParameters.falcon_512,
                FalconParameters.falcon_1024
            };

            TestSampler sampler = new TestSampler();
            for (int fileIndex = 0; fileIndex < files.Length; fileIndex++) {
                string name = files[fileIndex];
                Console.Write("testing: " + name);
                StreamReader src = new StreamReader(SimpleTest.GetTestDataAsStream("pqc.falcon." + name));
                string line = null;
                Dictionary<string, string> buf = new Dictionary<string, string>();
                while ((line = src.ReadLine()) != null)
                {
                    line = line.Trim();

                    if (line.StartsWith("#"))
                    {
                        continue;
                    }
                    if (line.Length == 0)
                    {
                        if (buf.Count > 0 && !sampler.SkipTest(buf["count"]))
                        {
                            string count = buf["count"];
                            Console.Write("test case: " + count);
                            byte[] seed = Hex.Decode(buf["seed"]); // seed for SecureRandom
                            byte[] pk = Hex.Decode(buf["pk"]);     // public key
                            byte[] sk = Hex.Decode(buf["sk"]);     // private key
                            byte[] sm = Hex.Decode(buf["sm"]);     // sm
                            byte[] msg = Hex.Decode(buf["msg"]);     // message
                            uint m_len = uint.Parse(buf["mlen"]);  // message length
                            uint sm_len = uint.Parse(buf["smlen"]); // sm length

                            NistSecureRandom random = new NistSecureRandom(seed, null);

                            // keygen
                            FalconKeyGenerationParameters kparam = new FalconKeyGenerationParameters(random, parameters[fileIndex]);
                            FalconKeyPairGenerator kpg = new FalconKeyPairGenerator();
                            kpg.Init(kparam);
                            AsymmetricCipherKeyPair ackp = kpg.GenerateKeyPair();
                            byte[] respk = ((FalconPublicKeyParameters) ackp.Public).GetEncoded();
                            byte[] ressk = ((FalconPrivateKeyParameters) ackp.Private).GetEncoded();
                            
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
                            noncesig[0] = (byte)(0x30 + parameters[fileIndex].LogN);
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
                        buf.Clear();

                        continue;
                    }
                    int a = line.IndexOf("=");
                    if (a > -1) {
                        buf[line.Substring(0, a).Trim()] = line.Substring(a + 1).Trim();
                    }
                }
                Console.Write("testing successful!");
            }
        }
    }
}
