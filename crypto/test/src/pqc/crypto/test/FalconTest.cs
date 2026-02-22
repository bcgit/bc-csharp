using System;
using System.Collections.Generic;

using NUnit.Framework;

using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.Pqc.Crypto.Falcon;
using Org.BouncyCastle.Pqc.Crypto.Utilities;
using Org.BouncyCastle.Security;
using Org.BouncyCastle.Utilities;
using Org.BouncyCastle.Utilities.Encoders;

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

        private static readonly IEnumerable<string> TestVectorFiles = Parameters.Keys;

        [Test]
        public void TestParameters()
        {
            Assert.AreEqual(9, FalconParameters.falcon_512.LogN);
            Assert.AreEqual(10, FalconParameters.falcon_1024.LogN);
        }

        [Test]
        public void TestRandom()
        {
            SecureRandom random = new SecureRandom();
            byte[] msg = Strings.ToByteArray("Hello World!");

            FalconKeyPairGenerator keyGen = new FalconKeyPairGenerator();
            keyGen.Init(new FalconKeyGenerationParameters(random, FalconParameters.falcon_512));

            for (int i = 0; i < 10; ++i)
            {
                AsymmetricCipherKeyPair keyPair = keyGen.GenerateKeyPair();

                var privParams = (FalconPrivateKeyParameters)keyPair.Private;
                var pubParams = (FalconPublicKeyParameters)keyPair.Public;

                privParams = (FalconPrivateKeyParameters)PqcPrivateKeyFactory.CreateKey(
                    PqcPrivateKeyInfoFactory.CreatePrivateKeyInfo(privParams));
                pubParams = (FalconPublicKeyParameters)PqcPublicKeyFactory.CreateKey(
                    PqcSubjectPublicKeyInfoFactory.CreateSubjectPublicKeyInfo(pubParams));

                for (int j = 0; j < 10; ++j)
                {
                    // sign
                    FalconSigner signer = new FalconSigner();
                    signer.Init(true, new ParametersWithRandom(privParams, random));
                    byte[] signature = signer.GenerateSignature(msg);

                    // verify
                    FalconSigner verifier = new FalconSigner();
                    verifier.Init(false, pubParams);
                    bool verified = verifier.VerifySignature(msg, signature);

                    Assert.True(verified, "count = " + i);
                }
            }
        }

        [TestCaseSource(nameof(TestVectorFiles))]
        [Parallelizable(ParallelScope.All)]
        public void TV(string testVectorFile) =>
            PqcTestUtilities.RunTestVectors("pqc/crypto/falcon", testVectorFile, sampleOnly: true, RunTestVector);

        private static void RunTestVector(string path, Dictionary<string, string> data)
        {
            string count = data["count"];
            byte[] seed = Hex.Decode(data["seed"]); // seed for SecureRandom
            byte[] pk = Hex.Decode(data["pk"]);     // public key
            byte[] sk = Hex.Decode(data["sk"]);     // private key
            byte[] sm = Hex.Decode(data["sm"]);     // sm
            byte[] msg = Hex.Decode(data["msg"]);     // message
            uint m_len = uint.Parse(data["mlen"]);  // message length
            uint sm_len = uint.Parse(data["smlen"]); // sm length

            NistSecureRandom random = new NistSecureRandom(seed, null);
            FalconParameters falconParameters = Parameters[path];

            // keygen
            FalconKeyGenerationParameters kparam = new FalconKeyGenerationParameters(random, falconParameters);
            FalconKeyPairGenerator kpg = new FalconKeyPairGenerator();
            kpg.Init(kparam);
            AsymmetricCipherKeyPair kp = kpg.GenerateKeyPair();

            FalconPublicKeyParameters pubParams = (FalconPublicKeyParameters)PqcPublicKeyFactory.CreateKey(
                PqcSubjectPublicKeyInfoFactory.CreateSubjectPublicKeyInfo((FalconPublicKeyParameters)kp.Public));
            FalconPrivateKeyParameters privParams = (FalconPrivateKeyParameters)PqcPrivateKeyFactory.CreateKey(
                PqcPrivateKeyInfoFactory.CreatePrivateKeyInfo((FalconPrivateKeyParameters)kp.Private));

            byte[] respk = pubParams.GetEncoded();
            byte[] ressk = privParams.GetEncoded();

            Assert.True(Arrays.AreEqual(respk, 0, respk.Length, pk, 1, pk.Length), path + " " + count + " public key");
            Assert.True(Arrays.AreEqual(ressk, 0, ressk.Length, sk, 1, sk.Length), path + " " + count + " private key");

            // sign
            FalconSigner signer = new FalconSigner();
            ParametersWithRandom skwrand = new ParametersWithRandom(kp.Private, random);
            signer.Init(true, skwrand);
            byte[] sig = signer.GenerateSignature(msg);
            byte[] ressm = new byte[2 + msg.Length + sig.Length];
            ressm[0] = (byte)((sig.Length - 40) >> 8);
            ressm[1] = (byte)(sig.Length - 40);
            Array.Copy(sig, 1, ressm, 2, 40);
            Array.Copy(msg, 0, ressm, 2 + 40, msg.Length);
            ressm[2 + 40 + msg.Length] = (byte)(0x20 + kparam.Parameters.LogN);
            Array.Copy(sig, 40 + 1, ressm, 3 + 40 + msg.Length, sig.Length - 40 - 1);
         
            // verify
            FalconSigner verifier = new FalconSigner();
            FalconPublicKeyParameters pkparam = (FalconPublicKeyParameters)kp.Public;
            verifier.Init(false, pkparam);
            bool vrfyrespass = verifier.VerifySignature(msg, sig);
            sig[42]++; // changing the signature by 1 byte should cause it to fail
            bool vrfyresfail = verifier.VerifySignature(msg, sig);
           
            //sign
            Assert.True(Arrays.AreEqual(ressm, sm), path + " " + count + " signature");
            //verify
            Assert.True(vrfyrespass, path + " " + count + " verify failed when should pass");
            Assert.False(vrfyresfail, path + " " + count + " verify passed when should fail");
        }
    }
}
