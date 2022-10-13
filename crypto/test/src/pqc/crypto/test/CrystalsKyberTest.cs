using System;
using System.Collections.Generic;
using System.IO;
using NUnit.Framework;
using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Pqc.Crypto.Crystals.Kyber;
using Org.BouncyCastle.Utilities;
using Org.BouncyCastle.Utilities.Encoders;
using Org.BouncyCastle.Utilities.Test;

namespace Org.BouncyCastle.Pqc.Crypto.Tests
{
    [TestFixture]
    public class CrystalsKyberTest
    {
        private static readonly Dictionary<string, KyberParameters> parameters = new Dictionary<string, KyberParameters>()
        {
            { "kyber512.rsp", KyberParameters.kyber512 },
            { "kyber768.rsp", KyberParameters.kyber768 },
            { "kyber1024.rsp", KyberParameters.kyber1024 },
            { "kyber512aes.rsp", KyberParameters.kyber512_aes },
            { "kyber768aes.rsp", KyberParameters.kyber768_aes },
            { "kyber1024aes.rsp", KyberParameters.kyber1024_aes }
        };
        
        private static readonly string[] TestVectorFilesBasic =
        {
            "kyber512.rsp",
            "kyber768.rsp",
            "kyber1024.rsp",
            "kyber512aes.rsp",
            "kyber768aes.rsp",
            "kyber1024aes.rsp",
        };
        
        [TestCaseSource(nameof(TestVectorFilesBasic))]
        [Parallelizable(ParallelScope.All)]
        public void TestVectorsBasic(string testVectorFile)
        {
            RunTestVectorFile(testVectorFile);
        }
        
        private static void TestVectors(string name, IDictionary<string, string> buf)
        {
            string count = buf["count"];

            byte[] seed = Hex.Decode(buf["seed"]); // seed for SecureRandom
            byte[] pk = Hex.Decode(buf["pk"]); // public key
            byte[] sk = Hex.Decode(buf["sk"]); // private key
            byte[] ct = Hex.Decode(buf["ct"]); // ciphertext
            byte[] ss = Hex.Decode(buf["ss"]); // session key

            NistSecureRandom random = new NistSecureRandom(seed, null);
            KyberParameters kyberparameters = CrystalsKyberTest.parameters[name];

            KyberKeyPairGenerator kpGen = new KyberKeyPairGenerator();
            KyberKeyGenerationParameters
                genParam = new KyberKeyGenerationParameters(random, kyberparameters);
            
            //
            // Generate keys and test.
            //
            kpGen.Init(genParam);
            AsymmetricCipherKeyPair ackp = kpGen.GenerateKeyPair();


            KyberPublicKeyParameters pubParams = (KyberPublicKeyParameters)ackp.Public;
            KyberPrivateKeyParameters privParams = (KyberPrivateKeyParameters)ackp.Private;

            Assert.True(Arrays.AreEqual(pk, pubParams.GetEncoded()), name + " " + count + ": public key");
            Assert.True(Arrays.AreEqual(sk, privParams.GetEncoded()), name + " " + count + ": secret key");

            // KEM Enc
            KyberKemGenerator KyberEncCipher = new KyberKemGenerator(random);
            ISecretWithEncapsulation secWenc = KyberEncCipher.GenerateEncapsulated(pubParams);
            byte[] generated_cipher_text = secWenc.GetEncapsulation();
            Assert.True(Arrays.AreEqual(ct, generated_cipher_text), name + " " + count + ": kem_enc cipher text");
            byte[] secret = secWenc.GetSecret();
            Assert.True(Arrays.AreEqual(ss, secret), name + " " + count + ": kem_enc key");

            // KEM Dec
            KyberKemExtractor KyberDecCipher = new KyberKemExtractor(privParams);

            byte[] dec_key = KyberDecCipher.ExtractSecret(generated_cipher_text);

            Assert.True(Arrays.AreEqual(dec_key, ss), name + " " + count + ": kem_dec ss");
            Assert.True(Arrays.AreEqual(dec_key, secret), name + " " + count + ": kem_dec key");
            
        }
        
        public static void RunTestVectorFile(string name)
        {
            var buf = new Dictionary<string, string>();

            using (var src = new StreamReader(SimpleTest.GetTestDataAsStream("pqc.crystals.kyber." + name)))
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
                        TestVectors(name, buf);
                        buf.Clear();
                    }
                }

                if (buf.Count > 0)
                {
                    TestVectors(name, buf);
                }
            }
        }
    }
}
