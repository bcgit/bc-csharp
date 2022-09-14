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
        [Test]
        public void TestVectors()
        {

            KyberParameters[] KyberParams =
            {
                KyberParameters.kyber512,
                KyberParameters.kyber768,
                KyberParameters.kyber1024,
            };
            String[] files =
            {
                "kyber512.rsp",
                "kyber768.rsp",
                "kyber1024.rsp"
            };

            TestSampler sampler = new TestSampler();
            for (int fileIndex = 0; fileIndex != files.Length; fileIndex++)
            {
                String name = files[fileIndex];
                StreamReader src = new StreamReader(SimpleTest.GetTestDataAsStream("pqc.crystals.kyber." + name));


                String line = null;
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
                            String count = buf["count"];

                            byte[] seed = Hex.Decode(buf["seed"]); // seed for Kyber secure random
                            byte[] pk = Hex.Decode(buf["pk"]); // public key
                            byte[] sk = Hex.Decode(buf["sk"]); // private key
                            byte[] ct = Hex.Decode(buf["ct"]); // ciphertext
                            byte[] ss = Hex.Decode(buf["ss"]); // session key

                            NistSecureRandom random = new NistSecureRandom(seed, null);
                            KyberParameters parameters = KyberParams[fileIndex];

                            KyberKeyPairGenerator kpGen = new KyberKeyPairGenerator();
                            KyberKeyGenerationParameters
                                genParam = new KyberKeyGenerationParameters(random, parameters);

                            Console.WriteLine(string.Format("seed = {0}", Hex.ToHexString(seed)));
                           
                            //
                            // Generate keys and test.
                            //
                            kpGen.Init(genParam);
                            AsymmetricCipherKeyPair kp = kpGen.GenerateKeyPair();


                            KyberPublicKeyParameters pubParams = (KyberPublicKeyParameters)kp.Public;
                            KyberPrivateKeyParameters privParams = (KyberPrivateKeyParameters)kp.Private;

                            //Console.WriteLine(string.Format("pk = {0}", Convert.ToHexString(pk)));
                            //Console.WriteLine(String.Format("Public key = {0}", Convert.ToHexString(pubParams.publicKey)));
                            Assert.True(Arrays.AreEqual(pk, pubParams.GetEncoded()), name + " " + count + ": public key");

                            Console.WriteLine(string.Format("sk = {0}", Hex.ToHexString(sk)));
                            Console.WriteLine(String.Format("sk bytes = {0}", sk.Length));
                            Console.WriteLine(String.Format("Secret key = {0}", Hex.ToHexString(privParams.GetEncoded())));
                            Console.WriteLine(String.Format("secret key bytes = {0}", privParams.GetEncoded().Length));

                            Assert.True(Arrays.AreEqual(sk, privParams.GetEncoded()), name + " " + count + ": secret key");

                            // KEM Enc
                            KyberKEMGenerator KyberEncCipher = new KyberKEMGenerator(random);
                            ISecretWithEncapsulation secWenc = KyberEncCipher.GenerateEncapsulated(pubParams);
                            byte[] generated_cipher_text = secWenc.GetEncapsulation();


                            //Console.WriteLine(string.Format("ct = {0}", Convert.ToHexString(ct)));
                            //Console.WriteLine(String.Format("ct bytes = {0}", ct.Length));
                            //Console.WriteLine(String.Format("Cipher Text = {0}", Convert.ToHexString(generated_cipher_text)));
                            //Console.WriteLine(String.Format("Cipher Text bytes = {0}", generated_cipher_text.Length));

                            //Console.WriteLine(string.Format("ss = {0}", Convert.ToHexString(ss)));
                            //Console.WriteLine(String.Format("ss bytes = {0}", ss.Length));
                            //Console.WriteLine(String.Format("Shared Secret = {0}", Convert.ToHexString(secWenc.GetSecret())));
                            //Console.WriteLine(String.Format("Shared Secret bytes = {0}", secWenc.GetSecret().Length));

                            Assert.True(Arrays.AreEqual(ct, generated_cipher_text), name + " " + count + ": kem_enc cipher text");
                            byte[] secret = secWenc.GetSecret();
                            Assert.True(Arrays.AreEqual(ss, 0, secret.Length, secret, 0, secret.Length), name + " " + count + ": kem_enc key");

                            // KEM Dec
                            KyberKEMExtractor KyberDecCipher = new KyberKEMExtractor(privParams);

                            byte[] dec_key = KyberDecCipher.ExtractSecret(generated_cipher_text);

                            Assert.AreEqual(dec_key.Length * 8, parameters.DefaultKeySize);
                            Assert.True(Arrays.AreEqual(dec_key, 0, dec_key.Length, ss, 0, dec_key.Length), name + " " + count + ": kem_dec ss");
                            Assert.True(Arrays.AreEqual(dec_key, secret), name + " " + count + ": kem_dec key");
                        }

                        buf.Clear();

                        continue;
                    }

                    int a = line.IndexOf("=");
                    if (a > -1)
                    {
                        buf[line.Substring(0, a).Trim()] = line.Substring(a + 1).Trim();
                    }
                }
            }
        }
    }
}
