using System;
using System.Collections.Generic;
using System.IO;
using NUnit.Framework;
using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Pqc.Crypto.NtruPrime;
using Org.BouncyCastle.Utilities;
using Org.BouncyCastle.Utilities.Encoders;
using Org.BouncyCastle.Utilities.Test;

namespace Org.BouncyCastle.Pqc.Crypto.Tests
{
    [TestFixture]
    public class NtruPrimeVectorTest
    {
        [Test]
        public void TestParameters()
        {
            // Console.WriteLine("Testing");
            // Console.WriteLine(NtruPrimeParameters.ntrulpr653.P);
            // Console.WriteLine(NtruPrimeParameters.ntrulpr653.Q);
            // Console.WriteLine(NtruPrimeParameters.ntrulpr653.lpr);
        }

        [Test]
        public void TestVectors()
        {
            string[] files =
            {
                "kat_kem_ntrulp_653.rsp",
                "kat_kem_ntrulp_761.rsp",
                "kat_kem_ntrulp_857.rsp",
                "kat_kem_ntrulp_953.rsp",
                "kat_kem_ntrulp_1013.rsp",
                "kat_kem_ntrulp_1277.rsp",
            };

            NtruLPRimeParameters[] parameters =
            {
                NtruLPRimeParameters.ntrulpr653,
                NtruLPRimeParameters.ntrulpr761,
                NtruLPRimeParameters.ntrulpr857,
                NtruLPRimeParameters.ntrulpr953,
                NtruLPRimeParameters.ntrulpr1013,
                NtruLPRimeParameters.ntrulpr1277,
            };

            TestSampler sampler = new TestSampler();
            for (int fileIndex = 0; fileIndex != files.Length; fileIndex++)
            {
                String name = files[fileIndex];
                Console.Write("Testing " + name + "...");
                Console.WriteLine("pqc.ntruprime."+ name);
                StreamReader src = new StreamReader(SimpleTest.GetTestDataAsStream("pqc.ntruprime." + name));
                String line = null;
                Dictionary<String, String> buf = new Dictionary<string, string>();
                
                while ((line = src.ReadLine()) != null)
                {
                    line = line.Trim();
                    if(line.StartsWith("#"))
                    {
                        continue;
                    }

                    if (line.Length == 0)
                    {
                        if (buf.Count > 0 && !sampler.SkipTest(buf["count"]))
                        {
                            String count = buf["count"];
                            
                            if (!"0".Equals(count))
                            {
                                // Console.WriteLine("Zero");
                            }
                    
                            byte[] seed = Hex.Decode(buf["seed"]);
                            byte[] pk = Hex.Decode(buf["pk"]);
                            byte[] ct = Hex.Decode(buf["ct"]);
                            byte[] sk = Hex.Decode(buf["sk"]);
                            byte[] ss = Hex.Decode(buf["ss"]);

                            
                            NistSecureRandom random = new NistSecureRandom(seed, null);
                            NtruLPRimeParameters ntruPParameters = parameters[fileIndex];
                            
                            NtruLPRimeKeyPairGenerator kpGen = new NtruLPRimeKeyPairGenerator();
                            NtruLPRimeKeyGenerationParameters genParams = new NtruLPRimeKeyGenerationParameters(random,ntruPParameters);
                            
                            // Generate the key pair
                            kpGen.Init(genParams);
                            AsymmetricCipherKeyPair kp = kpGen.GenerateKeyPair();
                            
                            NtruLPRimePublicKeyParameters pubParams = (NtruLPRimePublicKeyParameters) kp.Public;
                            NtruLPRimePrivateKeyParameters privParams = (NtruLPRimePrivateKeyParameters) kp.Private;
                            
                            // Check public and private key
                            Assert.True(Arrays.AreEqual(pk,pubParams.GetEncoded()), $"{name} {count} : public key");
                            Assert.True(Arrays.AreEqual(sk,privParams.GetEncoded()), $"{name} {count} : private key");
                            
                            // Encapsulation
                            NtruLPRimeKemGenerator ntruPEncCipher = new NtruLPRimeKemGenerator(random);
                            ISecretWithEncapsulation secWenc = ntruPEncCipher.GenerateEncapsulated(pubParams);
                            byte[] generatedCT = secWenc.GetEncapsulation();
                            
                            // Check ciphertext
                            Assert.True(Arrays.AreEqual(ct, generatedCT), name + " " + count + ": kem_enc cipher text");
                            
                            // Check secret
                            byte[] secret = secWenc.GetSecret();
                            Assert.True(Arrays.AreEqual(ss, secret), name + " " + count + ": kem_enc secret");
                            
                            // Decapsulation
                            NtruLPRimeKemExtractor ntruDecCipher = new NtruLPRimeKemExtractor(privParams);
                            byte[] dec_key = ntruDecCipher.ExtractSecret(generatedCT);
                            
                            // Check decapsulation secret
                            Assert.True(Arrays.AreEqual(dec_key, ss), $"{name} {count}: kem_dec ss");
                            Assert.True(Arrays.AreEqual(dec_key, secret),$"{name} {count}: kem_dec key");
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
                Console.WriteLine("OK");
            }

            files = new string[]
            {
                "kat_kem_sntrup_653.rsp",
                "kat_kem_sntrup_761.rsp",
                "kat_kem_sntrup_857.rsp",
                "kat_kem_sntrup_953.rsp",
                "kat_kem_sntrup_1013.rsp",
                "kat_kem_sntrup_1277.rsp",
            };

            SNtruPrimeParameters[] sparameters =
            {
                SNtruPrimeParameters.sntrup653,
                SNtruPrimeParameters.sntrup761,
                SNtruPrimeParameters.sntrup857,
                SNtruPrimeParameters.sntrup953,
                SNtruPrimeParameters.sntrup1013,
                SNtruPrimeParameters.sntrup1277,
            };

            for (int fileIndex = 0; fileIndex != files.Length; fileIndex++)
            {
                String name = files[fileIndex];
                Console.Write("Testing " + name + "...");
                Console.WriteLine("pqc.ntruprime." + name);
                StreamReader src = new StreamReader(SimpleTest.GetTestDataAsStream("pqc.ntruprime." + name));
                String line = null;
                Dictionary<String, String> buf = new Dictionary<string, string>();

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
                                // Console.WriteLine("Zero");
                            }

                            byte[] seed = Hex.Decode(buf["seed"]);
                            byte[] pk = Hex.Decode(buf["pk"]);
                            byte[] ct = Hex.Decode(buf["ct"]);
                            byte[] sk = Hex.Decode(buf["sk"]);
                            byte[] ss = Hex.Decode(buf["ss"]);


                            NistSecureRandom random = new NistSecureRandom(seed, null);
                            SNtruPrimeParameters ntruPParameters = sparameters[fileIndex];

                            SNtruPrimeKeyPairGenerator kpGen = new SNtruPrimeKeyPairGenerator();
                            SNtruPrimeKeyGenerationParameters genParams = new SNtruPrimeKeyGenerationParameters(random, ntruPParameters);

                            // Generate the key pair
                            kpGen.Init(genParams);
                            AsymmetricCipherKeyPair kp = kpGen.GenerateKeyPair();

                            SNtruPrimePublicKeyParameters pubParams = (SNtruPrimePublicKeyParameters)kp.Public;
                            SNtruPrimePrivateKeyParameters privParams = (SNtruPrimePrivateKeyParameters)kp.Private;

                            // Check public and private key
                            Assert.True(Arrays.AreEqual(pk, pubParams.GetEncoded()), $"{name} {count} : public key");
                            Assert.True(Arrays.AreEqual(sk, privParams.GetEncoded()), $"{name} {count} : private key");

                            // Encapsulation
                            SNtruPrimeKemGenerator ntruPEncCipher = new SNtruPrimeKemGenerator(random);
                            ISecretWithEncapsulation secWenc = ntruPEncCipher.GenerateEncapsulated(pubParams);
                            byte[] generatedCT = secWenc.GetEncapsulation();

                            // Check ciphertext
                            Assert.True(Arrays.AreEqual(ct, generatedCT), name + " " + count + ": kem_enc cipher text");

                            // Check secret
                            byte[] secret = secWenc.GetSecret();
                            Assert.True(Arrays.AreEqual(ss, secret), name + " " + count + ": kem_enc secret");

                            // Decapsulation
                            SNtruPrimeKemExtractor ntruDecCipher = new SNtruPrimeKemExtractor(privParams);
                            byte[] dec_key = ntruDecCipher.ExtractSecret(generatedCT);

                            // Check decapsulation secret
                            Assert.True(Arrays.AreEqual(dec_key, ss), $"{name} {count}: kem_dec ss");
                            Assert.True(Arrays.AreEqual(dec_key, secret), $"{name} {count}: kem_dec key");
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
                Console.WriteLine("OK");
            }
        }
        
    }
}
