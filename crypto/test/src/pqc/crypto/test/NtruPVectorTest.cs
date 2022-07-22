using System;
using System.Collections.Generic;
using System.IO;
using NUnit.Framework;
using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Pqc.Crypto.Frodo;
using Org.BouncyCastle.pqc.crypto.NtruP;
using Org.BouncyCastle.Utilities;
using Org.BouncyCastle.Utilities.Encoders;
using Org.BouncyCastle.Utilities.Test;

namespace Org.BouncyCastle.Pqc.Crypto.Tests
{
    [TestFixture]
    public class NtruPVectorTest
    {
        [Test]
        public void TestParameters()
        {
            // Console.WriteLine("Testing");
            // Console.WriteLine(NtruPParameters.ntrulpr653.P);
            // Console.WriteLine(NtruPParameters.ntrulpr653.Q);
            // Console.WriteLine(NtruPParameters.ntrulpr653.lpr);
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
                "kat_kem_sntrup_653.rsp",
                "kat_kem_sntrup_761.rsp",
                "kat_kem_sntrup_857.rsp",
                "kat_kem_sntrup_953.rsp",
                "kat_kem_sntrup_1013.rsp",
                "kat_kem_sntrup_1277.rsp",
            };

            NtruPParameters[] parameters =
            {
                NtruPParameters.ntrulpr653,
                NtruPParameters.ntrulpr761,
                NtruPParameters.ntrulpr857,
                NtruPParameters.ntrulpr953,
                NtruPParameters.ntrulpr1013,
                NtruPParameters.ntrulpr1277,
                NtruPParameters.sntrup653, 
                NtruPParameters.sntrup761,
                NtruPParameters.sntrup857,
                NtruPParameters.sntrup953,
                NtruPParameters.sntrup1013,
                NtruPParameters.sntrup1277,
            };

            for (int fileIndex = 0; fileIndex != files.Length; fileIndex++)
            {
                String name = files[fileIndex];
                Console.Write("Testing " + name + "...");
                Console.WriteLine("pqc.ntru."+ name);
                StreamReader src = new StreamReader(SimpleTest.GetTestDataAsStream("pqc.ntru." + name));
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
                            NtruPParameters ntruPParameters = parameters[fileIndex];
                            
                            NtruKeyPairGenerator kpGen = new NtruKeyPairGenerator();
                            NtruKeyGenerationParameters genParams = new NtruKeyGenerationParameters(random,ntruPParameters);
                            
                            // Generate the key pair
                            kpGen.Init(genParams);
                            AsymmetricCipherKeyPair kp = kpGen.GenerateKeyPair();
                            
                            NtruPPublicKeyParameters pubParams = (NtruPPublicKeyParameters) kp.Public;
                            NtruPPrivateKeyParameters privParams = (NtruPPrivateKeyParameters) kp.Private;
                            
                            // Check public and private key
                            Assert.True(Arrays.AreEqual(pk,pubParams.PublicKey), $"{name} {count} : public key");
                            Assert.True(Arrays.AreEqual(sk,privParams.PrivateKey), $"{name} {count} : private key");
                            
                            // Encapsulation
                            NtruPKemGenerator ntruPEncCipher = new NtruPKemGenerator(random);
                            ISecretWithEncapsulation secWenc = ntruPEncCipher.GenerateEncapsulated(pubParams);
                            byte[] generatedCT = secWenc.GetEncapsulation();
                            
                            // Check ciphertext
                            Assert.True(Arrays.AreEqual(ct, generatedCT), name + " " + count + ": kem_enc cipher text");
                            
                            // Check secret
                            byte[] secret = secWenc.GetSecret();
                            Assert.True(Arrays.AreEqual(ss, secret), name + " " + count + ": kem_enc secret");
                            
                            // Decapsulation
                            NtruPKEMExtractor ntruDecCipher = new NtruPKEMExtractor(privParams);
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

        }
        
    }
}
