using System;
using System.Collections.Generic;
using System.IO;

using NUnit.Framework;

using Org.BouncyCastle.Asn1.X509;
using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.Pqc.Crypto.Falcon;
using Org.BouncyCastle.Pqc.Crypto.Utilities;
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

        private static readonly IEnumerable<string> TestVectorFiles = Parameters.Keys;

        [Test]
        public void TestParameters()
        {
            Assert.AreEqual(9, FalconParameters.falcon_512.LogN);
            Assert.AreEqual(10, FalconParameters.falcon_1024.LogN);
        }

        [Test]
        public void TestKeyEncoding512()
        {
            byte[] altEncKey = Base64.Decode("vsUwFR+onoGQjgYmVpVBEacknmQpGTqsW+kNYw4VntPxVoRVLdsl2U24SzIAgrCZgwBAOnVK57arZT+5nF1afZZB5DzjapIKfPBhLlGmnQ6RX2j/WBaEoMAX7l46ZSb1GgycmZMgUFWvsYLEZr5D4zxOhfSkkzJ38NCzuOUNiFgYQ4TRtwxGwDM8WVV0vpL0nkLVnQJ7B0ZRBz++dXetoI651kjWW91GB3mj+x6U9SYx/KTF4zyejiEF2wVxKzgum13RiivF6cbBHLBeQLGBqRbgk5VasoRaswUc8NBywckHUBgmhilYUv0scpREs3m+IgjcYB2JmryzGNU1p6aM6b/sOrzJffLLm38mca6ZQpoNih03a+8QeIlAn8ns4XJOZOzg0J0ZsUhQ2Zdmj4BASFREAnma1LYH2k/rOf5qpfZUpYzuDhPJ43y5zLeUrt6kKErgGo4KYJBl4/JvWdlnFA8ROEbTY3qXEAHnkRzxsBOFX8midNdRVIDnRSJTZy1RNGFkcCOrpAad0HRVbCAvK6pT1gygOIltO6ap164lQu35kSJKP/a0xYFJgk25+WSK5DZThjVbA12Cb0WI5QRgfaM2+QZko8dDwsbbq05MMPLcy25HGHbqSGWIJLWFyGb0MisvSUnHGnKWL4x5JFP2VbSAtLzbdRCTg+mqcAkC5n1uxJcdZA6ReZ3biuV0RnLwEQhaPmpm2tbJl4w+UAni4mejObiRo8VGNUikK1L4Sig6DjMLON2nsvIEa8iDAaEJUbTLqy0iPWfl45v9HjY26FSpHVgl0GAfBAO0eagBOORzVX7iev0uqA2EGCrZCAdA5QvUTWK1RSA3O3hSXFm4+2A4jqainmxhfOtnuOCJxhZfbpkQ7BWHLLpl4B4LddyeXz2ug4KTzGeyugrDneZCqZ9TMp9URTyqBxmQmkYx3LsGQL4wMYMA6Q92iIQ+2jTBBQmkTNDlZKwjcOoi1eLSOwa3M/jhqiNA1HKsDWmKYoFg5qbPTYEJoDZqIDN6PJP4j++jQWlYW4MLhMXVFAlkWpQyHWcMRc9kpEvRd+hHSYl5G8Da3VSKsWgozoMb7aQbtwQxh0zhZgLJGBvYIyRkLaww0W5wLMJNg438+XOVAg0Olxk+4oVX6Xjpi1dIisTMumukfzOFCwIGgVsmWMVBit4woD7fVBNE5g38O2sdAfM=");
            byte[] altSubPubEnc = Base64.Decode("MIIDljAHBgUrzg8DAQOCA4kAMIIDhASCA4C+xTAVH6iegZCOBiZWlUERpySeZCkZOqxb6Q1jDhWe0/FWhFUt2yXZTbhLMgCCsJmDAEA6dUrntqtlP7mcXVp9lkHkPONqkgp88GEuUaadDpFfaP9YFoSgwBfuXjplJvUaDJyZkyBQVa+xgsRmvkPjPE6F9KSTMnfw0LO45Q2IWBhDhNG3DEbAMzxZVXS+kvSeQtWdAnsHRlEHP751d62gjrnWSNZb3UYHeaP7HpT1JjH8pMXjPJ6OIQXbBXErOC6bXdGKK8XpxsEcsF5AsYGpFuCTlVqyhFqzBRzw0HLByQdQGCaGKVhS/SxylESzeb4iCNxgHYmavLMY1TWnpozpv+w6vMl98subfyZxrplCmg2KHTdr7xB4iUCfyezhck5k7ODQnRmxSFDZl2aPgEBIVEQCeZrUtgfaT+s5/mql9lSljO4OE8njfLnMt5Su3qQoSuAajgpgkGXj8m9Z2WcUDxE4RtNjepcQAeeRHPGwE4VfyaJ011FUgOdFIlNnLVE0YWRwI6ukBp3QdFVsIC8rqlPWDKA4iW07pqnXriVC7fmRIko/9rTFgUmCTbn5ZIrkNlOGNVsDXYJvRYjlBGB9ozb5BmSjx0PCxturTkww8tzLbkcYdupIZYgktYXIZvQyKy9JSccacpYvjHkkU/ZVtIC0vNt1EJOD6apwCQLmfW7Elx1kDpF5nduK5XRGcvARCFo+amba1smXjD5QCeLiZ6M5uJGjxUY1SKQrUvhKKDoOMws43aey8gRryIMBoQlRtMurLSI9Z+Xjm/0eNjboVKkdWCXQYB8EA7R5qAE45HNVfuJ6/S6oDYQYKtkIB0DlC9RNYrVFIDc7eFJcWbj7YDiOpqKebGF862e44InGFl9umRDsFYcsumXgHgt13J5fPa6DgpPMZ7K6CsOd5kKpn1Myn1RFPKoHGZCaRjHcuwZAvjAxgwDpD3aIhD7aNMEFCaRM0OVkrCNw6iLV4tI7Brcz+OGqI0DUcqwNaYpigWDmps9NgQmgNmogM3o8k/iP76NBaVhbgwuExdUUCWRalDIdZwxFz2SkS9F36EdJiXkbwNrdVIqxaCjOgxvtpBu3BDGHTOFmAskYG9gjJGQtrDDRbnAswk2Djfz5c5UCDQ6XGT7ihVfpeOmLV0iKxMy6a6R/M4ULAgaBWyZYxUGK3jCgPt9UE0TmDfw7ax0B8w==");

            AsymmetricKeyParameter altPubDec = PqcPublicKeyFactory.CreateKey(SubjectPublicKeyInfo.GetInstance(altSubPubEnc));
            Assert.AreEqual(altEncKey, ((FalconPublicKeyParameters)altPubDec).GetEncoded());

            Security.SecureRandom random = new Security.SecureRandom();
            FalconKeyGenerationParameters kparam = new FalconKeyGenerationParameters(random, FalconParameters.falcon_512);
            FalconKeyPairGenerator kpg = new FalconKeyPairGenerator();
            kpg.Init(kparam);
            AsymmetricCipherKeyPair ackp = kpg.GenerateKeyPair();

            AsymmetricKeyParameter pub = ackp.Public;
            AsymmetricKeyParameter priv = ackp.Private;

            AsymmetricKeyParameter pubDec = PqcPublicKeyFactory.CreateKey(PqcSubjectPublicKeyInfoFactory.CreateSubjectPublicKeyInfo(pub));
            AsymmetricKeyParameter privDec = PqcPrivateKeyFactory.CreateKey(PqcPrivateKeyInfoFactory.CreatePrivateKeyInfo(priv));

            Assert.AreEqual(((FalconPublicKeyParameters)pub).GetEncoded(), ((FalconPublicKeyParameters)pubDec).GetEncoded());
            Assert.AreEqual(((FalconPrivateKeyParameters)priv).GetEncoded(), ((FalconPrivateKeyParameters)privDec).GetEncoded());
        }

        [Test]
        public void TestKeyEncoding1024()
        {
            byte[] altEncKey = Base64.Decode(" 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");
            byte[] altSubPubEnc = Base64.Decode("MIIHFjAHBgUrzg8DBAOCBwkAMIIHBASCBwB3MRaZLVABIP5EIVyjM7RlrFfqpJgACJI7cB9ZNAwctfoZvBHtSLhdl+5LWTnBaGDegfWGgGjevT01fVOe3dhq5YNVbV/LavDnxdbRDkj2auLGbeqkMmDCuSeXvW3k0yhfshEe0uIYzQ8e4fy6pSKzKIx3OOgKjGi9P3CQj+WahhhoP4Z3KJjmko+CyhiNj2r1laOWhSJFOGnvECEli9/Uw7nwbDNMXGkiOTPVSqxqfA5r93EmNES+YaO/3FWHhLUUPopLisKHV+1h2Xe5yaCYK5kmYGRXKxp5kYx8llNri7TFGEtphL5Q/PaoVlPHDXYbSgKsaoPCTbD7aZQfQYO5mefDVsCsl6HRWxw2DucIEPUrPMc6H+EOdLruJH1P40WSPlYuTGJElpnQEg+bWIG+Gt7a+UugcfnCihwZst1JPUf3Q2HxutpRuki1V7rjDtKUtt3nchtzJFpV9HYWk2a1EPYziTBxuI0QNqG5dI4ECMknIHykqln/HKWT8HMGG+naC8yT5uir7ykpZQIr6DMxmK92YQijlSQMxa4d9SiaAhUOJxBxcvHagMTVtzGJhJRrfSUArhmPm/yl9Mchrt8ARgAvKg2RQS+uw1KBGiIP3duTia0mDTjucagDOL4E5DMhhGhn0ncAf2ZCFsUWqR0Eq4lIHEsfz7FhpDPT7MohBTJSuvBK+gUtcqeGo7AoKME4QRkKnmpAihoMbl5Z0LFgahMs3aAQiQAOK2XBxwbSXimmHrBPL4xiwrWVSaDzV2g+EY2an5igyuUjV+9wfddIR2GDnDHfq+4dA4eKCWSG792zuoIWJqszFnbYIalTC5pdMZt1x0ZB2LB1AAqDWKU10TGMGH3Uc+FzqJajEZTD7cnlhzpJGcaaNLDdzzfRhm1FQbrFcKQGGy4fmLHmQ2/CFqESA4ObNiLTHUkvRLzwhWZdyK/p3MSIQ2GNqBYmjkmcDnoFMcUkDVcdvlIyTIEMYNRhgwlxGOGKV+SYMQfgxuQT0JZr0gumBkquJwFd9cRTVB+O1MHnCMN/4OuEJGkrjY4MB/SBYgsesZXzRjAetjmgulyLccz7qBdARV3C/2mvCXdm6Z44LFkCRNCnYQ1Qk4j5x/JHWdugTTl2BGzsW0LymliT7XwwS/XQlZJ5/EimQ2bLE8pqGHGgY3h5sJlHADFJyU34OOQGXD5D1ONH0geWqXhOB0MucmnrwgT3d1hX9p0JCCFkV9NcqKhxZYOx/9T7pzFXUb/j9Gf6y7R8xG9bZD/Q9SDrDtgtt9cEu7iKB0s3zdinUQ9j/5rserFPFH/ICwaxvYMr0J6k3jlA1qWiWtR52TrHShMIhfDurq+LzLHR4oGaWcSl4uJadI/ga/hnVeMnUKLQKKR3dbgOIgRVIhm9ldvyAs4MAD0yWOSLYd3z27zNOEDMB5NmX6+rWr3kT9xgmHk2JyHuQrltRUnGkqcMJibAvWN4Qh5ASv+Sunvh4xmbHmVlPjN1ahE5JL7GCSTaBLfMzQYFKls08CTapyXOBwaEhflIzD98CnYF6bA0OcQHjFmxnibCKpoO1j0cU8Y5EvyjPJUQYiGOr/ZBwkVpsby8Wnhs1vN0rQc68ZiWhNq4kaVmukQooAU/SDF96JfLI1ZknGAVVR+VQWNoxrDUY+eMqSoVpd3Vj0reW41k6GKNBCXFWAk71dLZ1WS8iDnuGosnOWFJ6aq0yYazsNwTzGLTKoj4EsMfhB/ghMW/SPuyqtkCxd2gM0b3024KqnYAfSHJVQ69ysqWDp9xp7hzV3SiDk0wwTW/KUFfhQgnKeoPrWYpRnFBGRCqJ6FZJqBkXdP1GBapGAG/ZTuI+rEQm+QAAOltfNdZat/3LRJmdaWEA0ta4sn461qcaTrjrBFNAZm0iUzlPiItFtiOXogD9f3FShPTk5aoy/gI8Q+UipgBqNWqzcKQC6kLfkmlWntG+Jctf4X7WoeCtDAhB2QZhAJyt4oELx4QhSeVCV8gMOh3Ct2SDd3XQVNL0KgwY/EA3oJWBq7EctG7cIXYsZQsNVeQCZWp2P5sZtpT7I7REwL6k3NIZmO2QoX3Ld9EUuBI4UakeNqeuBgDY25agNGniAdedi3KPYX/rYgA6xOisFf237u5ihgNWASmiyL8Qs2T0X1sBYP+nLJGWRCjvN8Tz6yOo9HYgbpLLLdBZ9X0F6SV/Ednx6sNIgwp+GtjhAqCfjjTa5C/xN3quYSwo15q1TZXgyLAfyieKSwYpaKE+1+LaWwvpOchrjt0CFLwnZA06tMDKAINk1GuMh5jwRM6NBcCmvkdzScFipyRJ8ADksbgIx0wiNajYj222oL1HNO1mC1J0rfQdr94g5pOhTkWLD8Ivp7PKXWhCOwX5bAaoed2XaUzgL6bcITN");

            AsymmetricKeyParameter altPubDec = PqcPublicKeyFactory.CreateKey(SubjectPublicKeyInfo.GetInstance(altSubPubEnc));
            Assert.AreEqual(altEncKey, ((FalconPublicKeyParameters)altPubDec).GetEncoded());

            Security.SecureRandom random = new Security.SecureRandom();
            FalconKeyGenerationParameters kparam = new FalconKeyGenerationParameters(random, FalconParameters.falcon_1024);
            FalconKeyPairGenerator kpg = new FalconKeyPairGenerator();
            kpg.Init(kparam);
            AsymmetricCipherKeyPair ackp = kpg.GenerateKeyPair();

            AsymmetricKeyParameter pub = ackp.Public;
            AsymmetricKeyParameter priv = ackp.Private;

            AsymmetricKeyParameter pubDec = PqcPublicKeyFactory.CreateKey(PqcSubjectPublicKeyInfoFactory.CreateSubjectPublicKeyInfo(pub));
            AsymmetricKeyParameter privDec = PqcPrivateKeyFactory.CreateKey(PqcPrivateKeyInfoFactory.CreatePrivateKeyInfo(priv));
  
            Assert.AreEqual(((FalconPublicKeyParameters)pub).GetEncoded(), ((FalconPublicKeyParameters)pubDec).GetEncoded());
            Assert.AreEqual(((FalconPrivateKeyParameters)priv).GetEncoded(), ((FalconPrivateKeyParameters)privDec).GetEncoded());
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
            byte[] ressm = new byte[2 + msg.Length + sig.Length];
            ressm[0] = (byte)((sig.Length - 40) >> 8);
            ressm[1] = (byte)(sig.Length - 40);
            Array.Copy(sig, 1, ressm, 2, 40);
            Array.Copy(msg, 0, ressm, 2 + 40, msg.Length);
            ressm[2 + 40 + msg.Length] = (byte)(0x20 + kparam.Parameters.LogN);
            Array.Copy(sig, 40 + 1, ressm, 3 + 40 + msg.Length, sig.Length - 40 - 1);
         
            // verify
            FalconSigner verifier = new FalconSigner();
            FalconPublicKeyParameters pkparam = (FalconPublicKeyParameters)ackp.Public;
            verifier.Init(false, pkparam);
            bool vrfyrespass = verifier.VerifySignature(msg, sig);
            sig[42]++; // changing the signature by 1 byte should cause it to fail
            bool vrfyresfail = verifier.VerifySignature(msg, sig);
           
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
