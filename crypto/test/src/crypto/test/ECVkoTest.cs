using NUnit.Framework;

using Org.BouncyCastle.Asn1.Rosstandart;
using Org.BouncyCastle.Crypto.Agreement;
using Org.BouncyCastle.Crypto.Digests;
using Org.BouncyCastle.Crypto.Generators;
using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.Math;
using Org.BouncyCastle.Security;
using Org.BouncyCastle.Utilities;
using Org.BouncyCastle.Utilities.Encoders;

namespace Org.BouncyCastle.Crypto.Tests
{
    [TestFixture]
    public class ECVkoTest
    {
        [Test]
        public void Consistency()
        {
            var random = new SecureRandom();
            var domainParameters = ECNamedDomainParameters.LookupOid(
                RosstandartObjectIdentifiers.id_tc26_gost_3410_12_512_paramSetA);

            var kpg = new ECKeyPairGenerator();
            kpg.Init(new ECKeyGenerationParameters(domainParameters, random));

            for (int i = 0; i < 10; ++i)
            {
                var ukm = SecureRandom.GetNextBytes(random, 8);

                var kpA = kpg.GenerateKeyPair();
                var kpB = kpg.GenerateKeyPair();

                byte[] secretA = ImplAgreement(ukm, kpA.Private, kpB.Public);
                byte[] secretB = ImplAgreement(ukm, kpB.Private, kpA.Public);

                Assert.True(Arrays.AreEqual(secretA, secretB));
            }
        }

        [Test]
        public void Rfc7836_AppendixB_7()
        {
            // See https://datatracker.ietf.org/doc/html/rfc7836#appendix-B, example 7;
            // VKO_GOSTR3410_2012_256 with 256-bit output on the GOST R 34.10-2012 512-bit keys with
            // id-tc26-gost-3410-12-512-paramSetA.

            byte[] ukm = new byte[] { 0x1d, 0x80, 0x60, 0x3c, 0x85, 0x44, 0xc7, 0x27 };

            var domainParameters = ECNamedDomainParameters.LookupOid(
                RosstandartObjectIdentifiers.id_tc26_gost_3410_12_512_paramSetA);

            var curve = domainParameters.Curve;

            BigInteger dA = new BigInteger(1, Hex.Decode("c990ecd972fce84ec4db022778f50fcac726f46708384b8d458304962d7147f8c2db41cef22c90b102f2968404f9b9be6d47c79692d81826b32b8daca43cb667"), bigEndian: false);
            BigInteger xpA = new BigInteger(1, Hex.Decode("aab0eda4abff21208d18799fb9a8556654ba783070eba10cb9abb253ec56dcf5d3ccba6192e464e6e5bcb6dea137792f2431f6c897eb1b3c0cc14327b1adc0a7"), bigEndian: false);
            BigInteger ypA = new BigInteger(1, Hex.Decode("914613a3074e363aedb204d38d3563971bd8758e878c9db11403721b48002d38461f92472d40ea92f9958c0ffa4c93756401b97f89fdbe0b5e46e4a4631cdb5a"), bigEndian: false);

            BigInteger dB = new BigInteger(1, Hex.Decode("48c859f7b6f11585887cc05ec6ef1390cfea739b1a18c0d4662293ef63b79e3b8014070b44918590b4b996acfea4edfbbbcccc8c06edd8bf5bda92a51392d0db"), bigEndian: false);
            BigInteger xpB = new BigInteger(1, Hex.Decode("192fe183b9713a077253c72c8735de2ea42a3dbc66ea317838b65fa32523cd5efca974eda7c863f4954d1147f1f2b25c395fce1c129175e876d132e94ed5a651"), bigEndian: false);
            BigInteger ypB = new BigInteger(1, Hex.Decode("04883b414c9b592ec4dc84826f07d0b6d9006dda176ce48c391e3f97d102e03bb598bf132a228a45f7201aba08fc524a2d77e43a362ab022ad4028f75bde3b79"), bigEndian: false);

            byte[] expectedResult = Hex.Decode("c9a9a77320e2cc559ed72dce6f47e2192ccea95fa648670582c054c0ef36c221");

            ECPrivateKeyParameters sKeyA = new ECPrivateKeyParameters("ECGOST3410", dA, domainParameters);
            ECPublicKeyParameters pKeyA = new ECPublicKeyParameters("ECGOST3410", curve.CreatePoint(xpA, ypA),
                domainParameters);

            ECPrivateKeyParameters sKeyB = new ECPrivateKeyParameters("ECGOST3410", dB, domainParameters);
            ECPublicKeyParameters pKeyB = new ECPublicKeyParameters("ECGOST3410", curve.CreatePoint(xpB, ypB),
                domainParameters);

            var secretA = ImplAgreement(ukm, sKeyA, pKeyB);
            var secretB = ImplAgreement(ukm, sKeyB, pKeyA);

            Assert.True(Arrays.AreEqual(secretA, secretB), "ECVKO agreement failed");
            Assert.True(Arrays.AreEqual(secretA, expectedResult), "ECVKO agreement unexpected result");
        }

        private static byte[] ImplAgreement(byte[] ukm, AsymmetricKeyParameter privateKey,
            AsymmetricKeyParameter publicKey)
        {
            var digest = new Gost3411_2012_256Digest();
            var agreement = new ECVkoAgreement(digest);
            agreement.Init(new ParametersWithUkm(privateKey, ukm));
            byte[] secret = new byte[agreement.AgreementSize];
            agreement.CalculateAgreement(publicKey, secret, 0);
            return secret;
        }
    }
}
