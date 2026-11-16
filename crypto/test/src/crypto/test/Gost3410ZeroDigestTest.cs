using System.Collections.Generic;

using NUnit.Framework;

using Org.BouncyCastle.Asn1.CryptoPro;
using Org.BouncyCastle.Crypto.Generators;
using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.Crypto.Signers;
using Org.BouncyCastle.Math;
using Org.BouncyCastle.Security;
using Org.BouncyCastle.Utilities;

namespace Org.BouncyCastle.Crypto.Tests
{
    /// <summary>
    /// RFC 5832 / RFC 7091 sec. 6.1 step 2 and sec. 6.2 step 3 (and GOST R 34.10-94 likewise): a message
    /// representative that is 0 mod q is replaced by 1 before use, when signing and when verifying. Without it a
    /// signature over such a digest is s = d * r mod q, which gives up the private key as s * r^-1, and
    /// GOST R 34.10-94 verification accepted r = 1 with any s.
    /// </summary>
    [TestFixture]
    public class Gost3410ZeroDigestTest
    {
        private static readonly SecureRandom Random = new SecureRandom();

        private static IEnumerable<TestCaseData> ECNamedCurves()
        {
            foreach (string name in ECGost3410NamedCurves.Names)
            {
                yield return new TestCaseData(name).SetArgDisplayNames(name);
            }
        }

        private static IEnumerable<TestCaseData> Gost94NamedParameters()
        {
            foreach (string name in Gost3410NamedParameters.Names)
            {
                yield return new TestCaseData(name).SetArgDisplayNames(name);
            }
        }

        [TestCaseSource(nameof(ECNamedCurves))]
        public void ECGost3410(string curveName)
        {
            var domain = new ECDomainParameters(ECGost3410NamedCurves.GetByName(curveName));
            BigInteger n = domain.N;
            int digestLength = n.BitLength > 256 ? 64 : 32;

            var kpGen = new ECKeyPairGenerator();
            kpGen.Init(new ECKeyGenerationParameters(domain, Random));
            AsymmetricCipherKeyPair kp = kpGen.GenerateKeyPair();
            BigInteger d = ((ECPrivateKeyParameters)kp.Private).D;

            byte[] one = new byte[digestLength];
            one[0] = 1; // little-endian 1

            byte[][] zeroDigests = new byte[][]
            {
                new byte[digestLength],
                new byte[0],
                Arrays.Reverse(BigIntegers.AsUnsignedByteArray(digestLength, n)), // n, little-endian
            };

            for (int i = 0; i < zeroDigests.Length; ++i)
            {
                var signer = new ECGost3410Signer();
                signer.Init(true, new ParametersWithRandom(kp.Private, Random));
                BigInteger[] sig = signer.GenerateSignature(zeroDigests[i]);

                Assert.AreNotEqual(d, sig[1].Multiply(sig[0].ModInverse(n)).Mod(n),
                    "digest " + i + ": s * r^-1 is the private key");

                var verifier = new ECGost3410Signer();
                verifier.Init(false, kp.Public);
                // previously threw ArithmeticException ("BigInteger not invertible")
                Assert.IsTrue(verifier.VerifySignature(zeroDigests[i], sig[0], sig[1]),
                    "digest " + i + ": own signature does not verify");
                Assert.IsTrue(verifier.VerifySignature(one, sig[0], sig[1]),
                    "digest " + i + ": signature not formed over e = 1");
            }
        }

        [TestCaseSource(nameof(Gost94NamedParameters))]
        public void Gost3410_94(string paramSetName)
        {
            var kpGen = new Gost3410KeyPairGenerator();
            kpGen.Init(new Gost3410KeyGenerationParameters(Random, Gost3410NamedParameters.GetOid(paramSetName)));
            AsymmetricCipherKeyPair kp = kpGen.GenerateKeyPair();
            BigInteger q = ((Gost3410PrivateKeyParameters)kp.Private).Parameters.Q;
            BigInteger x = ((Gost3410PrivateKeyParameters)kp.Private).X;

            byte[] one = new byte[32];
            one[0] = 1; // little-endian 1

            byte[][] zeroDigests = new byte[][]
            {
                new byte[32],
                new byte[0],
                Arrays.Reverse(BigIntegers.AsUnsignedByteArray(32, q)), // q, little-endian
            };

            for (int i = 0; i < zeroDigests.Length; ++i)
            {
                var signer = new Gost3410Signer();
                signer.Init(true, new ParametersWithRandom(kp.Private, Random));
                BigInteger[] sig = signer.GenerateSignature(zeroDigests[i]);

                Assert.AreNotEqual(x, sig[1].Multiply(sig[0].ModInverse(q)).Mod(q),
                    "digest " + i + ": s * r^-1 is the private key");

                var verifier = new Gost3410Signer();
                verifier.Init(false, kp.Public);
                Assert.IsTrue(verifier.VerifySignature(zeroDigests[i], sig[0], sig[1]),
                    "digest " + i + ": own signature does not verify");
                Assert.IsTrue(verifier.VerifySignature(one, sig[0], sig[1]),
                    "digest " + i + ": signature not formed over m = 1");

                // with m = 0 left as 0, v = 0 and z1 = z2 = 0, so u = 1 and r = 1 verified for any s without the key
                BigInteger anyS = BigIntegers.CreateRandomInRange(BigInteger.One, q.Subtract(BigInteger.One), Random);
                Assert.IsFalse(verifier.VerifySignature(zeroDigests[i], BigInteger.One, anyS),
                    "digest " + i + ": r = 1 with an arbitrary s verifies");
            }
        }
    }
}
