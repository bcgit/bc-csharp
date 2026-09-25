using NUnit.Framework;

using Org.BouncyCastle.Asn1.CryptoPro;
using Org.BouncyCastle.Crypto.Agreement;
using Org.BouncyCastle.Crypto.Digests;
using Org.BouncyCastle.Crypto.Generators;
using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.Security;
using Org.BouncyCastle.Utilities.Encoders;

namespace Org.BouncyCastle.Crypto.Tests
{
    /// <summary>
    /// <see cref="ParametersWithUkm"/> goes outside <see cref="ParametersWithRandom"/>. Every ukm consumer must
    /// accept that nesting with the same result as no randomness at all.
    /// </summary>
    /// <remarks>
    /// Ported from bc-java's UKMParametersNestingTest. There are no GOST 28147 wrap engines here, so only the VKO
    /// case applies.
    /// </remarks>
    [TestFixture]
    public class UkmParametersNestingTest
    {
        private static readonly SecureRandom Random = new SecureRandom();

        private static readonly byte[] Ukm = Hex.Decode("1d80603c8544c727");

        [Test]
        public void TestVko()
        {
            var domain = new ECDomainParameters(ECGost3410NamedCurves.GetByName("Tc26-Gost-3410-12-256-paramSetA"));

            var kpGen = new ECKeyPairGenerator();
            kpGen.Init(new ECKeyGenerationParameters(domain, Random));

            AsymmetricCipherKeyPair kpA = kpGen.GenerateKeyPair();
            AsymmetricCipherKeyPair kpB = kpGen.GenerateKeyPair();

            var agreeA = new ECVkoAgreement(new Gost3411_2012_256Digest());
            agreeA.Init(new ParametersWithUkm(kpA.Private, Ukm));
            byte[] expected = CalculateAgreement(agreeA, kpB.Public);

            agreeA.Init(new ParametersWithUkm(new ParametersWithRandom(kpA.Private, Random), Ukm));
            Assert.That(CalculateAgreement(agreeA, kpB.Public), Is.EqualTo(expected),
                "VKO agreement differs for Ukm(Random(key))");

            var agreeB = new ECVkoAgreement(new Gost3411_2012_256Digest());
            agreeB.Init(new ParametersWithUkm(new ParametersWithRandom(kpB.Private, Random), Ukm));
            Assert.That(CalculateAgreement(agreeB, kpA.Public), Is.EqualTo(expected),
                "VKO peer agreement differs for Ukm(Random(key))");
        }

        private static byte[] CalculateAgreement(IRawAgreement agreement, ICipherParameters publicKey)
        {
            byte[] result = new byte[agreement.AgreementSize];
            agreement.CalculateAgreement(publicKey, result, 0);
            return result;
        }
    }
}
