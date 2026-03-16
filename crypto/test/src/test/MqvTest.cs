using System;

using NUnit.Framework;

using Org.BouncyCastle.Asn1.X9;
using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.Math;
using Org.BouncyCastle.Security;

namespace Org.BouncyCastle.Tests
{
    [TestFixture]
    public class MqvTest
    {
        private readonly SecureRandom Random = new SecureRandom();

        /**
         * Different curves should fail due to domain parameter mismatch.
         */
        [Test]
        public void TestDifferentCurveAgreement()
        {
            var kpg256 = GeneratorUtilities.GetKeyPairGenerator("ECMQV");
            kpg256.Init(new ECKeyGenerationParameters(ECNamedCurveTable.GetOid("secp256r1"), Random));

            var kpg384 = GeneratorUtilities.GetKeyPairGenerator("ECMQV");
            kpg384.Init(new ECKeyGenerationParameters(ECNamedCurveTable.GetOid("secp384r1"), Random));

            var U1 = kpg256.GenerateKeyPair();
            var U2 = kpg256.GenerateKeyPair();

            var V1 = kpg384.GenerateKeyPair();
            var V2 = kpg384.GenerateKeyPair();

            try
            {
                var uAgree = AgreementUtilities.GetBasicAgreement("ECMQV");
                InitECMqv(uAgree, U1, U2);

                CalculateAgreementECMqv(uAgree, V1, V2);

                Assert.Fail("Expected InvalidOperationException for mismatched EC domain parameters");
            }
            catch (InvalidOperationException)
            {
                // Expected
            }

            try
            {
                var uAgree = AgreementUtilities.GetBasicAgreement("ECMQV");
                InitECMqv(uAgree, U1, V2);

                Assert.Fail("Expected ArgumentException for mismatched EC domain parameters");
            }
            catch (ArgumentException)
            {
                // Expected
            }
        }

        [Test]
        public void TestECMqv()
        {
            var kpg = GeneratorUtilities.GetKeyPairGenerator("ECMQV");
            kpg.Init(new ECKeyGenerationParameters(ECNamedCurveTable.GetOid("secp256r1"), Random));

            //
            // U side
            //
            var U1 = kpg.GenerateKeyPair();
            var U2 = kpg.GenerateKeyPair();

            var uAgree = AgreementUtilities.GetBasicAgreement("ECMQV");
            InitECMqv(uAgree, U1, U2);

            //
            // V side
            //
            var V1 = kpg.GenerateKeyPair();
            var V2 = kpg.GenerateKeyPair();

            var vAgree = AgreementUtilities.GetBasicAgreement("ECMQV");
            InitECMqv(vAgree, V1, V2);

            //
            // agreement
            //
            var ux = CalculateAgreementECMqv(uAgree, V1, V2);
            var vx = CalculateAgreementECMqv(vAgree, U1, U2);

            Assert.AreEqual(ux, vx, "Agreement failed");
        }

        private static void InitECMqv(IBasicAgreement agreement, AsymmetricCipherKeyPair staticKeyPair,
            AsymmetricCipherKeyPair ephemeralKeyPair)
        {
            var mqvPrivate = new MqvPrivateParameters((ECPrivateKeyParameters)staticKeyPair.Private,
                (ECPrivateKeyParameters)ephemeralKeyPair.Private, (ECPublicKeyParameters)ephemeralKeyPair.Public);
            agreement.Init(mqvPrivate);
        }

        private static BigInteger CalculateAgreementECMqv(IBasicAgreement agreement,
            AsymmetricCipherKeyPair staticKeyPair, AsymmetricCipherKeyPair ephemeralKeyPair)
        {
            var mqvPublic = new MqvPublicParameters((ECPublicKeyParameters)staticKeyPair.Public,
                (ECPublicKeyParameters)ephemeralKeyPair.Public);
            return agreement.CalculateAgreement(mqvPublic);
        }
    }
}
