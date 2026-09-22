using System;

using NUnit.Framework;

using Org.BouncyCastle.Asn1;
using Org.BouncyCastle.Asn1.CryptoPro;
using Org.BouncyCastle.Asn1.Rosstandart;
using Org.BouncyCastle.Asn1.X9;
using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.Pkcs;
using Org.BouncyCastle.Security;

namespace Org.BouncyCastle.Cms.Tests
{
    [TestFixture]
    public class CmsSignedHelperTest
    {
        private static readonly TestCaseData[] ECGost3410EncOidCases =
        {
            new TestCaseData("ECGOST3410", CryptoProObjectIdentifiers.GostR3410x2001CryptoProA,
                CryptoProObjectIdentifiers.GostR3410x2001).SetArgDisplayNames("ECGOST3410 on CryptoPro-A"),
            new TestCaseData("ECGOST3410", RosstandartObjectIdentifiers.id_tc26_gost_3410_12_256_paramSetA,
                RosstandartObjectIdentifiers.id_tc26_gost_3410_12_256).SetArgDisplayNames("ECGOST3410 on TC26 256-A"),
            new TestCaseData("ECGOST3410-2012", CryptoProObjectIdentifiers.GostR3410x2001CryptoProA,
                RosstandartObjectIdentifiers.id_tc26_gost_3410_12_256).SetArgDisplayNames(
                    "ECGOST3410-2012 on CryptoPro-A"),
            new TestCaseData("ECGOST3410-2012", RosstandartObjectIdentifiers.id_tc26_gost_3410_12_512_paramSetA,
                RosstandartObjectIdentifiers.id_tc26_gost_3410_12_512).SetArgDisplayNames(
                    "ECGOST3410-2012 on TC26 512-A"),
        };

        /// <summary>
        /// The encryption (signature) algorithm OID for an ECGOST3410 key must follow the key's GOST parameters, both
        /// for a freshly generated key and for the same key decoded by <see cref="PrivateKeyFactory"/> (which names
        /// every ECGOST3410 key "ECGOST3410", whatever its version).
        /// </summary>
        [TestCaseSource(nameof(ECGost3410EncOidCases))]
        public void ECGost3410EncOid(string algorithm, DerObjectIdentifier curveOid, DerObjectIdentifier expectedOid)
        {
            var generator = GeneratorUtilities.GetKeyPairGenerator(algorithm);
            generator.Init(new ECKeyGenerationParameters(curveOid, new SecureRandom()));
            var privateKey = generator.GenerateKeyPair().Private;

            var decoded = PrivateKeyFactory.CreateKey(PrivateKeyInfoFactory.CreatePrivateKeyInfo(privateKey));
            Assert.That(((ECPrivateKeyParameters)decoded).AlgorithmName, Is.EqualTo("ECGOST3410"));

            foreach (var key in new[] { privateKey, decoded })
            {
                Assert.That(CmsSignedHelper.GetEncOid(key, CmsSignedGenerator.DigestGost3411), Is.EqualTo(expectedOid));
            }
        }

        /// <summary>
        /// An ECGOST3410 key on domain parameters that are not a named ECGOST3410 parameter set has no GOST key
        /// algorithm OID.
        /// </summary>
        [Test]
        public void ECGost3410ExplicitParametersRejected()
        {
            var x9 = ECGost3410NamedCurves.GetByOid(CryptoProObjectIdentifiers.GostR3410x2001CryptoProA);
            var generator = GeneratorUtilities.GetKeyPairGenerator("ECGOST3410");
            generator.Init(new ECKeyGenerationParameters(ECDomainParameters.FromX9ECParameters(x9),
                new SecureRandom()));
            AsymmetricKeyParameter privateKey = generator.GenerateKeyPair().Private;

            Assert.Throws<ArgumentException>(
                () => CmsSignedHelper.GetEncOid(privateKey, CmsSignedGenerator.DigestGost3411));
        }

        [Test]
        public void ECDsaEncOid()
        {
            var generator = GeneratorUtilities.GetKeyPairGenerator("EC");
            generator.Init(new ECKeyGenerationParameters(X9ObjectIdentifiers.Prime256v1, new SecureRandom()));
            var privateKey = generator.GenerateKeyPair().Private;

            Assert.That(CmsSignedHelper.GetEncOid(privateKey, CmsSignedGenerator.DigestSha256),
                Is.EqualTo(X9ObjectIdentifiers.ECDsaWithSha256));
        }
    }
}
