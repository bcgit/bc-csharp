using System;

using NUnit.Framework;

using Org.BouncyCastle.Asn1;
using Org.BouncyCastle.Asn1.CryptoPro;
using Org.BouncyCastle.Asn1.Pkcs;
using Org.BouncyCastle.Asn1.Rosstandart;
using Org.BouncyCastle.Asn1.X509;
using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Crypto.Generators;
using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.Pkcs;
using Org.BouncyCastle.Security;
using Org.BouncyCastle.X509;

namespace Org.BouncyCastle.Tests
{
    /// <summary>
    /// Checks the key algorithm OID chosen when encoding ECGOST3410 keys as SubjectPublicKeyInfo/PrivateKeyInfo.
    /// A legacy GOST R 34.10-2001 parameter set combined with a GOST R 34.11-2012 digest must encode as GOST R
    /// 34.10-2012 (RFC 9215, Section 4.2), while the same curve with a GOST R 34.11-94 digest remains GOST R
    /// 34.10-2001 (RFC 4491, Section 2.3.2).
    /// </summary>
    [TestFixture]
    public class ECGost3410KeyEncodingTest
    {
        private static readonly Asn1Set Attributes = new DerSet(
            new AttributePkcs(PkcsObjectIdentifiers.Pkcs9AtFriendlyName, new DerSet(new DerBmpString("ECGOST3410"))));

        private static readonly TestCaseData[] AlgorithmOidCases =
        {
            // Legacy CryptoPro parameter sets with a GOST R 34.11-2012 digest (RFC 9215, Section 4.2)
            Case("CryptoPro-A with 34.11-2012-256",
                CryptoProObjectIdentifiers.GostR3410x2001CryptoProA,
                RosstandartObjectIdentifiers.id_tc26_gost_3411_12_256,
                RosstandartObjectIdentifiers.id_tc26_gost_3410_12_256),
            Case("CryptoPro-XchA with 34.11-2012-256",
                CryptoProObjectIdentifiers.GostR3410x2001CryptoProXchA,
                RosstandartObjectIdentifiers.id_tc26_gost_3411_12_256,
                RosstandartObjectIdentifiers.id_tc26_gost_3410_12_256),

            // Legacy CryptoPro parameter sets with a GOST R 34.11-94 digest (RFC 4491, Section 2.3.2)
            Case("CryptoPro-A with 34.11-94 CryptoPro",
                CryptoProObjectIdentifiers.GostR3410x2001CryptoProA,
                CryptoProObjectIdentifiers.GostR3411x94CryptoProParamSet,
                CryptoProObjectIdentifiers.GostR3410x2001),
            Case("CryptoPro-A with 34.11-94 Test",
                CryptoProObjectIdentifiers.GostR3410x2001CryptoProA,
                CryptoProObjectIdentifiers.GostR3411x94TestParamSet,
                CryptoProObjectIdentifiers.GostR3410x2001),

            // TC26 parameter sets
            Case("TC26 256-A with 34.11-2012-256",
                RosstandartObjectIdentifiers.id_tc26_gost_3410_12_256_paramSetA,
                RosstandartObjectIdentifiers.id_tc26_gost_3411_12_256,
                RosstandartObjectIdentifiers.id_tc26_gost_3410_12_256),
            Case("TC26 512-A with 34.11-2012-512",
                RosstandartObjectIdentifiers.id_tc26_gost_3410_12_512_paramSetA,
                RosstandartObjectIdentifiers.id_tc26_gost_3411_12_512,
                RosstandartObjectIdentifiers.id_tc26_gost_3410_12_512),

            // TC26 parameter sets with digestParamSet omitted (RFC 9215, Section 4.2: MUST for 256-B/C/D, SHOULD
            // for 256-A and 512-bit keys)
            Case("TC26 256-B with no digest",
                RosstandartObjectIdentifiers.id_tc26_gost_3410_12_256_paramSetB,
                null,
                RosstandartObjectIdentifiers.id_tc26_gost_3410_12_256),
            Case("TC26 512-A with no digest",
                RosstandartObjectIdentifiers.id_tc26_gost_3410_12_512_paramSetA,
                null,
                RosstandartObjectIdentifiers.id_tc26_gost_3410_12_512),
        };

        private static TestCaseData Case(string displayName, DerObjectIdentifier publicKeyParamSet,
            DerObjectIdentifier digestParamSet, DerObjectIdentifier expectedAlgOid)
        {
            return new TestCaseData(publicKeyParamSet, digestParamSet, expectedAlgOid).SetArgDisplayNames(displayName);
        }

        [TestCaseSource(nameof(AlgorithmOidCases))]
        public void KeyAlgID(DerObjectIdentifier publicKeyParamSet, DerObjectIdentifier digestParamSet,
            DerObjectIdentifier expectedAlgOid)
        {
            var keyPair = GenerateKeyPair(publicKeyParamSet, digestParamSet);

            var spki = SubjectPublicKeyInfoFactory.CreateSubjectPublicKeyInfo(keyPair.Public);
            CheckAlgorithmIdentifier(spki.Algorithm, expectedAlgOid, publicKeyParamSet, digestParamSet);

            var pki = PrivateKeyInfoFactory.CreatePrivateKeyInfo(keyPair.Private, Attributes);
            CheckAlgorithmIdentifier(pki.PrivateKeyAlgorithm, expectedAlgOid, publicKeyParamSet, digestParamSet);
            Assert.That(pki.Attributes, Is.EqualTo(Attributes));

            // Round trip: the key material and the algorithm OID must survive decoding and re-encoding
            var publicKey = (ECPublicKeyParameters)PublicKeyFactory.CreateKey(spki);
            Assert.That(publicKey.Q, Is.EqualTo(((ECPublicKeyParameters)keyPair.Public).Q));
            Assert.That(SubjectPublicKeyInfoFactory.CreateSubjectPublicKeyInfo(publicKey).Algorithm.Algorithm,
                Is.EqualTo(expectedAlgOid));

            var privateKey = (ECPrivateKeyParameters)PrivateKeyFactory.CreateKey(pki);
            Assert.That(privateKey.D, Is.EqualTo(((ECPrivateKeyParameters)keyPair.Private).D));
            Assert.That(PrivateKeyInfoFactory.CreatePrivateKeyInfo(privateKey).PrivateKeyAlgorithm.Algorithm,
                Is.EqualTo(expectedAlgOid));
        }

        /// <summary>
        /// Original test case from PR #709 (issue #707): a GOST R 34.10-2012 key using a legacy CryptoPro parameter
        /// set must be encoded with the GOST 2012 algorithm OID in SubjectPublicKeyInfo (per RFC 9215).
        /// </summary>
        [Test]
        public void Gost2012CryptoProSpki()
        {
            // 1. Select a legacy CryptoPro curve OID (GOST R 34.10-2001 parameter set)
            var curveOid = CryptoProObjectIdentifiers.GostR3410x2001CryptoProA;
            var domain = ECGost3410NamedCurves.GetByOid(curveOid);
            var namedDomain = new ECNamedDomainParameters(curveOid, domain);

            // 2. Configure key parameters with a GOST 2012 (256-bit) digest OID
            var gostParameters = new ECGost3410Parameters(
                namedDomain,
                curveOid,
                RosstandartObjectIdentifiers.id_tc26_gost_3411_12_256,
                null);

            // 3. Generate a key pair based on GOST 2012 parameters
            var keyGen = new ECKeyPairGenerator();
            keyGen.Init(new ECKeyGenerationParameters(gostParameters, new SecureRandom()));
            var keyPair = keyGen.GenerateKeyPair();

            // 4. Wrap the public key into SubjectPublicKeyInfo structure
            var spki = SubjectPublicKeyInfoFactory.CreateSubjectPublicKeyInfo(keyPair.Public);

            // 5. Assert that the algorithm OID corresponds to GOST 2012 rather than GOST 2001
            Assert.That(spki.Algorithm.Algorithm, Is.EqualTo(RosstandartObjectIdentifiers.id_tc26_gost_3410_12_256));
        }

        [Test]
        public void UnrecognizedDigestParamSet()
        {
            // The GOST R 34.11-94 algorithm OID is not a digest parameter set
            var keyPair = GenerateKeyPair(CryptoProObjectIdentifiers.GostR3410x2001CryptoProA,
                CryptoProObjectIdentifiers.GostR3411);

            Assert.Throws<ArgumentException>(
                () => SubjectPublicKeyInfoFactory.CreateSubjectPublicKeyInfo(keyPair.Public));
            Assert.Throws<ArgumentException>(
                () => PrivateKeyInfoFactory.CreatePrivateKeyInfo(keyPair.Private));
        }

        private static void CheckAlgorithmIdentifier(AlgorithmIdentifier algID, DerObjectIdentifier expectedAlgOid,
            DerObjectIdentifier publicKeyParamSet, DerObjectIdentifier digestParamSet)
        {
            Assert.That(algID.Algorithm, Is.EqualTo(expectedAlgOid));

            // An omitted digestParamSet must be absent from the encoding, not encoded as some placeholder
            int expectedCount = digestParamSet == null ? 1 : 2;
            Assert.That(Asn1Sequence.GetInstance(algID.Parameters).Count, Is.EqualTo(expectedCount));

            var algParams = Gost3410PublicKeyAlgParameters.GetInstance(algID.Parameters);
            Assert.That(algParams.PublicKeyParamSet, Is.EqualTo(publicKeyParamSet));
            Assert.That(algParams.DigestParamSet, Is.EqualTo(digestParamSet));
            Assert.That(algParams.EncryptionParamSet, Is.Null);
        }

        [Test]
        public void AlgParametersSequenceSizes()
        {
            var publicKeyParamSet = CryptoProObjectIdentifiers.GostR3410x2001CryptoProA;
            var digestParamSet = CryptoProObjectIdentifiers.GostR3411x94CryptoProParamSet;
            var encryptionParamSet = CryptoProObjectIdentifiers.ID_Gost28147_89_CryptoPro_A_ParamSet;

            // One element: digestParamSet omitted (RFC 9215)
            var one = Gost3410PublicKeyAlgParameters.GetInstance(new DerSequence(publicKeyParamSet));
            Assert.That(one.PublicKeyParamSet, Is.EqualTo(publicKeyParamSet));
            Assert.That(one.DigestParamSet, Is.Null);
            Assert.That(one.EncryptionParamSet, Is.Null);
            Assert.That(one.ToAsn1Object(), Is.EqualTo(new DerSequence(publicKeyParamSet)));

            // Two elements: the second is always digestParamSet, never encryptionParamSet
            var two = Gost3410PublicKeyAlgParameters.GetInstance(new DerSequence(publicKeyParamSet, digestParamSet));
            Assert.That(two.DigestParamSet, Is.EqualTo(digestParamSet));
            Assert.That(two.EncryptionParamSet, Is.Null);
            Assert.That(two.ToAsn1Object(), Is.EqualTo(new DerSequence(publicKeyParamSet, digestParamSet)));

            // Three elements (RFC 4491)
            var threeSeq = new DerSequence(publicKeyParamSet, digestParamSet, encryptionParamSet);
            var three = Gost3410PublicKeyAlgParameters.GetInstance(threeSeq);
            Assert.That(three.DigestParamSet, Is.EqualTo(digestParamSet));
            Assert.That(three.EncryptionParamSet, Is.EqualTo(encryptionParamSet));
            Assert.That(three.ToAsn1Object(), Is.EqualTo(threeSeq));

            // Out-of-range sizes
            Assert.Throws<ArgumentException>(() => Gost3410PublicKeyAlgParameters.GetInstance(new DerSequence()));
            Assert.Throws<ArgumentException>(() => Gost3410PublicKeyAlgParameters.GetInstance(
                new DerSequence(publicKeyParamSet, digestParamSet, encryptionParamSet, encryptionParamSet)));

            // encryptionParamSet cannot be encoded without digestParamSet
            Assert.Throws<ArgumentException>(
                () => new Gost3410PublicKeyAlgParameters(publicKeyParamSet, null, encryptionParamSet));
        }

        private static AsymmetricCipherKeyPair GenerateKeyPair(DerObjectIdentifier publicKeyParamSet,
            DerObjectIdentifier digestParamSet)
        {
            var domainParameters = ECNamedDomainParameters.LookupOid(publicKeyParamSet);
            var gostParameters = new ECGost3410Parameters(domainParameters, publicKeyParamSet, digestParamSet, null);

            var generator = new ECKeyPairGenerator();
            generator.Init(new ECKeyGenerationParameters(gostParameters, new SecureRandom()));
            return generator.GenerateKeyPair();
        }
    }
}
