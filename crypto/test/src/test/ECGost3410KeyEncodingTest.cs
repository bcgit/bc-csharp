using System;
using System.Collections.Generic;

using NUnit.Framework;

using Org.BouncyCastle.Asn1;
using Org.BouncyCastle.Asn1.CryptoPro;
using Org.BouncyCastle.Asn1.Pkcs;
using Org.BouncyCastle.Asn1.Rosstandart;
using Org.BouncyCastle.Asn1.Sec;
using Org.BouncyCastle.Asn1.X509;
using Org.BouncyCastle.Asn1.X9;
using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Crypto.Generators;
using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.Math;
using Org.BouncyCastle.Pkcs;
using Org.BouncyCastle.Security;
using Org.BouncyCastle.Utilities;
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
            // 2. Configure key parameters with a GOST 2012 (256-bit) digest OID
            var gostParams = new GostR3410x2012PublicKeyParameters(CryptoProObjectIdentifiers.GostR3410x2001CryptoProA,
                RosstandartObjectIdentifiers.id_tc26_gost_3411_12_256);
            var ecGost3410Parameters = ECGost3410Parameters.FromPublicKeyParameters(gostParams);

            // 3. Generate a key pair based on GOST 2012 parameters
            var keyGen = new ECKeyPairGenerator();
            keyGen.Init(new ECKeyGenerationParameters(ecGost3410Parameters, new SecureRandom()));
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

            // An omitted digestParamSet (or DEFAULT encryptionParamSet) must be absent from the encoding
            int expectedCount = digestParamSet == null ? 1 : 2;
            Assert.That(Asn1Sequence.GetInstance(algID.Parameters).Count, Is.EqualTo(expectedCount));

            if (CryptoProObjectIdentifiers.GostR3410x2001.Equals(expectedAlgOid))
            {
                var algParams = GostR3410x2001PublicKeyParameters.GetInstance(algID.Parameters);
                Assert.That(algParams.PublicKeyParamSet, Is.EqualTo(publicKeyParamSet));
                Assert.That(algParams.DigestParamSet, Is.EqualTo(digestParamSet));
                Assert.That(algParams.EncryptionParamSet,
                    Is.EqualTo(GostR3410x2001PublicKeyParameters.DefaultEncryptionParamSet));
            }
            else
            {
                var algParams = GostR3410x2012PublicKeyParameters.GetInstance(algID.Parameters);
                Assert.That(algParams.PublicKeyParamSet, Is.EqualTo(publicKeyParamSet));
                Assert.That(algParams.DigestParamSet, Is.EqualTo(digestParamSet));
            }
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

        private static readonly TestCaseData[] CurveOidCases =
        {
            // "ECGOST3410" (GOST R 34.10-2001) on a CryptoPro parameter set
            CurveOidCase("ECGOST3410 on CryptoPro-A", "ECGOST3410",
                CryptoProObjectIdentifiers.GostR3410x2001CryptoProA,
                CryptoProObjectIdentifiers.GostR3410x2001,
                CryptoProObjectIdentifiers.GostR3411x94CryptoProParamSet),

            // TC26 parameter sets are GOST R 34.10-2012 regardless of the algorithm name
            CurveOidCase("ECGOST3410 on TC26 256-A", "ECGOST3410",
                RosstandartObjectIdentifiers.id_tc26_gost_3410_12_256_paramSetA,
                RosstandartObjectIdentifiers.id_tc26_gost_3410_12_256,
                null),
            CurveOidCase("ECGOST3410 on TC26 512-A", "ECGOST3410",
                RosstandartObjectIdentifiers.id_tc26_gost_3410_12_512_paramSetA,
                RosstandartObjectIdentifiers.id_tc26_gost_3410_12_512,
                null),
            CurveOidCase("ECGOST3410-2012 on TC26 256-B", "ECGOST3410-2012",
                RosstandartObjectIdentifiers.id_tc26_gost_3410_12_256_paramSetB,
                RosstandartObjectIdentifiers.id_tc26_gost_3410_12_256,
                null),

            // A GOST R 34.10-2012 key on a legacy parameter set must carry id-tc26-gost3411-12-256 (RFC 9215, 4.2)
            CurveOidCase("ECGOST3410-2012 on CryptoPro-A", "ECGOST3410-2012",
                CryptoProObjectIdentifiers.GostR3410x2001CryptoProA,
                RosstandartObjectIdentifiers.id_tc26_gost_3410_12_256,
                RosstandartObjectIdentifiers.id_tc26_gost_3411_12_256),
        };

        private static TestCaseData CurveOidCase(string displayName, string algorithm, DerObjectIdentifier curveOid,
            DerObjectIdentifier expectedAlgOid, DerObjectIdentifier expectedDigestParamSet)
        {
            return new TestCaseData(algorithm, curveOid, expectedAlgOid, expectedDigestParamSet)
                .SetArgDisplayNames(displayName);
        }

        /// <summary>
        /// A key pair generated from a bare curve OID under a GOST algorithm name is promoted to
        /// <see cref="ECGost3410Parameters"/>, with default parameter sets chosen from the algorithm name and curve. A
        /// key constructed directly with plain named domain parameters must encode the same way. Both must round trip
        /// through the key factories.
        /// </summary>
        [TestCaseSource(nameof(CurveOidCases))]
        public void GeneratedFromCurveOid(string algorithm, DerObjectIdentifier curveOid,
            DerObjectIdentifier expectedAlgOid, DerObjectIdentifier expectedDigestParamSet)
        {
            var generator = GeneratorUtilities.GetKeyPairGenerator(algorithm);
            generator.Init(new ECKeyGenerationParameters(curveOid, new SecureRandom()));
            var keyPair = generator.GenerateKeyPair();

            var publicKey = (ECPublicKeyParameters)keyPair.Public;
            var privateKey = (ECPrivateKeyParameters)keyPair.Private;

            var gostParameters = (ECGost3410Parameters)privateKey.Parameters;
            Assert.That(gostParameters.PublicKeyParamSet, Is.EqualTo(curveOid));
            Assert.That(gostParameters.DigestParamSet, Is.EqualTo(expectedDigestParamSet));
            Assert.That(publicKey.Parameters, Is.SameAs(gostParameters));

            int fieldSize = privateKey.Parameters.Curve.FieldElementEncodingLength;

            var spki = SubjectPublicKeyInfoFactory.CreateSubjectPublicKeyInfo(publicKey);
            CheckAlgorithmIdentifier(spki.Algorithm, expectedAlgOid, curveOid, expectedDigestParamSet);

            var pki = PrivateKeyInfoFactory.CreatePrivateKeyInfo(privateKey);
            CheckAlgorithmIdentifier(pki.PrivateKeyAlgorithm, expectedAlgOid, curveOid, expectedDigestParamSet);

            // Keys constructed with plain named domain parameters are promoted by the encoders
            var namedParameters = ECNamedDomainParameters.LookupOid(curveOid);
            Assert.That(namedParameters, Is.Not.InstanceOf<ECGost3410Parameters>());
            var plainPublic = new ECPublicKeyParameters(algorithm, publicKey.Q, namedParameters);
            var plainPrivate = new ECPrivateKeyParameters(algorithm, privateKey.D, namedParameters);
            Assert.That(SubjectPublicKeyInfoFactory.CreateSubjectPublicKeyInfo(plainPublic), Is.EqualTo(spki));
            Assert.That(PrivateKeyInfoFactory.CreatePrivateKeyInfo(plainPrivate), Is.EqualTo(pki));

            // The private key must be the little-endian OCTET STRING form, not an ECPrivateKey structure
            var privateKeyOctets = Asn1OctetString.GetInstance(pki.ParsePrivateKey());
            Assert.That(privateKeyOctets.GetOctetsLength(), Is.EqualTo(fieldSize));

            var decodedPublic = (ECPublicKeyParameters)PublicKeyFactory.CreateKey(spki);
            Assert.That(decodedPublic.Q, Is.EqualTo(publicKey.Q));
            Assert.That(decodedPublic.PublicKeyParamSet, Is.EqualTo(curveOid));

            var decodedPrivate = (ECPrivateKeyParameters)PrivateKeyFactory.CreateKey(pki);
            Assert.That(decodedPrivate.D, Is.EqualTo(privateKey.D));
            Assert.That(decodedPrivate.PublicKeyParamSet, Is.EqualTo(curveOid));
            Assert.That(decodedPrivate, Is.EqualTo(privateKey));

            // Re-encoding the decoded keys must be stable
            Assert.That(SubjectPublicKeyInfoFactory.CreateSubjectPublicKeyInfo(decodedPublic), Is.EqualTo(spki));
            Assert.That(PrivateKeyInfoFactory.CreatePrivateKeyInfo(decodedPrivate), Is.EqualTo(pki));
        }

        [Test]
        public void NonGostCurveRejected()
        {
            var generator = GeneratorUtilities.GetKeyPairGenerator("ECGOST3410");
            generator.Init(new ECKeyGenerationParameters(SecObjectIdentifiers.SecP256r1, new SecureRandom()));
            var keyPair = generator.GenerateKeyPair();
            Assert.That(((ECPrivateKeyParameters)keyPair.Private).Parameters,
                Is.Not.InstanceOf<ECGost3410Parameters>());

            Assert.Throws<ArgumentException>(
                () => SubjectPublicKeyInfoFactory.CreateSubjectPublicKeyInfo(keyPair.Public));
            Assert.Throws<ArgumentException>(
                () => PrivateKeyInfoFactory.CreatePrivateKeyInfo(keyPair.Private));
        }

        /// <summary>
        /// Keys on explicit (unnamed) domain parameters, or on a GOST curve name that does not match the domain
        /// parameters, are generated as given (they remain usable for signing) but cannot be encoded.
        /// </summary>
        [Test]
        public void UnpromotableParametersNotPromoted()
        {
            var gostOid = CryptoProObjectIdentifiers.GostR3410x2001CryptoProA;
            var explicitParameters = ECDomainParameters.FromX9ECParameters(ECGost3410NamedCurves.GetByOid(gostOid));
            var misnamedParameters = new ECNamedDomainParameters(gostOid,
                ECNamedCurveTable.GetByOid(SecObjectIdentifiers.SecP256r1));

            foreach (var domainParameters in new[] { explicitParameters, misnamedParameters })
            {
                var generator = GeneratorUtilities.GetKeyPairGenerator("ECGOST3410");
                generator.Init(new ECKeyGenerationParameters(domainParameters, new SecureRandom()));
                var keyPair = generator.GenerateKeyPair();
                Assert.That(((ECPrivateKeyParameters)keyPair.Private).Parameters, Is.SameAs(domainParameters));

                Assert.Throws<ArgumentException>(
                    () => SubjectPublicKeyInfoFactory.CreateSubjectPublicKeyInfo(keyPair.Public));
                Assert.Throws<ArgumentException>(
                    () => PrivateKeyInfoFactory.CreatePrivateKeyInfo(keyPair.Private));
            }
        }

        /// <summary>
        /// Key generation by strength alone selects X9.62/SEC curves, never GOST ones, so it is rejected for the GOST
        /// algorithm names.
        /// </summary>
        [TestCase("ECGOST3410")]
        [TestCase("ECGOST3410-2012")]
        public void StrengthOnlyInitRejected(string algorithm)
        {
            var generator = GeneratorUtilities.GetKeyPairGenerator(algorithm);
            Assert.Throws<ArgumentException>(
                () => generator.Init(new KeyGenerationParameters(new SecureRandom(), 256)));
        }

        private static readonly TestCaseData[] LegacyPrivateKeyShapeCases =
        {
            new TestCaseData(CryptoProObjectIdentifiers.GostR3410x2001,
                CryptoProObjectIdentifiers.GostR3410x2001CryptoProA,
                CryptoProObjectIdentifiers.GostR3411x94CryptoProParamSet).SetArgDisplayNames("2001 CryptoPro-A"),
            new TestCaseData(RosstandartObjectIdentifiers.id_tc26_gost_3410_12_256,
                CryptoProObjectIdentifiers.GostR3410x2001CryptoProA,
                RosstandartObjectIdentifiers.id_tc26_gost_3411_12_256).SetArgDisplayNames("2012 CryptoPro-A"),
            new TestCaseData(RosstandartObjectIdentifiers.id_tc26_gost_3410_12_512,
                RosstandartObjectIdentifiers.id_tc26_gost_3410_12_512_paramSetA,
                null).SetArgDisplayNames("2012 TC26 512-A"),
        };

        /// <summary>
        /// PrivateKeyFactory must accept the private key shapes other encoders (and older bc-csharp versions) have
        /// produced under a GOST algorithm OID: an ECPrivateKey structure with either GOST parameters or a bare curve
        /// OID, an INTEGER, and a nested OCTET STRING, as well as the standard raw little-endian OCTET STRING.
        /// </summary>
        [TestCaseSource(nameof(LegacyPrivateKeyShapeCases))]
        public void LegacyPrivateKeyShapes(DerObjectIdentifier algOid, DerObjectIdentifier curveOid,
            DerObjectIdentifier expectedDigestParamSet)
        {
            var x9 = ECGost3410NamedCurves.GetByOid(curveOid);
            var d = new BigInteger(x9.N.BitLength - 1, new SecureRandom()).Add(BigInteger.One);
            int fieldSize = x9.Curve.FieldElementEncodingLength;

            var gostAlgID = CreateGostAlgID(algOid, curveOid, expectedDigestParamSet);
            var bareOidAlgID = new AlgorithmIdentifier(algOid, curveOid);

            var ecPrivateKey = new ECPrivateKeyStructure(x9.N.BitLength, d);
            var dLittleEndian = BigIntegers.AsUnsignedByteArray(fieldSize, d);
            Array.Reverse(dLittleEndian);

            var shapes = new[]
            {
                // Standard (BC): GOST parameters, little-endian OCTET STRING inside the PrivateKeyInfo OCTET STRING
                new PrivateKeyInfo(gostAlgID, new DerOctetString(dLittleEndian)),
                // GOST parameters, raw little-endian octets as the PrivateKeyInfo OCTET STRING (CryptoPro)
                PrivateKeyInfo.GetInstance(
                    new DerSequence(DerInteger.Zero, gostAlgID, new DerOctetString(dLittleEndian))),
                // GOST parameters with an ECPrivateKey structure (older bc-csharp versions)
                new PrivateKeyInfo(gostAlgID, ecPrivateKey),
                // GOST parameters with an INTEGER (other encoders)
                new PrivateKeyInfo(gostAlgID, new DerInteger(d)),
                // Bare curve OID with an ECPrivateKey structure (bc-java provider) or INTEGER
                new PrivateKeyInfo(bareOidAlgID, ecPrivateKey),
                new PrivateKeyInfo(bareOidAlgID, new DerInteger(d)),
            };

            foreach (var pki in shapes)
            {
                var privateKey = (ECPrivateKeyParameters)PrivateKeyFactory.CreateKey(pki);

                Assert.That(privateKey.D, Is.EqualTo(d));
                Assert.That(privateKey.AlgorithmName, Is.EqualTo("ECGOST3410"));
                Assert.That(privateKey.PublicKeyParamSet, Is.EqualTo(curveOid));

                var parameters = (ECGost3410Parameters)privateKey.Parameters;
                Assert.That(parameters.DigestParamSet, Is.EqualTo(expectedDigestParamSet));

                // Every shape re-encodes to the standard form under the original algorithm OID
                var reencoded = PrivateKeyInfoFactory.CreatePrivateKeyInfo(privateKey);
                Assert.That(reencoded, Is.EqualTo(shapes[0]));
            }
        }

        /// <summary>
        /// The raw form is recognized only at the curve's field size, so an ASN.1 form whose length is the other raw
        /// size is parsed as ASN.1 rather than misread as raw.
        /// </summary>
        [Test]
        public void PrivateKeyRawLengthFollowsCurve()
        {
            // 256-bit curve: a nested OCTET STRING zero-padded (little-endian) to 62 bytes, 64 bytes in all
            {
                var algID = CreateGostAlgID(CryptoProObjectIdentifiers.GostR3410x2001,
                    CryptoProObjectIdentifiers.GostR3410x2001CryptoProA,
                    CryptoProObjectIdentifiers.GostR3411x94CryptoProParamSet);
                var x9 = ECGost3410NamedCurves.GetByOid(CryptoProObjectIdentifiers.GostR3410x2001CryptoProA);
                var d = new BigInteger(x9.N.BitLength - 1, new SecureRandom()).Add(BigInteger.One);

                var dLittleEndian = Arrays.ReverseInPlace(BigIntegers.AsUnsignedByteArray(62, d));
                var pki = new PrivateKeyInfo(algID, new DerOctetString(dLittleEndian));
                Assert.That(pki.PrivateKeyLength, Is.EqualTo(64));

                var privateKey = (ECPrivateKeyParameters)PrivateKeyFactory.CreateKey(pki);
                Assert.That(privateKey.D, Is.EqualTo(d));
            }

            // 512-bit curve: an INTEGER with 30 content bytes, 32 bytes in all
            {
                var algID = CreateGostAlgID(RosstandartObjectIdentifiers.id_tc26_gost_3410_12_512,
                    RosstandartObjectIdentifiers.id_tc26_gost_3410_12_512_paramSetA, null);
                var d = new BigInteger(239, new SecureRandom()).SetBit(238);

                var pki = new PrivateKeyInfo(algID, new DerInteger(d));
                Assert.That(pki.PrivateKeyLength, Is.EqualTo(32));

                var privateKey = (ECPrivateKeyParameters)PrivateKeyFactory.CreateKey(pki);
                Assert.That(privateKey.D, Is.EqualTo(d));
            }
        }

        private static readonly TestCaseData[] PublicKeyAlgorithmOidCases =
        {
            new TestCaseData(CryptoProObjectIdentifiers.GostR3410x2001,
                CryptoProObjectIdentifiers.GostR3410x2001CryptoProA,
                CryptoProObjectIdentifiers.GostR3411x94CryptoProParamSet).SetArgDisplayNames("2001 CryptoPro-A"),
            new TestCaseData(RosstandartObjectIdentifiers.id_tc26_gost_3410_12_256,
                RosstandartObjectIdentifiers.id_tc26_gost_3410_12_256_paramSetA,
                null).SetArgDisplayNames("2012-256 TC26 256-A"),
            new TestCaseData(RosstandartObjectIdentifiers.id_tc26_gost_3410_12_512,
                RosstandartObjectIdentifiers.id_tc26_gost_3410_12_512_paramSetA,
                null).SetArgDisplayNames("2012-512 TC26 512-A"),
            new TestCaseData(RosstandartObjectIdentifiers.id_tc26_agreement_gost_3410_12_256,
                RosstandartObjectIdentifiers.id_tc26_gost_3410_12_256_paramSetB,
                null).SetArgDisplayNames("agreement-256 TC26 256-B"),
            new TestCaseData(RosstandartObjectIdentifiers.id_tc26_agreement_gost_3410_12_512,
                RosstandartObjectIdentifiers.id_tc26_gost_3410_12_512_paramSetB,
                null).SetArgDisplayNames("agreement-512 TC26 512-B"),
        };

        /// <summary>
        /// PublicKeyFactory must decode an ECGOST3410 public key under any of the key algorithm OIDs, including the
        /// GOST R 34.10-2012 agreement OIDs (which the encoder never produces) and with a bare curve OID in place of
        /// the GOST parameters, sizing the point from the curve rather than the algorithm OID.
        /// </summary>
        [TestCaseSource(nameof(PublicKeyAlgorithmOidCases))]
        public void PublicKeyAlgorithmOids(DerObjectIdentifier algOid, DerObjectIdentifier curveOid,
            DerObjectIdentifier digestParamSet)
        {
            var keyPair = GenerateKeyPair(curveOid, digestParamSet);
            var publicKey = (ECPublicKeyParameters)keyPair.Public;

            // Take the encoder's public key octets and re-wrap them under the OID being tested
            var encoded = SubjectPublicKeyInfoFactory.CreateSubjectPublicKeyInfo(publicKey);
            var publicKeyData = encoded.PublicKey;

            var gostAlgID = CreateGostAlgID(algOid, curveOid, digestParamSet);
            var bareOidAlgID = new AlgorithmIdentifier(algOid, curveOid);

            foreach (var algID in new[] { gostAlgID, bareOidAlgID })
            {
                var spki = new SubjectPublicKeyInfo(algID, publicKeyData);
                var decoded = (ECPublicKeyParameters)PublicKeyFactory.CreateKey(spki);

                Assert.That(decoded.Q, Is.EqualTo(publicKey.Q));
                Assert.That(decoded.AlgorithmName, Is.EqualTo("ECGOST3410"));
                Assert.That(decoded.PublicKeyParamSet, Is.EqualTo(curveOid));
                Assert.That(decoded.Parameters, Is.InstanceOf<ECGost3410Parameters>());
            }

            // A public key of the wrong size for the curve is rejected
            var truncated = new SubjectPublicKeyInfo(gostAlgID, Arrays.CopyOf(publicKeyData.GetBytes(), 32));
            Assert.Throws<ArgumentException>(() => PublicKeyFactory.CreateKey(truncated));
        }

        /// <summary>
        /// The GOST R 34.10-2001 encryptionParamSet is DEFAULT id-Gost28147-89-CryptoPro-A-ParamSet (RFC 4491): an
        /// absent value decodes as the DEFAULT, an explicit DEFAULT is omitted on re-encoding, and any other value
        /// round trips.
        /// </summary>
        [Test]
        public void Gost2001EncryptionParamSet()
        {
            var algOid = CryptoProObjectIdentifiers.GostR3410x2001;
            var publicKeyParamSet = CryptoProObjectIdentifiers.GostR3410x2001CryptoProA;
            var digestParamSet = CryptoProObjectIdentifiers.GostR3411x94CryptoProParamSet;
            var defaultEncryptionParamSet = GostR3410x2001PublicKeyParameters.DefaultEncryptionParamSet;
            var otherEncryptionParamSet = CryptoProObjectIdentifiers.ID_Gost28147_89_CryptoPro_B_ParamSet;

            var keyPair = GenerateKeyPair(
                new ECGost3410Parameters(publicKeyParamSet, digestParamSet, otherEncryptionParamSet));

            var spki = SubjectPublicKeyInfoFactory.CreateSubjectPublicKeyInfo(keyPair.Public);
            Assert.That(spki.Algorithm.Parameters,
                Is.EqualTo(new DerSequence(publicKeyParamSet, digestParamSet, otherEncryptionParamSet)));
            Assert.That(GetEncryptionParamSet(PublicKeyFactory.CreateKey(spki)), Is.EqualTo(otherEncryptionParamSet));

            var pki = PrivateKeyInfoFactory.CreatePrivateKeyInfo(keyPair.Private);
            Assert.That(pki.PrivateKeyAlgorithm.Parameters, Is.EqualTo(spki.Algorithm.Parameters));
            Assert.That(GetEncryptionParamSet(PrivateKeyFactory.CreateKey(pki)), Is.EqualTo(otherEncryptionParamSet));

            var defaultAlgID = new AlgorithmIdentifier(algOid, new DerSequence(publicKeyParamSet, digestParamSet));
            var algIDs = new[]
            {
                defaultAlgID,
                new AlgorithmIdentifier(algOid,
                    new DerSequence(publicKeyParamSet, digestParamSet, defaultEncryptionParamSet)),
                new AlgorithmIdentifier(algOid, publicKeyParamSet),
            };

            foreach (var algID in algIDs)
            {
                var publicKey = PublicKeyFactory.CreateKey(new SubjectPublicKeyInfo(algID, spki.PublicKey));
                Assert.That(GetEncryptionParamSet(publicKey), Is.EqualTo(defaultEncryptionParamSet));
                Assert.That(SubjectPublicKeyInfoFactory.CreateSubjectPublicKeyInfo(publicKey).Algorithm,
                    Is.EqualTo(defaultAlgID));

                var privateKey = PrivateKeyFactory.CreateKey(new PrivateKeyInfo(algID, pki.ParsePrivateKey()));
                Assert.That(GetEncryptionParamSet(privateKey), Is.EqualTo(defaultEncryptionParamSet));
                Assert.That(PrivateKeyInfoFactory.CreatePrivateKeyInfo(privateKey).PrivateKeyAlgorithm,
                    Is.EqualTo(defaultAlgID));
            }
        }

        /// <summary>
        /// GOST R 34.10-2001 parameters require digestParamSet (RFC 4491), so a one-element SEQUENCE is rejected.
        /// </summary>
        [Test]
        public void Gost2001MissingDigestParamSetRejected()
        {
            var keyPair = GenerateKeyPair(CryptoProObjectIdentifiers.GostR3410x2001CryptoProA,
                CryptoProObjectIdentifiers.GostR3411x94CryptoProParamSet);
            var spki = SubjectPublicKeyInfoFactory.CreateSubjectPublicKeyInfo(keyPair.Public);
            var pki = PrivateKeyInfoFactory.CreatePrivateKeyInfo(keyPair.Private);

            var algID = new AlgorithmIdentifier(CryptoProObjectIdentifiers.GostR3410x2001,
                new DerSequence(CryptoProObjectIdentifiers.GostR3410x2001CryptoProA));

            Assert.Throws<ArgumentException>(
                () => PublicKeyFactory.CreateKey(new SubjectPublicKeyInfo(algID, spki.PublicKey)));
            Assert.Throws<ArgumentException>(
                () => PrivateKeyFactory.CreateKey(new PrivateKeyInfo(algID, pki.ParsePrivateKey())));
        }

        /// <summary>
        /// GOST R 34.10-2012 parameters have no encryptionParamSet (RFC 9215), so one set on the parameters is not
        /// encoded.
        /// </summary>
        [Test]
        public void Gost2012EncryptionParamSetNotEncoded()
        {
            var publicKeyParamSet = RosstandartObjectIdentifiers.id_tc26_gost_3410_12_256_paramSetA;
            var digestParamSet = RosstandartObjectIdentifiers.id_tc26_gost_3411_12_256;

            var keyPair = GenerateKeyPair(new ECGost3410Parameters(publicKeyParamSet, digestParamSet,
                CryptoProObjectIdentifiers.ID_Gost28147_89_CryptoPro_A_ParamSet));

            var expected = new DerSequence(publicKeyParamSet, digestParamSet);

            var spki = SubjectPublicKeyInfoFactory.CreateSubjectPublicKeyInfo(keyPair.Public);
            Assert.That(spki.Algorithm.Algorithm, Is.EqualTo(RosstandartObjectIdentifiers.id_tc26_gost_3410_12_256));
            Assert.That(spki.Algorithm.Parameters, Is.EqualTo(expected));

            var pki = PrivateKeyInfoFactory.CreatePrivateKeyInfo(keyPair.Private);
            Assert.That(pki.PrivateKeyAlgorithm.Parameters, Is.EqualTo(expected));
        }

        /// <summary>
        /// bc-csharp versions prior to 2.8.0 could encode a GOST R 34.10-2012 key with an encryptionParamSet. Such
        /// keys are rejected unless <see cref="Properties.GostAllowLenientKeyParameters"/> is set, and then re-encode
        /// in the RFC 9215 form.
        /// </summary>
        [Test]
        public void Gost2012LegacyEncryptionParamSet()
        {
            var algOid = RosstandartObjectIdentifiers.id_tc26_gost_3410_12_256;
            var publicKeyParamSet = RosstandartObjectIdentifiers.id_tc26_gost_3410_12_256_paramSetA;
            var digestParamSet = RosstandartObjectIdentifiers.id_tc26_gost_3411_12_256;
            var encryptionParamSet = CryptoProObjectIdentifiers.ID_Gost28147_89_CryptoPro_A_ParamSet;

            var keyPair = GenerateKeyPair(publicKeyParamSet, digestParamSet);
            var spki = SubjectPublicKeyInfoFactory.CreateSubjectPublicKeyInfo(keyPair.Public);
            var pki = PrivateKeyInfoFactory.CreatePrivateKeyInfo(keyPair.Private);

            var legacyAlgID = new AlgorithmIdentifier(algOid,
                new DerSequence(publicKeyParamSet, digestParamSet, encryptionParamSet));
            var legacySpki = new SubjectPublicKeyInfo(legacyAlgID, spki.PublicKey);
            var legacyPki = new PrivateKeyInfo(legacyAlgID, pki.ParsePrivateKey());

            Assert.Throws<ArgumentException>(() => PublicKeyFactory.CreateKey(legacySpki));
            Assert.Throws<ArgumentException>(() => PrivateKeyFactory.CreateKey(legacyPki));

            Properties.WithThreadProperty(Properties.GostAllowLenientKeyParameters, bool.TrueString, () =>
            {
                var publicKey = (ECPublicKeyParameters)PublicKeyFactory.CreateKey(legacySpki);
                Assert.That(publicKey.Q, Is.EqualTo(((ECPublicKeyParameters)keyPair.Public).Q));
                Assert.That(SubjectPublicKeyInfoFactory.CreateSubjectPublicKeyInfo(publicKey), Is.EqualTo(spki));

                var privateKey = (ECPrivateKeyParameters)PrivateKeyFactory.CreateKey(legacyPki);
                Assert.That(privateKey.D, Is.EqualTo(((ECPrivateKeyParameters)keyPair.Private).D));
                Assert.That(PrivateKeyInfoFactory.CreatePrivateKeyInfo(privateKey), Is.EqualTo(pki));
            });
        }

        /// <summary>
        /// GOST R 34.10-2001 (RFC 4491) defines no TC26 parameter sets, but bc-csharp versions prior to 2.8.0 could
        /// encode such a key under the GOST R 34.10-2001 key algorithm. Such keys are rejected unless
        /// <see cref="Properties.GostAllowLenientKeyParameters"/> is set.
        /// </summary>
        [Test]
        public void Gost2001Tc26ParamSet()
        {
            var algOid = CryptoProObjectIdentifiers.GostR3410x2001;
            var publicKeyParamSet = RosstandartObjectIdentifiers.id_tc26_gost_3410_12_256_paramSetA;
            var digestParamSet = CryptoProObjectIdentifiers.GostR3411x94CryptoProParamSet;

            var keyPair = GenerateKeyPair(publicKeyParamSet, null);
            var spki = SubjectPublicKeyInfoFactory.CreateSubjectPublicKeyInfo(keyPair.Public);
            var pki = PrivateKeyInfoFactory.CreatePrivateKeyInfo(keyPair.Private);

            var expectedAlgID = new AlgorithmIdentifier(algOid, new DerSequence(publicKeyParamSet, digestParamSet));
            var algIDs = new[]
            {
                expectedAlgID,
                new AlgorithmIdentifier(algOid, publicKeyParamSet),
            };

            foreach (var algID in algIDs)
            {
                var legacySpki = new SubjectPublicKeyInfo(algID, spki.PublicKey);
                var legacyPki = new PrivateKeyInfo(algID, pki.ParsePrivateKey());

                Assert.Throws<ArgumentException>(() => PublicKeyFactory.CreateKey(legacySpki));
                Assert.Throws<ArgumentException>(() => PrivateKeyFactory.CreateKey(legacyPki));

                Properties.WithThreadProperty(Properties.GostAllowLenientKeyParameters, bool.TrueString, () =>
                {
                    var publicKey = (ECPublicKeyParameters)PublicKeyFactory.CreateKey(legacySpki);
                    Assert.That(publicKey.Q, Is.EqualTo(((ECPublicKeyParameters)keyPair.Public).Q));
                    Assert.That(SubjectPublicKeyInfoFactory.CreateSubjectPublicKeyInfo(publicKey).Algorithm,
                        Is.EqualTo(expectedAlgID));

                    var privateKey = (ECPrivateKeyParameters)PrivateKeyFactory.CreateKey(legacyPki);
                    Assert.That(privateKey.D, Is.EqualTo(((ECPrivateKeyParameters)keyPair.Private).D));
                    Assert.That(PrivateKeyInfoFactory.CreatePrivateKeyInfo(privateKey).PrivateKeyAlgorithm,
                        Is.EqualTo(expectedAlgID));
                });
            }
        }

        private static readonly TestCaseData[] InconsistentKeyAlgorithmCases =
        {
            new TestCaseData(RosstandartObjectIdentifiers.id_tc26_gost_3410_12_256,
                RosstandartObjectIdentifiers.id_tc26_gost_3410_12_256_paramSetA,
                CryptoProObjectIdentifiers.GostR3411x94CryptoProParamSet).SetArgDisplayNames("2012-256 with 34.11-94"),
            new TestCaseData(CryptoProObjectIdentifiers.GostR3410x2001,
                CryptoProObjectIdentifiers.GostR3410x2001CryptoProA,
                RosstandartObjectIdentifiers.id_tc26_gost_3411_12_256).SetArgDisplayNames("2001 with 34.11-2012"),
            new TestCaseData(RosstandartObjectIdentifiers.id_tc26_gost_3410_12_512,
                RosstandartObjectIdentifiers.id_tc26_gost_3410_12_256_paramSetA,
                null).SetArgDisplayNames("2012-512 on 256-bit curve"),
            new TestCaseData(RosstandartObjectIdentifiers.id_tc26_agreement_gost_3410_12_512,
                RosstandartObjectIdentifiers.id_tc26_gost_3410_12_256_paramSetA,
                null).SetArgDisplayNames("agreement-512 on 256-bit curve"),
            new TestCaseData(RosstandartObjectIdentifiers.id_tc26_gost_3410_12_256,
                RosstandartObjectIdentifiers.id_tc26_gost_3410_12_256_paramSetA,
                CryptoProObjectIdentifiers.GostR3411).SetArgDisplayNames("2012-256 with unrecognized digest"),
        };

        /// <summary>
        /// The encoder derives the key algorithm OID from the parameters, so parameters that identify a different key
        /// algorithm than the one they are decoded under (or none, for an unrecognized digestParamSet) are rejected
        /// unless <see cref="Properties.GostAllowLenientKeyParameters"/> is set. bc-csharp versions prior to 2.8.0
        /// could write such keys, since they chose the key algorithm OID from the curve.
        /// </summary>
        [TestCaseSource(nameof(InconsistentKeyAlgorithmCases))]
        public void InconsistentKeyAlgorithmRejected(DerObjectIdentifier algOid, DerObjectIdentifier curveOid,
            DerObjectIdentifier digestParamSet)
        {
            var keyPair = GenerateKeyPair(curveOid, null);
            var spki = SubjectPublicKeyInfoFactory.CreateSubjectPublicKeyInfo(keyPair.Public);
            var pki = PrivateKeyInfoFactory.CreatePrivateKeyInfo(keyPair.Private);

            var algIDs = new List<AlgorithmIdentifier> { CreateGostAlgID(algOid, curveOid, digestParamSet) };
            if (digestParamSet == null)
            {
                // A bare curve OID is equivalent to parameters without a digestParamSet
                algIDs.Add(new AlgorithmIdentifier(algOid, curveOid));
            }

            foreach (var algID in algIDs)
            {
                var inconsistentSpki = new SubjectPublicKeyInfo(algID, spki.PublicKey);
                var inconsistentPki = new PrivateKeyInfo(algID, pki.ParsePrivateKey());

                Assert.Throws<ArgumentException>(() => PublicKeyFactory.CreateKey(inconsistentSpki));
                Assert.Throws<ArgumentException>(() => PrivateKeyFactory.CreateKey(inconsistentPki));

                Properties.WithThreadProperty(Properties.GostAllowLenientKeyParameters, bool.TrueString, () =>
                {
                    var publicKey = (ECPublicKeyParameters)PublicKeyFactory.CreateKey(inconsistentSpki);
                    Assert.That(publicKey.Q, Is.EqualTo(((ECPublicKeyParameters)keyPair.Public).Q));

                    var privateKey = (ECPrivateKeyParameters)PrivateKeyFactory.CreateKey(inconsistentPki);
                    Assert.That(privateKey.D, Is.EqualTo(((ECPrivateKeyParameters)keyPair.Private).D));
                });
            }
        }

        private static DerObjectIdentifier GetEncryptionParamSet(AsymmetricKeyParameter key) =>
            ((ECGost3410Parameters)((ECKeyParameters)key).Parameters).EncryptionParamSet;

        [Test]
        public void ExplicitParametersRejected()
        {
            var x9 = ECGost3410NamedCurves.GetByOid(CryptoProObjectIdentifiers.GostR3410x2001CryptoProA);
            var explicitParams = new X962Parameters(x9);
            var algID = new AlgorithmIdentifier(CryptoProObjectIdentifiers.GostR3410x2001, explicitParams);
            var pki = new PrivateKeyInfo(algID, new ECPrivateKeyStructure(x9.N.BitLength, BigInteger.One));

            Assert.Throws<ArgumentException>(() => PrivateKeyFactory.CreateKey(pki));
        }

        private static AsymmetricCipherKeyPair GenerateKeyPair(DerObjectIdentifier publicKeyParamSet,
            DerObjectIdentifier digestParamSet)
        {
            return GenerateKeyPair(new ECGost3410Parameters(publicKeyParamSet, digestParamSet, null));
        }

        private static AsymmetricCipherKeyPair GenerateKeyPair(ECGost3410Parameters parameters)
        {
            var generator = new ECKeyPairGenerator();
            generator.Init(new ECKeyGenerationParameters(parameters, new SecureRandom()));
            return generator.GenerateKeyPair();
        }

        private static AlgorithmIdentifier CreateGostAlgID(DerObjectIdentifier algOid,
            DerObjectIdentifier publicKeyParamSet, DerObjectIdentifier digestParamSet)
        {
            Asn1Encodable algParams;
            if (CryptoProObjectIdentifiers.GostR3410x2001.Equals(algOid))
            {
                algParams = new GostR3410x2001PublicKeyParameters(publicKeyParamSet, digestParamSet);
            }
            else
            {
                algParams = new GostR3410x2012PublicKeyParameters(publicKeyParamSet, digestParamSet);
            }
            return new AlgorithmIdentifier(algOid, algParams);
        }
    }
}
