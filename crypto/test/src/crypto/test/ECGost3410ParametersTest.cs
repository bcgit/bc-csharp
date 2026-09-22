using System;
using System.Collections.Generic;

using NUnit.Framework;

using Org.BouncyCastle.Asn1;
using Org.BouncyCastle.Asn1.CryptoPro;
using Org.BouncyCastle.Asn1.Rosstandart;
using Org.BouncyCastle.Asn1.Sec;
using Org.BouncyCastle.Asn1.X9;
using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.Math;

namespace Org.BouncyCastle.Crypto.Tests
{
    /// <summary>
    /// Tests for <see cref="ECGost3410Parameters"/>: construction from parameter set OIDs (validated against
    /// <see cref="ECGost3410NamedCurves"/>), conversion from <see cref="GostR3410x2001PublicKeyParameters"/> and
    /// <see cref="GostR3410x2012PublicKeyParameters"/>, and
    /// the consistency checks in the legacy constructors that accept caller-supplied domain parameters.
    /// </summary>
    [TestFixture]
    public class ECGost3410ParametersTest
    {
        private static readonly DerObjectIdentifier EncryptionParamSet =
            CryptoProObjectIdentifiers.ID_Gost28147_89_CryptoPro_A_ParamSet;

        /// <summary>
        /// Every ECGOST3410 named curve, covering both the CryptoPro (2001) and TC26 (2012) parameter sets.
        /// </summary>
        private static IEnumerable<TestCaseData> NamedCurves()
        {
            foreach (string name in ECGost3410NamedCurves.Names)
            {
                yield return new TestCaseData(ECGost3410NamedCurves.GetOid(name)).SetArgDisplayNames(name);
            }
        }

        [TestCaseSource(nameof(NamedCurves))]
        public void ConstructFromParamSets(DerObjectIdentifier publicKeyParamSet)
        {
            var digestParamSet = DefaultDigestParamSet(publicKeyParamSet);

            var parameters = new ECGost3410Parameters(publicKeyParamSet, digestParamSet, EncryptionParamSet);

            Assert.That(parameters.Name, Is.EqualTo(publicKeyParamSet));
            Assert.That(parameters.PublicKeyParamSet, Is.EqualTo(publicKeyParamSet));
            Assert.That(parameters.DigestParamSet, Is.EqualTo(digestParamSet));
            Assert.That(parameters.EncryptionParamSet, Is.EqualTo(EncryptionParamSet));

            CheckCurve(parameters, publicKeyParamSet);

            // ECKeyParameters.PublicKeyParamSet is derived from the name, so the two views must agree
            var privateKey = new ECPrivateKeyParameters("ECGOST3410", BigInteger.One, parameters);
            Assert.That(privateKey.PublicKeyParamSet, Is.EqualTo(publicKeyParamSet));
        }

        [TestCaseSource(nameof(NamedCurves))]
        public void FromGost2001PublicKeyParameters(DerObjectIdentifier publicKeyParamSet)
        {
            var digestParamSet = CryptoProObjectIdentifiers.GostR3411x94CryptoProParamSet;
            var otherEncryptionParamSet = CryptoProObjectIdentifiers.ID_Gost28147_89_CryptoPro_B_ParamSet;

            // The DEFAULT encryptionParamSet is reported, not null
            CheckFrom(new GostR3410x2001PublicKeyParameters(publicKeyParamSet, digestParamSet),
                publicKeyParamSet, digestParamSet, GostR3410x2001PublicKeyParameters.DefaultEncryptionParamSet);
            CheckFrom(new GostR3410x2001PublicKeyParameters(publicKeyParamSet, digestParamSet, otherEncryptionParamSet),
                publicKeyParamSet, digestParamSet, otherEncryptionParamSet);
        }

        [TestCaseSource(nameof(NamedCurves))]
        public void FromGost2012PublicKeyParameters(DerObjectIdentifier publicKeyParamSet)
        {
            var digestParamSet = DefaultDigestParamSet(publicKeyParamSet);

            CheckFrom(new GostR3410x2012PublicKeyParameters(publicKeyParamSet),
                publicKeyParamSet, null, null);
            CheckFrom(new GostR3410x2012PublicKeyParameters(publicKeyParamSet, digestParamSet),
                publicKeyParamSet, digestParamSet, null);
        }

        [Test]
        public void FromNullThrows()
        {
            Assert.Throws<ArgumentNullException>(
                () => ECGost3410Parameters.FromPublicKeyParameters((GostR3410x2001PublicKeyParameters)null));
            Assert.Throws<ArgumentNullException>(
                () => ECGost3410Parameters.FromPublicKeyParameters((GostR3410x2012PublicKeyParameters)null));
        }

        [Test]
        public void UnrecognizedCurveOidThrows()
        {
            // A valid EC named curve, but not an ECGOST3410 parameter set
            var notGost = SecObjectIdentifiers.SecP256r1;
            var digestParamSet = RosstandartObjectIdentifiers.id_tc26_gost_3411_12_256;

            Assert.Throws<ArgumentException>(() => new ECGost3410Parameters(notGost, digestParamSet, null));
            Assert.Throws<ArgumentException>(() => ECGost3410Parameters.FromPublicKeyParameters(
                new GostR3410x2012PublicKeyParameters(notGost, digestParamSet)));
            Assert.Throws<ArgumentException>(() => ECGost3410Parameters.FromPublicKeyParameters(
                new GostR3410x2001PublicKeyParameters(notGost,
                    CryptoProObjectIdentifiers.GostR3411x94CryptoProParamSet)));
        }

        [Test]
        public void EncryptionParamSetRequiresDigestParamSet()
        {
            var publicKeyParamSet = CryptoProObjectIdentifiers.GostR3410x2001CryptoProA;

            Assert.Throws<ArgumentException>(
                () => new ECGost3410Parameters(publicKeyParamSet, null, EncryptionParamSet));

            // The legacy constructors route through the same check
#pragma warning disable CS0618 // Type or member is obsolete
            var x9 = ECGost3410NamedCurves.GetByOid(publicKeyParamSet);
            var named = new ECNamedDomainParameters(publicKeyParamSet, x9);
            Assert.Throws<ArgumentException>(
                () => new ECGost3410Parameters(named, publicKeyParamSet, null, EncryptionParamSet));
#pragma warning restore CS0618
        }

#pragma warning disable CS0618 // Type or member is obsolete

        [TestCaseSource(nameof(NamedCurves))]
        public void LegacyConstructorFromNamedDomainParameters(DerObjectIdentifier publicKeyParamSet)
        {
            var digestParamSet = DefaultDigestParamSet(publicKeyParamSet);
            var x9 = ECGost3410NamedCurves.GetByOid(publicKeyParamSet);
            var named = new ECNamedDomainParameters(publicKeyParamSet, x9);

            var parameters = new ECGost3410Parameters(named, publicKeyParamSet, digestParamSet, EncryptionParamSet);

            Assert.That(parameters.Name, Is.EqualTo(publicKeyParamSet));
            Assert.That(parameters.PublicKeyParamSet, Is.EqualTo(publicKeyParamSet));
            Assert.That(parameters.DigestParamSet, Is.EqualTo(digestParamSet));
            Assert.That(parameters.EncryptionParamSet, Is.EqualTo(EncryptionParamSet));
            CheckCurve(parameters, publicKeyParamSet);
        }

        [TestCaseSource(nameof(NamedCurves))]
        public void LegacyConstructorFromUnnamedDomainParameters(DerObjectIdentifier publicKeyParamSet)
        {
            var digestParamSet = DefaultDigestParamSet(publicKeyParamSet);
            var x9 = ECGost3410NamedCurves.GetByOid(publicKeyParamSet);
            var unnamed = ECDomainParameters.FromX9ECParameters(x9);

            var parameters = new ECGost3410Parameters(unnamed, publicKeyParamSet, digestParamSet, null);

            Assert.That(parameters.Name, Is.EqualTo(publicKeyParamSet));
            Assert.That(parameters.PublicKeyParamSet, Is.EqualTo(publicKeyParamSet));
            CheckCurve(parameters, publicKeyParamSet);
        }

        [Test]
        public void LegacyConstructorRejectsNameMismatch()
        {
            // CryptoPro-A and CryptoPro-XchA share a curve, so only the name check can reject this pairing
            var oidA = CryptoProObjectIdentifiers.GostR3410x2001CryptoProA;
            var oidXchA = CryptoProObjectIdentifiers.GostR3410x2001CryptoProXchA;
            var digestParamSet = CryptoProObjectIdentifiers.GostR3411x94CryptoProParamSet;

            var namedA = new ECNamedDomainParameters(oidA, ECGost3410NamedCurves.GetByOid(oidA));
            Assert.That(namedA.Curve, Is.EqualTo(ECGost3410NamedCurves.GetByOid(oidXchA).Curve));

            Assert.Throws<ArgumentException>(
                () => new ECGost3410Parameters(namedA, oidXchA, digestParamSet, null));
            Assert.Throws<ArgumentException>(
                () => new ECGost3410Parameters((ECDomainParameters)namedA, oidXchA, digestParamSet, null));
        }

        [Test]
        public void LegacyConstructorRejectsForeignCurve()
        {
            var gostOid = RosstandartObjectIdentifiers.id_tc26_gost_3410_12_256_paramSetA;
            var digestParamSet = RosstandartObjectIdentifiers.id_tc26_gost_3411_12_256;
            var p256 = ECNamedCurveTable.GetByOid(SecObjectIdentifiers.SecP256r1);

            // Unnamed: only the curve comparison can reject this
            var unnamed = ECDomainParameters.FromX9ECParameters(p256);
            Assert.Throws<ArgumentException>(
                () => new ECGost3410Parameters(unnamed, gostOid, digestParamSet, null));

            // Named: rejected by the name check
            var named = new ECNamedDomainParameters(SecObjectIdentifiers.SecP256r1, p256);
            Assert.Throws<ArgumentException>(
                () => new ECGost3410Parameters(named, gostOid, digestParamSet, null));
        }

        [Test]
        public void LegacyConstructorRejectsNulls()
        {
            var gostOid = CryptoProObjectIdentifiers.GostR3410x2001CryptoProA;
            var digestParamSet = CryptoProObjectIdentifiers.GostR3411x94CryptoProParamSet;
            var named = new ECNamedDomainParameters(gostOid, ECGost3410NamedCurves.GetByOid(gostOid));

            Assert.Throws<ArgumentNullException>(
                () => new ECGost3410Parameters((ECNamedDomainParameters)null, gostOid, digestParamSet, null));
            Assert.Throws<ArgumentNullException>(
                () => new ECGost3410Parameters((ECDomainParameters)null, gostOid, digestParamSet, null));
            Assert.Throws<ArgumentNullException>(
                () => new ECGost3410Parameters(named, null, digestParamSet, null));
        }

#pragma warning restore CS0618

        private static void CheckCurve(ECGost3410Parameters parameters, DerObjectIdentifier publicKeyParamSet)
        {
            var x9 = ECGost3410NamedCurves.GetByOid(publicKeyParamSet);

            Assert.That(parameters.Curve, Is.EqualTo(x9.Curve));
            Assert.That(parameters.G, Is.EqualTo(x9.G));
            Assert.That(parameters.N, Is.EqualTo(x9.N));
            Assert.That(parameters.H, Is.EqualTo(x9.H));
        }

        private static void CheckFrom(ECGost3410Parameters parameters, DerObjectIdentifier publicKeyParamSet,
            DerObjectIdentifier digestParamSet, DerObjectIdentifier encryptionParamSet)
        {
            Assert.That(parameters.PublicKeyParamSet, Is.EqualTo(publicKeyParamSet));
            Assert.That(parameters.DigestParamSet, Is.EqualTo(digestParamSet));
            Assert.That(parameters.EncryptionParamSet, Is.EqualTo(encryptionParamSet));
            CheckCurve(parameters, publicKeyParamSet);
        }

        private static void CheckFrom(GostR3410x2001PublicKeyParameters publicKeyParameters,
            DerObjectIdentifier publicKeyParamSet, DerObjectIdentifier digestParamSet,
            DerObjectIdentifier encryptionParamSet)
        {
            CheckFrom(ECGost3410Parameters.FromPublicKeyParameters(publicKeyParameters), publicKeyParamSet,
                digestParamSet, encryptionParamSet);
        }

        private static void CheckFrom(GostR3410x2012PublicKeyParameters publicKeyParameters,
            DerObjectIdentifier publicKeyParamSet, DerObjectIdentifier digestParamSet,
            DerObjectIdentifier encryptionParamSet)
        {
            CheckFrom(ECGost3410Parameters.FromPublicKeyParameters(publicKeyParameters), publicKeyParamSet,
                digestParamSet, encryptionParamSet);
        }

        /// <summary>
        /// A digest parameter set appropriate to the curve: GOST R 34.11-94 for the 2001 (CryptoPro) parameter sets,
        /// GOST R 34.11-2012 of matching size for the 2012 (TC26) ones.
        /// </summary>
        private static DerObjectIdentifier DefaultDigestParamSet(DerObjectIdentifier publicKeyParamSet)
        {
            string name = ECGost3410NamedCurves.GetName(publicKeyParamSet);
            if (name.StartsWith("GostR3410-2001"))
                return CryptoProObjectIdentifiers.GostR3411x94CryptoProParamSet;

            var x9 = ECGost3410NamedCurves.GetByOid(publicKeyParamSet);
            return x9.Curve.FieldElementEncodingLength > 32
                ? RosstandartObjectIdentifiers.id_tc26_gost_3411_12_512
                : RosstandartObjectIdentifiers.id_tc26_gost_3411_12_256;
        }
    }
}
