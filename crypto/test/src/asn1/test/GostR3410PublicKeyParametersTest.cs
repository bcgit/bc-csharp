using System;

using NUnit.Framework;

using Org.BouncyCastle.Asn1.CryptoPro;
using Org.BouncyCastle.Asn1.Rosstandart;

namespace Org.BouncyCastle.Asn1.Tests
{
    /// <summary>
    /// Tests for the structure-specific GOST R 34.10 key parameter types:
    /// <see cref="GostR3410x2001PublicKeyParameters"/> (RFC 4491, with a DEFAULT encryptionParamSet) and
    /// <see cref="GostR3410x2012PublicKeyParameters"/> (RFC 9215, with an OPTIONAL digestParamSet and no
    /// encryptionParamSet).
    /// </summary>
    [TestFixture]
    public class GostR3410PublicKeyParametersTest
    {
        private static readonly DerObjectIdentifier CurveA = CryptoProObjectIdentifiers.GostR3410x2001CryptoProA;
        private static readonly DerObjectIdentifier Digest94 = CryptoProObjectIdentifiers.GostR3411x94CryptoProParamSet;
        private static readonly DerObjectIdentifier EncryptionA =
            CryptoProObjectIdentifiers.ID_Gost28147_89_CryptoPro_A_ParamSet;
        private static readonly DerObjectIdentifier EncryptionB =
            CryptoProObjectIdentifiers.ID_Gost28147_89_CryptoPro_B_ParamSet;

        private static readonly DerObjectIdentifier Curve256A =
            RosstandartObjectIdentifiers.id_tc26_gost_3410_12_256_paramSetA;
        private static readonly DerObjectIdentifier Digest2012_256 =
            RosstandartObjectIdentifiers.id_tc26_gost_3411_12_256;

        [Test]
        public void Gost2001DefaultValue()
        {
            Assert.That(GostR3410x2001PublicKeyParameters.DefaultEncryptionParamSet, Is.EqualTo(EncryptionA));
        }

        [Test]
        public void Gost2001DecodeAbsentEncryptionParamSet()
        {
            var seq = new DerSequence(CurveA, Digest94);
            var p = GostR3410x2001PublicKeyParameters.GetInstance(seq);

            Assert.That(p.PublicKeyParamSet, Is.EqualTo(CurveA));
            Assert.That(p.DigestParamSet, Is.EqualTo(Digest94));
            Assert.That(p.EncryptionParamSet, Is.EqualTo(EncryptionA), "absent means DEFAULT");
            Assert.That(p.ToAsn1Object(), Is.EqualTo(seq));
        }

        [Test]
        public void Gost2001DecodeExplicitDefaultIsAcceptedAndCanonicalized()
        {
            // Not DER-canonical, but seen in the wild (e.g. from encoders treating the field as OPTIONAL)
            var explicitDefault = new DerSequence(CurveA, Digest94, EncryptionA);
            var p = GostR3410x2001PublicKeyParameters.GetInstance(explicitDefault);

            Assert.That(p.EncryptionParamSet, Is.EqualTo(EncryptionA));
            Assert.That(p.ToAsn1Object(), Is.EqualTo(new DerSequence(CurveA, Digest94)), "DEFAULT must be omitted");
        }

        [Test]
        public void Gost2001DecodeNonDefaultEncryptionParamSet()
        {
            var seq = new DerSequence(CurveA, Digest94, EncryptionB);
            var p = GostR3410x2001PublicKeyParameters.GetInstance(seq);

            Assert.That(p.EncryptionParamSet, Is.EqualTo(EncryptionB));
            Assert.That(p.ToAsn1Object(), Is.EqualTo(seq));
        }

        [Test]
        public void Gost2001ConstructorsAgreeOnDefault()
        {
            var twoArg = new GostR3410x2001PublicKeyParameters(CurveA, Digest94);
            var nullEnc = new GostR3410x2001PublicKeyParameters(CurveA, Digest94, null);
            var explicitEnc = new GostR3410x2001PublicKeyParameters(CurveA, Digest94, EncryptionA);

            Assert.That(twoArg.EncryptionParamSet, Is.EqualTo(EncryptionA));
            Assert.That(nullEnc.EncryptionParamSet, Is.EqualTo(EncryptionA));
            Assert.That(explicitEnc.EncryptionParamSet, Is.EqualTo(EncryptionA));

            // Asn1Encodable equality compares encodings, so all three must be equal and two elements long
            Assert.That(nullEnc, Is.EqualTo(twoArg));
            Assert.That(explicitEnc, Is.EqualTo(twoArg));
            Assert.That(Asn1Sequence.GetInstance(twoArg.ToAsn1Object()).Count, Is.EqualTo(2));

            var nonDefault = new GostR3410x2001PublicKeyParameters(CurveA, Digest94, EncryptionB);
            Assert.That(nonDefault, Is.Not.EqualTo(twoArg));
            Assert.That(Asn1Sequence.GetInstance(nonDefault.ToAsn1Object()).Count, Is.EqualTo(3));
        }

        [Test]
        public void Gost2001RejectsBadShapes()
        {
            // digestParamSet is mandatory in the 2001 structure
            Assert.Throws<ArgumentException>(
                () => GostR3410x2001PublicKeyParameters.GetInstance(new DerSequence(CurveA)));
            Assert.Throws<ArgumentException>(
                () => GostR3410x2001PublicKeyParameters.GetInstance(
                    new DerSequence(CurveA, Digest94, EncryptionA, EncryptionA)));
            Assert.Throws<ArgumentException>(
                () => GostR3410x2001PublicKeyParameters.GetInstance(new DerSequence(CurveA, DerNull.Instance)));

            Assert.Throws<ArgumentNullException>(() => new GostR3410x2001PublicKeyParameters(null, Digest94));
            Assert.Throws<ArgumentNullException>(() => new GostR3410x2001PublicKeyParameters(CurveA, null));
        }

        [Test]
        public void Gost2001GetOptional()
        {
            Assert.That(GostR3410x2001PublicKeyParameters.GetOptional(new DerSequence(CurveA, Digest94)), Is.Not.Null);
            Assert.That(GostR3410x2001PublicKeyParameters.GetOptional(CurveA), Is.Null);
            Assert.That(GostR3410x2001PublicKeyParameters.GetInstance(null), Is.Null);
            Assert.Throws<ArgumentNullException>(() => GostR3410x2001PublicKeyParameters.GetOptional(null));
        }

        [Test]
        public void Gost2012DecodeOneElement()
        {
            var seq = new DerSequence(Curve256A);
            var p = GostR3410x2012PublicKeyParameters.GetInstance(seq);

            Assert.That(p.PublicKeyParamSet, Is.EqualTo(Curve256A));
            Assert.That(p.DigestParamSet, Is.Null);
            Assert.That(p.ToAsn1Object(), Is.EqualTo(seq));
        }

        [Test]
        public void Gost2012DecodeTwoElements()
        {
            var seq = new DerSequence(Curve256A, Digest2012_256);
            var p = GostR3410x2012PublicKeyParameters.GetInstance(seq);

            Assert.That(p.PublicKeyParamSet, Is.EqualTo(Curve256A));
            Assert.That(p.DigestParamSet, Is.EqualTo(Digest2012_256));
            Assert.That(p.ToAsn1Object(), Is.EqualTo(seq));
        }

        [Test]
        public void Gost2012Constructors()
        {
            var oneArg = new GostR3410x2012PublicKeyParameters(Curve256A);
            var nullDigest = new GostR3410x2012PublicKeyParameters(Curve256A, null);
            var withDigest = new GostR3410x2012PublicKeyParameters(Curve256A, Digest2012_256);

            Assert.That(oneArg.DigestParamSet, Is.Null);
            Assert.That(nullDigest, Is.EqualTo(oneArg));
            Assert.That(Asn1Sequence.GetInstance(oneArg.ToAsn1Object()).Count, Is.EqualTo(1));
            Assert.That(Asn1Sequence.GetInstance(withDigest.ToAsn1Object()).Count, Is.EqualTo(2));

            Assert.Throws<ArgumentNullException>(() => new GostR3410x2012PublicKeyParameters(null));
        }

        [Test]
        public void Gost2012RejectsBadShapes()
        {
            // No encryptionParamSet in the 2012 structure
            Assert.Throws<ArgumentException>(
                () => GostR3410x2012PublicKeyParameters.GetInstance(
                    new DerSequence(Curve256A, Digest2012_256, EncryptionA)));
            Assert.Throws<ArgumentException>(
                () => GostR3410x2012PublicKeyParameters.GetInstance(new DerSequence()));
            Assert.Throws<ArgumentException>(
                () => GostR3410x2012PublicKeyParameters.GetInstance(new DerSequence(Curve256A, DerNull.Instance)));
        }

        [Test]
        public void Gost2012GetOptional()
        {
            Assert.That(GostR3410x2012PublicKeyParameters.GetOptional(new DerSequence(Curve256A)), Is.Not.Null);
            Assert.That(GostR3410x2012PublicKeyParameters.GetOptional(Curve256A), Is.Null);
            Assert.That(GostR3410x2012PublicKeyParameters.GetInstance(null), Is.Null);
            Assert.Throws<ArgumentNullException>(() => GostR3410x2012PublicKeyParameters.GetOptional(null));
        }

        /// <summary>
        /// The same two-element encoding is a valid 2001 structure (DEFAULT encryptionParamSet) and a valid 2012
        /// structure (digestParamSet present). Only the key algorithm OID can tell them apart.
        /// </summary>
        [Test]
        public void TwoElementEncodingIsAmbiguousBetweenStructures()
        {
            var seq = new DerSequence(CurveA, Digest94);

            var p2001 = GostR3410x2001PublicKeyParameters.GetInstance(seq);
            var p2012 = GostR3410x2012PublicKeyParameters.GetInstance(seq);

            Assert.That(p2001.EncryptionParamSet, Is.EqualTo(EncryptionA));
            Assert.That(p2012.DigestParamSet, Is.EqualTo(Digest94));
            Assert.That(p2001.ToAsn1Object(), Is.EqualTo(p2012.ToAsn1Object()));
        }
    }
}
