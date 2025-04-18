using System;

using Org.BouncyCastle.Asn1;
using Org.BouncyCastle.Asn1.CryptoPro;
using Org.BouncyCastle.Asn1.EdEC;
using Org.BouncyCastle.Asn1.Oiw;
using Org.BouncyCastle.Asn1.Pkcs;
using Org.BouncyCastle.Asn1.Rosstandart;
using Org.BouncyCastle.Asn1.X509;
using Org.BouncyCastle.Asn1.X9;
using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.Math;
using Org.BouncyCastle.Math.EC;
using Org.BouncyCastle.Utilities;

namespace Org.BouncyCastle.X509
{
    /// <summary>
    /// A factory to produce Public Key Info Objects.
    /// </summary>
    public static class SubjectPublicKeyInfoFactory
    {
        /// <summary>
        /// Create a Subject Public Key Info object for a given public key.
        /// </summary>
        /// <param name="publicKey">One of ElGammalPublicKeyParameters, DSAPublicKeyParameter, DHPublicKeyParameters, RsaKeyParameters or ECPublicKeyParameters</param>
        /// <returns>A subject public key info object.</returns>
        /// <exception cref="Exception">Throw exception if object provided is not one of the above.</exception>
        public static SubjectPublicKeyInfo CreateSubjectPublicKeyInfo(AsymmetricKeyParameter publicKey)
        {
            if (publicKey == null)
                throw new ArgumentNullException(nameof(publicKey));
            if (publicKey.IsPrivate)
                throw new ArgumentException("Private key passed - public key expected.", nameof(publicKey));

            if (publicKey is ElGamalPublicKeyParameters elGamalKey)
            {
                ElGamalParameters kp = elGamalKey.Parameters;
                var algParams = new ElGamalParameter(kp.P, kp.G);
                var algID = new AlgorithmIdentifier(OiwObjectIdentifiers.ElGamalAlgorithm, algParams);
                return new SubjectPublicKeyInfo(algID, new DerInteger(elGamalKey.Y));
            }

            if (publicKey is DsaPublicKeyParameters dsaKey)
            {
                DsaParameters kp = dsaKey.Parameters;
                var algParams = new DsaParameter(kp.P, kp.Q, kp.G);
                var algID = new AlgorithmIdentifier(X9ObjectIdentifiers.IdDsa, algParams);
                return new SubjectPublicKeyInfo(algID, new DerInteger(dsaKey.Y));
            }

            if (publicKey is DHPublicKeyParameters dhKey)
            {
                DHParameters kp = dhKey.Parameters;
                var algParams = new DHParameter(kp.P, kp.G, kp.L);
                var algID = new AlgorithmIdentifier(dhKey.AlgorithmOid, algParams);
                return new SubjectPublicKeyInfo(algID, new DerInteger(dhKey.Y));
            }

            if (publicKey is RsaKeyParameters rsaKey)
            {
                var algID = new AlgorithmIdentifier(PkcsObjectIdentifiers.RsaEncryption, DerNull.Instance);
                return new SubjectPublicKeyInfo(algID, new RsaPublicKeyStructure(rsaKey.Modulus, rsaKey.Exponent));
            }

            if (publicKey is ECPublicKeyParameters ecKey)
            {
                var q = ecKey.Q;

                if (ecKey.Parameters is ECGost3410Parameters gostParams)
                {
                    int fieldSize = ecKey.Parameters.Curve.FieldElementEncodingLength;
                    var algOid = fieldSize > 32
                        ? RosstandartObjectIdentifiers.id_tc26_gost_3410_12_512
                        : RosstandartObjectIdentifiers.id_tc26_gost_3410_12_256;
                    var algParams = new Gost3410PublicKeyAlgParameters(gostParams.PublicKeyParamSet,
                        gostParams.DigestParamSet, gostParams.EncryptionParamSet);
                    var algID = new AlgorithmIdentifier(algOid, algParams);
                    return new SubjectPublicKeyInfo(algID, CreateECGost3410PublicKey(fieldSize, q));
                }

                if (ecKey.AlgorithmName == "ECGOST3410")
                {
                    if (ecKey.PublicKeyParamSet == null)
                        throw new NotImplementedException("Not a CryptoPro parameter set");

                    int fieldSize = ecKey.Parameters.Curve.FieldElementEncodingLength;
                    var algParams = new Gost3410PublicKeyAlgParameters(ecKey.PublicKeyParamSet,
                        CryptoProObjectIdentifiers.GostR3411x94CryptoProParamSet);
                    var algID = new AlgorithmIdentifier(CryptoProObjectIdentifiers.GostR3410x2001, algParams);
                    return new SubjectPublicKeyInfo(algID, CreateECGost3410PublicKey(fieldSize, q));
                }
                else
                {
                    var algParams = ECDomainParameters.ToX962Parameters(ecKey.Parameters);

#if NETCOREAPP2_1_OR_GREATER || NETSTANDARD2_1_OR_GREATER
                    int encodedLength = q.GetEncodedLength(false);
                    Span<byte> pubKey = encodedLength <= 512
                        ? stackalloc byte[encodedLength]
                        : new byte[encodedLength];
                    q.EncodeTo(false, pubKey);
#else
                    byte[] pubKey = q.GetEncoded(false);
#endif

                    var algID = new AlgorithmIdentifier(X9ObjectIdentifiers.IdECPublicKey, algParams);
                    return new SubjectPublicKeyInfo(algID, pubKey);
                }
            }

            if (publicKey is Gost3410PublicKeyParameters gost3410Key)
            {
                if (gost3410Key.PublicKeyParamSet == null)
                    throw new NotImplementedException("Not a CryptoPro parameter set");

                // must be little endian
                byte[] keyEnc = Arrays.ReverseInPlace(gost3410Key.Y.ToByteArrayUnsigned());

                var algParams = new Gost3410PublicKeyAlgParameters(gost3410Key.PublicKeyParamSet,
                    CryptoProObjectIdentifiers.GostR3411x94CryptoProParamSet);
                var algID = new AlgorithmIdentifier(CryptoProObjectIdentifiers.GostR3410x94, algParams);
                return new SubjectPublicKeyInfo(algID, new DerOctetString(keyEnc));
            }

            if (publicKey is X448PublicKeyParameters x448Key)
            {
                var algID = new AlgorithmIdentifier(EdECObjectIdentifiers.id_X448);
#if NETCOREAPP2_1_OR_GREATER || NETSTANDARD2_1_OR_GREATER
                return new SubjectPublicKeyInfo(algID, x448Key.DataSpan);
#else
                return new SubjectPublicKeyInfo(algID, x448Key.GetEncoded());
#endif
            }

            if (publicKey is X25519PublicKeyParameters x25519Key)
            {
                var algID = new AlgorithmIdentifier(EdECObjectIdentifiers.id_X25519);
#if NETCOREAPP2_1_OR_GREATER || NETSTANDARD2_1_OR_GREATER
                return new SubjectPublicKeyInfo(algID, x25519Key.DataSpan);
#else
                return new SubjectPublicKeyInfo(algID, x25519Key.GetEncoded());
#endif
            }

            if (publicKey is Ed448PublicKeyParameters ed448Key)
            {
                var algID = new AlgorithmIdentifier(EdECObjectIdentifiers.id_Ed448);
                return new SubjectPublicKeyInfo(algID, ed448Key.GetEncoded());
            }

            if (publicKey is Ed25519PublicKeyParameters ed25519Key)
            {
                var algID = new AlgorithmIdentifier(EdECObjectIdentifiers.id_Ed25519);
                return new SubjectPublicKeyInfo(algID, ed25519Key.GetEncoded());
            }

            if (publicKey is MLDsaPublicKeyParameters mlDsaKey)
            {
                var algID = new AlgorithmIdentifier(mlDsaKey.Parameters.Oid);

                // TODO[pqc] Avoid redundant copies?
                return new SubjectPublicKeyInfo(algID, publicKey: mlDsaKey.GetEncoded());
            }

            if (publicKey is MLKemPublicKeyParameters mlKemKey)
            {
                var algID = new AlgorithmIdentifier(mlKemKey.Parameters.Oid);

                // TODO[pqc] Avoid redundant copies?
                return new SubjectPublicKeyInfo(algID, publicKey: mlKemKey.GetEncoded());
            }

            if (publicKey is SlhDsaPublicKeyParameters slhDsaKey)
            {
                var algID = new AlgorithmIdentifier(slhDsaKey.Parameters.Oid);

                // TODO[pqc] Avoid redundant copies?
                return new SubjectPublicKeyInfo(algID, publicKey: slhDsaKey.GetEncoded());
            }

            throw new ArgumentException("Class provided no convertible: " + Platform.GetTypeName(publicKey));
        }

        private static Asn1OctetString CreateECGost3410PublicKey(int fieldSize, ECPoint q)
        {
            byte[] encoding = new byte[fieldSize * 2];
            EncodeECGost3410FieldElement(q.AffineXCoord.ToBigInteger(), encoding, 0, fieldSize);
            EncodeECGost3410FieldElement(q.AffineYCoord.ToBigInteger(), encoding, fieldSize, fieldSize);
            return DerOctetString.WithContents(encoding);
        }

        private static void EncodeECGost3410FieldElement(BigInteger bi, byte[] buf, int off, int len)
        {
            // TODO Add a little-endian option to do this in one go
            BigIntegers.AsUnsignedByteArray(bi, buf, off, len);
            Array.Reverse(buf, off, len);
        }
    }
}
