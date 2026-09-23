using System;
using System.IO;

using Org.BouncyCastle.Asn1;
using Org.BouncyCastle.Asn1.Cryptlib;
using Org.BouncyCastle.Asn1.CryptoPro;
using Org.BouncyCastle.Asn1.EdEC;
using Org.BouncyCastle.Asn1.Gnu;
using Org.BouncyCastle.Asn1.Oiw;
using Org.BouncyCastle.Asn1.Pkcs;
using Org.BouncyCastle.Asn1.Sec;
using Org.BouncyCastle.Asn1.X509;
using Org.BouncyCastle.Asn1.X9;
using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Crypto.Kems.MLKem;
using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.Crypto.Utilities;
using Org.BouncyCastle.Math;
using Org.BouncyCastle.Pkcs;
using Org.BouncyCastle.Utilities;

namespace Org.BouncyCastle.Security
{
    public static class PrivateKeyFactory
    {
        public static AsymmetricKeyParameter CreateKey(byte[] privateKeyInfoData) =>
            CreateKey(PrivateKeyInfo.GetInstance(privateKeyInfoData));

        public static AsymmetricKeyParameter CreateKey(Stream inStr) =>
            CreateKey(PrivateKeyInfo.GetInstance(Asn1Object.FromStream(inStr)));

        public static AsymmetricKeyParameter CreateKey(PrivateKeyInfo keyInfo)
        {
            AlgorithmIdentifier algID = keyInfo.PrivateKeyAlgorithm;
            DerObjectIdentifier algOid = algID.Algorithm;

            // TODO See RSAUtil.isRsaOid in Java build
            if (algOid.Equals(PkcsObjectIdentifiers.RsaEncryption)
                || algOid.Equals(X509ObjectIdentifiers.IdEARsa)
                || algOid.Equals(PkcsObjectIdentifiers.IdRsassaPss)
                || algOid.Equals(PkcsObjectIdentifiers.IdRsaesOaep))
            {
                RsaPrivateKeyStructure keyStructure = RsaPrivateKeyStructure.GetInstance(keyInfo.ParsePrivateKey());

                return new RsaPrivateCrtKeyParameters(
                    keyStructure.Modulus,
                    keyStructure.PublicExponent,
                    keyStructure.PrivateExponent,
                    keyStructure.Prime1,
                    keyStructure.Prime2,
                    keyStructure.Exponent1,
                    keyStructure.Exponent2,
                    keyStructure.Coefficient);
            }
            // TODO?
            //else if (algOid.Equals(X9ObjectIdentifiers.DHPublicNumber))
            else if (algOid.Equals(PkcsObjectIdentifiers.DhKeyAgreement))
            {
                DHParameter para = DHParameter.GetInstance(algID.Parameters);
                DerInteger derX = (DerInteger)keyInfo.ParsePrivateKey();

                BigInteger lVal = para.L;
                int l = lVal == null ? 0 : lVal.IntValue;
                DHParameters dhParams = new DHParameters(para.P, para.G, null, l);

                return new DHPrivateKeyParameters(derX.Value, dhParams, algOid);
            }
            else if (algOid.Equals(OiwObjectIdentifiers.ElGamalAlgorithm))
            {
                ElGamalParameter para = ElGamalParameter.GetInstance(algID.Parameters);
                DerInteger derX = (DerInteger)keyInfo.ParsePrivateKey();

                return new ElGamalPrivateKeyParameters(
                    derX.Value,
                    new ElGamalParameters(para.P, para.G));
            }
            else if (algOid.Equals(X9ObjectIdentifiers.IdDsa))
            {
                DerInteger derX = (DerInteger)keyInfo.ParsePrivateKey();
                Asn1Encodable ae = algID.Parameters;

                DsaParameters parameters = null;
                if (ae != null)
                {
                    DsaParameter para = DsaParameter.GetInstance(ae.ToAsn1Object());
                    parameters = new DsaParameters(para.P, para.Q, para.G);
                }

                return new DsaPrivateKeyParameters(derX.Value, parameters);
            }
            /*
             * TODO id-ecDH (SecObjectIdentifiers.ecdh) and/or id-ecMQV (SecObjectIdentifiers.ecmqv) could be supported
             * if we could properly restrict usage of the resulting key.
             */
            else if (algOid.Equals(X9ObjectIdentifiers.IdECPublicKey))
            {
                /*
                 * TODO Consistency checks in case parameters and/or public key are specified at both the
                 * PrivateKeyInfo and ECPrivateKey levels?
                 */
                ECPrivateKeyStructure ecPrivateKey = ECPrivateKeyStructure.GetInstance(keyInfo.ParsePrivateKey());
                X962Parameters parameters = X962Parameters.GetInstance(algID.Parameters);
                ECDomainParameters domainParameters = ECDomainParameters.FromX962Parameters(parameters);
                return new ECPrivateKeyParameters("EC", ecPrivateKey.GetKey(), domainParameters);
            }
            else if (ECGost3410Utilities.IsKeyAlgorithmOid(algOid))
            {
                var ecGost3410Parameters = ECGost3410Utilities.CreateECGost3410Parameters(algID);

                BigInteger d;

                /*
                 * TODO[ecgost3410] The raw and ASN.1 forms are ambiguous:
                 * 1. If we check for raw first, then we might mistake a short ASN.1 encoding for raw.
                 * 2. If we check for ASN.1 first, we might accidentally parse a raw key successfully.
                 */
                int fieldSize = ECGost3410Utilities.GetFieldElementEncodingLength(ecGost3410Parameters);
                if ((fieldSize == 32 || fieldSize == 64) && keyInfo.PrivateKeyLength == fieldSize)
                {
                    d = new BigInteger(1, keyInfo.PrivateKey.GetOctets(), bigEndian: false);
                }
                else
                {
                    Asn1Object privateKey = keyInfo.ParsePrivateKey();

                    if (DerInteger.GetOptional(privateKey) is DerInteger integer)
                    {
                        d = integer.PositiveValue;
                    }
                    else if (Asn1OctetString.GetOptional(privateKey) is Asn1OctetString octetString)
                    {
                        d = new BigInteger(1, octetString.GetOctets(), bigEndian: false);
                    }
                    else
                    {
                        d = ECPrivateKeyStructure.GetInstance(privateKey).GetKey();
                    }
                }

                return new ECPrivateKeyParameters("ECGOST3410", d, ecGost3410Parameters);
            }
            else if (algOid.Equals(CryptoProObjectIdentifiers.GostR3410x94))
            {
                Gost3410PublicKeyAlgParameters gostParams = Gost3410PublicKeyAlgParameters.GetInstance(algID.Parameters);

                Asn1Object privKey = keyInfo.ParsePrivateKey();
                BigInteger x;

                if (privKey is DerInteger)
                {
                    x = DerInteger.GetInstance(privKey).PositiveValue;
                }
                else
                {
                    x = new BigInteger(1, Asn1OctetString.GetInstance(privKey).GetOctets(), bigEndian: false);
                }

                return new Gost3410PrivateKeyParameters(x, gostParams.PublicKeyParamSet);
            }
            else if (algOid.Equals(EdECObjectIdentifiers.id_X25519)
                || algOid.Equals(CryptlibObjectIdentifiers.curvey25519))
            {
                // Java 11 bug: exact length of X25519/X448 secret used in Java 11
                if (X25519PrivateKeyParameters.KeySize == keyInfo.PrivateKeyLength)
                    return new X25519PrivateKeyParameters(keyInfo.PrivateKey.GetOctets());

                return new X25519PrivateKeyParameters(GetRawKey(keyInfo));
            }
            else if (algOid.Equals(EdECObjectIdentifiers.id_X448))
            {
                // Java 11 bug: exact length of X25519/X448 secret used in Java 11
                if (X448PrivateKeyParameters.KeySize == keyInfo.PrivateKeyLength)
                    return new X448PrivateKeyParameters(keyInfo.PrivateKey.GetOctets());

                return new X448PrivateKeyParameters(GetRawKey(keyInfo));
            }
            else if (algOid.Equals(EdECObjectIdentifiers.id_Ed25519)
                || algOid.Equals(GnuObjectIdentifiers.Ed25519))
            {
                return new Ed25519PrivateKeyParameters(GetRawKey(keyInfo));
            }
            else if (algOid.Equals(EdECObjectIdentifiers.id_Ed448))
            {
                return new Ed448PrivateKeyParameters(GetRawKey(keyInfo));
            }
            else if (MLDsaParameters.ByOid.TryGetValue(algOid, out MLDsaParameters mlDsaParameters))
            {
                // NOTE: We ignore the publicKey field since the private key already includes the public key
                // TODO[pqc] Validate the public key if it is included?

                var privateKey = keyInfo.PrivateKey;
                int length = privateKey.GetOctetsLength();

                // TODO[api] Eventually remove legacy support for raw octets
                {
                    var parameterSet = mlDsaParameters.ParameterSet;

                    if (length == parameterSet.SeedLength)
                        return MLDsaPrivateKeyParameters.FromSeed(mlDsaParameters, seed: privateKey.GetOctets());

                    if (length == parameterSet.PrivateKeyLength)
                        return MLDsaPrivateKeyParameters.FromEncoding(mlDsaParameters, encoding: privateKey.GetOctets());
                }

                try
                {
                    var asn1Object = Asn1Object.FromByteArray(privateKey.GetOctets());

                    if (asn1Object is Asn1TaggedObject taggedSeedOnly)
                    {
                        // SeedOnly is a [CONTEXT 0] IMPLICIT OCTET STRING
                        if (taggedSeedOnly.HasContextTag(0))
                        {
                            var seed = Asn1OctetString.GetTagged(taggedSeedOnly, declaredExplicit: false).GetOctets();
                            return MLDsaPrivateKeyParameters.FromSeed(mlDsaParameters, seed);
                        }
                    }
                    else if (asn1Object is Asn1OctetString encodingOnly)
                    {
                        // EncodingOnly is an OCTET STRING
                        var encoding = encodingOnly.GetOctets();
                        return MLDsaPrivateKeyParameters.FromEncoding(mlDsaParameters, encoding);
                    }
                    else if (asn1Object is Asn1Sequence sequence)
                    {
                        // SeedAndEncoding is a SEQUENCE containing a seed OCTET STRING and an encoding OCTET STRING
                        if (sequence.Count == 2)
                        {
                            var seed = Asn1OctetString.GetInstance(sequence[0]).GetOctets();
                            var encoding = Asn1OctetString.GetInstance(sequence[1]).GetOctets();

                            var fromSeed = MLDsaPrivateKeyParameters.FromSeed(mlDsaParameters, seed,
                                preferredFormat: MLDsaPrivateKeyParameters.Format.SeedAndEncoding);

                            /*
                             * RFC 9881 8.2. When receiving a private key that contains both the seed and the
                             * expandedKey, the recipient SHOULD perform a seed consistency check to ensure that the
                             * sender properly generated the private key. [..] If the check is done and the seed and the
                             * expandedKey are not consistent, the recipient MUST reject the private key as malformed.
                             */
                            if (!Arrays.FixedTimeEquals(fromSeed.GetEncoded(), encoding))
                                throw new ArgumentException("inconsistent " + mlDsaParameters.Name + " private key");

                            return fromSeed;
                        }
                    }
                }
                catch (Exception)
                {
                    // Ignore
                }

                throw new ArgumentException("invalid " + mlDsaParameters.Name + " private key");
            }
            else if (MLKemParameters.ByOid.TryGetValue(algOid, out MLKemParameters mlKemParameters))
            {
                // NOTE: We ignore the publicKey field since the private key already includes the public key
                // TODO[pqc] Validate the public key if it is included?

                var privateKey = keyInfo.PrivateKey;
                int length = privateKey.GetOctetsLength();

                // TODO[api] Eventually remove legacy support for raw octets
                {
                    if (length == MLKemEngine.SeedBytes)
                        return MLKemPrivateKeyParameters.FromSeed(mlKemParameters, seed: privateKey.GetOctets());

                    if (length == mlKemParameters.ParameterSet.Engine.SecretKeyBytes)
                        return MLKemPrivateKeyParameters.FromEncoding(mlKemParameters, encoding: privateKey.GetOctets());
                }

                try
                {
                    var asn1Object = Asn1Object.FromByteArray(privateKey.GetOctets());

                    if (asn1Object is Asn1TaggedObject taggedSeedOnly)
                    {
                        // SeedOnly is a [CONTEXT 0] IMPLICIT OCTET STRING
                        if (taggedSeedOnly.HasContextTag(0))
                        {
                            var seed = Asn1OctetString.GetTagged(taggedSeedOnly, declaredExplicit: false).GetOctets();
                            return MLKemPrivateKeyParameters.FromSeed(mlKemParameters, seed);
                        }
                    }
                    else if (asn1Object is Asn1OctetString encodingOnly)
                    {
                        // EncodingOnly is an OCTET STRING
                        var encoding = encodingOnly.GetOctets();
                        return MLKemPrivateKeyParameters.FromEncoding(mlKemParameters, encoding);
                    }
                    else if (asn1Object is Asn1Sequence sequence)
                    {
                        // SeedAndEncoding is a SEQUENCE containing a seed OCTET STRING and an encoding OCTET STRING
                        if (sequence.Count == 2)
                        {
                            var seed = Asn1OctetString.GetInstance(sequence[0]).GetOctets();
                            var encoding = Asn1OctetString.GetInstance(sequence[1]).GetOctets();

                            var fromSeed = MLKemPrivateKeyParameters.FromSeed(mlKemParameters, seed,
                                preferredFormat: MLKemPrivateKeyParameters.Format.SeedAndEncoding);

                            if (!Arrays.FixedTimeEquals(fromSeed.GetEncoded(), encoding))
                                throw new ArgumentException("inconsistent " + mlKemParameters.Name + " private key");

                            return fromSeed;
                        }
                    }
                }
                catch (Exception)
                {
                    // Ignore
                }

                throw new ArgumentException("invalid " + mlKemParameters.Name + " private key");
            }
            else if (SlhDsaParameters.ByOid.TryGetValue(algOid, out SlhDsaParameters slhDsaParameters))
            {
                // NOTE: We ignore the publicKey field since the private key already includes the public key
                // TODO[pqc] Validate the public key if it is included?

                int privateKeyLength = slhDsaParameters.ParameterSet.PrivateKeyLength;

                var privateKey = keyInfo.PrivateKey;
                int octetsLength = privateKey.GetOctetsLength();

                if (octetsLength == privateKeyLength)
                    return SlhDsaPrivateKeyParameters.FromEncoding(slhDsaParameters, encoding: privateKey.GetOctets());

                // TODO[api] Eventually remove legacy support for OCTET STRING encoding
                if (octetsLength > privateKeyLength)
                {
                    try
                    {
                        var asn1Object = Asn1Object.FromByteArray(privateKey.GetOctets());

                        if (asn1Object is Asn1OctetString octetString)
                        {
                            var encoding = octetString.GetOctets();
                            return MLKemPrivateKeyParameters.FromEncoding(mlKemParameters, encoding);
                        }
                    }
                    catch (Exception)
                    {
                        // Ignore
                    }
                }

                throw new ArgumentException("invalid " + slhDsaParameters.Name + " private key");
            }
            else
            {
                throw new SecurityUtilityException("algorithm identifier in private key not recognised");
            }
        }

#if NETCOREAPP2_1_OR_GREATER || NETSTANDARD2_1_OR_GREATER
        private static ReadOnlySpan<byte> GetRawKey(PrivateKeyInfo keyInfo)
        {
            return Asn1OctetString.GetInstance(keyInfo.ParsePrivateKey()).GetOctetsSpan();
        }
#else
        private static byte[] GetRawKey(PrivateKeyInfo keyInfo)
        {
            return Asn1OctetString.GetInstance(keyInfo.ParsePrivateKey()).GetOctets();
        }
#endif

        public static AsymmetricKeyParameter DecryptKey(char[] passPhrase, EncryptedPrivateKeyInfo encInfo) =>
            CreateKey(PrivateKeyInfoFactory.CreatePrivateKeyInfo(passPhrase, encInfo));

        public static AsymmetricKeyParameter DecryptKey(char[] passPhrase, byte[] encryptedPrivateKeyInfoData) =>
            DecryptKey(passPhrase, EncryptedPrivateKeyInfo.GetInstance(encryptedPrivateKeyInfoData));

        public static AsymmetricKeyParameter DecryptKey(char[] passPhrase, Stream encryptedPrivateKeyInfoStream)
        {
            return DecryptKey(passPhrase,
                EncryptedPrivateKeyInfo.GetInstance(Asn1Object.FromStream(encryptedPrivateKeyInfoStream)));
        }

        public static byte[] EncryptKey(
            DerObjectIdentifier algorithm,
            char[] passPhrase,
            byte[] salt,
            int iterationCount,
            AsymmetricKeyParameter key)
        {
            return EncryptedPrivateKeyInfoFactory.CreateEncryptedPrivateKeyInfo(
                algorithm, passPhrase, salt, iterationCount, key).GetEncoded();
        }

        public static byte[] EncryptKey(
            string algorithm,
            char[] passPhrase,
            byte[] salt,
            int iterationCount,
            AsymmetricKeyParameter key)
        {
            return EncryptedPrivateKeyInfoFactory.CreateEncryptedPrivateKeyInfo(
                algorithm, passPhrase, salt, iterationCount, key).GetEncoded();
        }
    }
}
