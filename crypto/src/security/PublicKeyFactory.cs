using System;
using System.IO;

using Org.BouncyCastle.Asn1;
using Org.BouncyCastle.Asn1.Cryptlib;
using Org.BouncyCastle.Asn1.CryptoPro;
using Org.BouncyCastle.Asn1.EdEC;
using Org.BouncyCastle.Asn1.Gnu;
using Org.BouncyCastle.Asn1.Oiw;
using Org.BouncyCastle.Asn1.Pkcs;
using Org.BouncyCastle.Asn1.Rosstandart;
using Org.BouncyCastle.Asn1.X509;
using Org.BouncyCastle.Asn1.X9;
using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Crypto.Generators;
using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.Math;
using Org.BouncyCastle.Math.EC;
using Org.BouncyCastle.Pqc.Crypto.Crystals.Dilithium;
using Org.BouncyCastle.Utilities;

namespace Org.BouncyCastle.Security
{
    public static class PublicKeyFactory
    {
        public static AsymmetricKeyParameter CreateKey(
            byte[] keyInfoData)
        {
            return CreateKey(
                SubjectPublicKeyInfo.GetInstance(
                    Asn1Object.FromByteArray(keyInfoData)));
        }

        public static AsymmetricKeyParameter CreateKey(
            Stream inStr)
        {
            return CreateKey(
                SubjectPublicKeyInfo.GetInstance(
                    Asn1Object.FromStream(inStr)));
        }

        public static AsymmetricKeyParameter CreateKey(
            SubjectPublicKeyInfo keyInfo)
        {
            AlgorithmIdentifier algID = keyInfo.Algorithm;
            DerObjectIdentifier algOid = algID.Algorithm;

            // TODO See RSAUtil.isRsaOid in Java build
            if (algOid.Equals(PkcsObjectIdentifiers.RsaEncryption)
                || algOid.Equals(X509ObjectIdentifiers.IdEARsa)
                || algOid.Equals(PkcsObjectIdentifiers.IdRsassaPss)
                || algOid.Equals(PkcsObjectIdentifiers.IdRsaesOaep))
            {
                RsaPublicKeyStructure pubKey = RsaPublicKeyStructure.GetInstance(
                    keyInfo.ParsePublicKey());

                return new RsaKeyParameters(false, pubKey.Modulus, pubKey.PublicExponent);
            }
            else if (algOid.Equals(X9ObjectIdentifiers.DHPublicNumber))
            {
                Asn1Sequence seq = Asn1Sequence.GetInstance(algID.Parameters.ToAsn1Object());

                DHPublicKey dhPublicKey = DHPublicKey.GetInstance(keyInfo.ParsePublicKey());

                BigInteger y = dhPublicKey.Y.Value;

                if (IsPkcsDHParam(seq))
                    return ReadPkcsDHParam(algOid, y, seq);

                DHDomainParameters dhParams = DHDomainParameters.GetInstance(seq);

                BigInteger p = dhParams.P.Value;
                BigInteger g = dhParams.G.Value;
                BigInteger q = dhParams.Q.Value;

                BigInteger j = null;
                if (dhParams.J != null)
                {
                    j = dhParams.J.Value;
                }

                DHValidationParameters validation = null;
                DHValidationParms dhValidationParms = dhParams.ValidationParms;
                if (dhValidationParms != null)
                {
                    byte[] seed = dhValidationParms.Seed.GetBytes();
                    BigInteger pgenCounter = dhValidationParms.PgenCounter.Value;

                    // TODO Check pgenCounter size?

                    validation = new DHValidationParameters(seed, pgenCounter.IntValue);
                }

                return new DHPublicKeyParameters(y, new DHParameters(p, g, q, j, validation));
            }
            else if (algOid.Equals(PkcsObjectIdentifiers.DhKeyAgreement))
            {
                Asn1Sequence seq = Asn1Sequence.GetInstance(algID.Parameters.ToAsn1Object());

                DerInteger derY = (DerInteger)keyInfo.ParsePublicKey();

                return ReadPkcsDHParam(algOid, derY.Value, seq);
            }
            else if (algOid.Equals(OiwObjectIdentifiers.ElGamalAlgorithm))
            {
                ElGamalParameter para = ElGamalParameter.GetInstance(algID.Parameters);
                DerInteger derY = (DerInteger)keyInfo.ParsePublicKey();

                return new ElGamalPublicKeyParameters(
                    derY.Value,
                    new ElGamalParameters(para.P, para.G));
            }
            else if (algOid.Equals(X9ObjectIdentifiers.IdDsa)
                || algOid.Equals(OiwObjectIdentifiers.DsaWithSha1))
            {
                DerInteger derY = (DerInteger)keyInfo.ParsePublicKey();
                Asn1Encodable ae = algID.Parameters;

                DsaParameters parameters = null;
                if (ae != null)
                {
                    DsaParameter para = DsaParameter.GetInstance(ae.ToAsn1Object());
                    parameters = new DsaParameters(para.P, para.Q, para.G);
                }

                return new DsaPublicKeyParameters(derY.Value, parameters);
            }
            else if (algOid.Equals(X9ObjectIdentifiers.IdECPublicKey))
            {
                X962Parameters para = X962Parameters.GetInstance(algID.Parameters.ToAsn1Object());

                X9ECParameters x9;
                if (para.IsNamedCurve)
                {
                    x9 = ECKeyPairGenerator.FindECCurveByOid((DerObjectIdentifier)para.Parameters);
                }
                else
                {
                    x9 = X9ECParameters.GetInstance(para.Parameters);
                }

                Asn1OctetString key = new DerOctetString(keyInfo.PublicKey.GetBytes());
                X9ECPoint derQ = new X9ECPoint(x9.Curve, key);
                ECPoint q = derQ.Point;

                if (para.IsNamedCurve)
                {
                    return new ECPublicKeyParameters("EC", q, (DerObjectIdentifier)para.Parameters);
                }

                ECDomainParameters dParams = new ECDomainParameters(x9);
                return new ECPublicKeyParameters(q, dParams);
            }
            else if (algOid.Equals(CryptoProObjectIdentifiers.GostR3410x2001))
            {
                Gost3410PublicKeyAlgParameters gostParams = Gost3410PublicKeyAlgParameters.GetInstance(algID.Parameters);
                DerObjectIdentifier publicKeyParamSet = gostParams.PublicKeyParamSet;

                X9ECParameters ecP = ECGost3410NamedCurves.GetByOid(publicKeyParamSet);
                if (ecP == null)
                    return null;

                Asn1OctetString key;
                try
                {
                    key = (Asn1OctetString)keyInfo.ParsePublicKey();
                }
                catch (IOException e)
                {
                    throw new ArgumentException("error recovering GOST3410_2001 public key", e);
                }

                int fieldSize = 32;
                int keySize = 2 * fieldSize;

                byte[] keyEnc = key.GetOctets();
                if (keyEnc.Length != keySize)
                    throw new ArgumentException("invalid length for GOST3410_2001 public key");

                byte[] x9Encoding = new byte[1 + keySize];
                x9Encoding[0] = 0x04;
                for (int i = 1; i <= fieldSize; ++i)
                {
                    x9Encoding[i] = keyEnc[fieldSize - i];
                    x9Encoding[i + fieldSize] = keyEnc[keySize - i];
                }

                ECPoint q = ecP.Curve.DecodePoint(x9Encoding);

                return new ECPublicKeyParameters("ECGOST3410", q, publicKeyParamSet);
            }
            else if (algOid.Equals(CryptoProObjectIdentifiers.GostR3410x94))
            {
                Gost3410PublicKeyAlgParameters algParams = Gost3410PublicKeyAlgParameters.GetInstance(algID.Parameters);

                Asn1OctetString key;
                try
                {
                    key = (Asn1OctetString)keyInfo.ParsePublicKey();
                }
                catch (IOException e)
                {
                    throw new ArgumentException("error recovering GOST3410_94 public key", e);
                }

                byte[] keyBytes = key.GetOctets();

                BigInteger y = new BigInteger(1, keyBytes, bigEndian: false);

                return new Gost3410PublicKeyParameters(y, algParams.PublicKeyParamSet);
            }
            else if (algOid.Equals(EdECObjectIdentifiers.id_X25519)
                || algOid.Equals(CryptlibObjectIdentifiers.curvey25519))
            {
                return new X25519PublicKeyParameters(GetRawKey(keyInfo));
            }
            else if (algOid.Equals(EdECObjectIdentifiers.id_X448))
            {
                return new X448PublicKeyParameters(GetRawKey(keyInfo));
            }
            else if (algOid.Equals(EdECObjectIdentifiers.id_Ed25519)
                || algOid.Equals(GnuObjectIdentifiers.Ed25519))
            {
                return new Ed25519PublicKeyParameters(GetRawKey(keyInfo));
            }
            else if (algOid.Equals(EdECObjectIdentifiers.id_Ed448))
            {
                return new Ed448PublicKeyParameters(GetRawKey(keyInfo));
            }
            else if (algOid.Equals(RosstandartObjectIdentifiers.id_tc26_gost_3410_12_256)
                ||   algOid.Equals(RosstandartObjectIdentifiers.id_tc26_gost_3410_12_512)
                ||   algOid.Equals(RosstandartObjectIdentifiers.id_tc26_agreement_gost_3410_12_256)
                ||   algOid.Equals(RosstandartObjectIdentifiers.id_tc26_agreement_gost_3410_12_512))
            {
                Gost3410PublicKeyAlgParameters gostParams = Gost3410PublicKeyAlgParameters.GetInstance(algID.Parameters);
                DerObjectIdentifier publicKeyParamSet = gostParams.PublicKeyParamSet;

                ECGost3410Parameters ecDomainParameters =new ECGost3410Parameters(
                    new ECNamedDomainParameters(publicKeyParamSet, ECGost3410NamedCurves.GetByOid(publicKeyParamSet)),
                    publicKeyParamSet,
                    gostParams.DigestParamSet,
                    gostParams.EncryptionParamSet);

                Asn1OctetString key;
                try
                {
                    key = (Asn1OctetString)keyInfo.ParsePublicKey();
                }
                catch (IOException e)
                {
                    throw new ArgumentException("error recovering GOST3410_2012 public key", e);
                }

                int fieldSize = 32;
                if (algOid.Equals(RosstandartObjectIdentifiers.id_tc26_gost_3410_12_512))
                {
                    fieldSize = 64;
                }
                int keySize = 2 * fieldSize;

                byte[] keyEnc = key.GetOctets();
                if (keyEnc.Length != keySize)
                    throw new ArgumentException("invalid length for GOST3410_2012 public key");

                byte[] x9Encoding = new byte[1 + keySize];
                x9Encoding[0] = 0x04;
                for (int i = 1; i <= fieldSize; ++i)
                {
                    x9Encoding[i] = keyEnc[fieldSize - i];
                    x9Encoding[i + fieldSize] = keyEnc[keySize - i];
                }

                ECPoint q = ecDomainParameters.Curve.DecodePoint(x9Encoding);

                return new ECPublicKeyParameters(q, ecDomainParameters);
            }
            else if (MLDsaParameters.ByOid.TryGetValue(algOid, out MLDsaParameters mlDsaParameters))
            {
                return GetMLDsaPublicKey(mlDsaParameters, keyInfo.PublicKey);
            }
            else if (MLKemParameters.ByOid.TryGetValue(algOid, out MLKemParameters mlKemParameters))
            {
                return GetMLKemPublicKey(mlKemParameters, keyInfo.PublicKey);
            }
            else if (SlhDsaParameters.ByOid.TryGetValue(algOid, out SlhDsaParameters slhDsaParameters))
            {
                return GetSlhDsaPublicKey(slhDsaParameters, keyInfo.PublicKey);
            }
            else
            {
                throw new SecurityUtilityException("algorithm identifier in public key not recognised: " + algOid);
            }
        }

        internal static MLDsaPublicKeyParameters GetMLDsaPublicKey(MLDsaParameters mlDsaParameters, DerBitString publicKey)
        {
            if (publicKey.IsOctetAligned())
            {
                int publicKeyLength = mlDsaParameters.ParameterSet.PublicKeyLength;

                int bytesLength = publicKey.GetBytesLength();
                if (bytesLength == publicKeyLength)
                    // TODO[pqc] Avoid redundant copies?
                    return MLDsaPublicKeyParameters.FromEncoding(mlDsaParameters, encoding: publicKey.GetOctets());

                // TODO[pqc] Remove support for legacy/prototype formats?
                if (bytesLength > publicKeyLength)
                {
                    try
                    {
                        Asn1Object obj = Asn1Object.FromMemoryStream(publicKey.GetOctetMemoryStream());
                        if (obj is Asn1OctetString oct)
                        {
                            if (oct.GetOctetsLength() == publicKeyLength)
                                return MLDsaPublicKeyParameters.FromEncoding(mlDsaParameters, encoding: oct.GetOctets());
                        }
                    }
                    catch (Exception)
                    {
                    }
                }
            }

            throw new ArgumentException("invalid " + mlDsaParameters.Name + " public key");
        }

        internal static MLKemPublicKeyParameters GetMLKemPublicKey(MLKemParameters mlKemParameters,
            DerBitString publicKey)
        {
            if (publicKey.IsOctetAligned())
            {
                int publicKeyLength = mlKemParameters.ParameterSet.PublicKeyLength;

                int bytesLength = publicKey.GetBytesLength();
                if (bytesLength == publicKeyLength)
                    // TODO[pqc] Avoid redundant copies?
                    return MLKemPublicKeyParameters.FromEncoding(mlKemParameters, encoding: publicKey.GetOctets());
            }

            throw new ArgumentException("invalid " + mlKemParameters.Name + " public key");
        }

#if NETCOREAPP2_1_OR_GREATER || NETSTANDARD2_1_OR_GREATER
        private static ReadOnlySpan<byte> GetRawKey(SubjectPublicKeyInfo keyInfo)
        {
            /*
             * TODO[RFC 8422]
             * - Require keyInfo.Algorithm.Parameters == null?
             */
            return keyInfo.PublicKey.GetOctetsSpan();
        }
#else
        private static byte[] GetRawKey(SubjectPublicKeyInfo keyInfo)
        {
            /*
             * TODO[RFC 8422]
             * - Require keyInfo.Algorithm.Parameters == null?
             */
            return keyInfo.PublicKey.GetOctets();
        }
#endif

        internal static SlhDsaPublicKeyParameters GetSlhDsaPublicKey(SlhDsaParameters slhDsaParameters,
            DerBitString publicKey)
        {
            if (publicKey.IsOctetAligned())
            {
                int publicKeyLength = slhDsaParameters.ParameterSet.PublicKeyLength;

                int bytesLength = publicKey.GetBytesLength();
                if (bytesLength == publicKeyLength)
                    // TODO[pqc] Avoid redundant copies?
                    return SlhDsaPublicKeyParameters.FromEncoding(slhDsaParameters, encoding: publicKey.GetOctets());

                // TODO[pqc] Remove support for legacy/prototype formats?
                if (bytesLength > publicKeyLength)
                {
                    try
                    {
                        Asn1Object obj = Asn1Object.FromMemoryStream(publicKey.GetOctetMemoryStream());
                        if (obj is Asn1OctetString oct)
                        {
                            if (oct.GetOctetsLength() == 4 + publicKeyLength)
                            {
                                byte[] octets = oct.GetOctets();
                                byte[] encoding = Arrays.CopyOfRange(octets, 4, octets.Length);
                                return SlhDsaPublicKeyParameters.FromEncoding(slhDsaParameters, encoding);
                            }
                        }
                    }
                    catch (Exception)
                    {
                    }
                }
            }

            throw new ArgumentException("invalid " + slhDsaParameters.Name + " public key");
        }

        private static bool IsPkcsDHParam(Asn1Sequence seq)
        {
            if (seq.Count == 2)
                return true;

            if (seq.Count > 3)
                return false;

            DerInteger l = DerInteger.GetInstance(seq[2]);
            DerInteger p = DerInteger.GetInstance(seq[0]);

            return l.Value.CompareTo(BigInteger.ValueOf(p.Value.BitLength)) <= 0;
        }

        private static DHPublicKeyParameters ReadPkcsDHParam(DerObjectIdentifier algOid,
            BigInteger y, Asn1Sequence seq)
        {
            DHParameter para = DHParameter.GetInstance(seq);

            BigInteger lVal = para.L;
            int l = lVal == null ? 0 : lVal.IntValue;
            DHParameters dhParams = new DHParameters(para.P, para.G, null, l);

            return new DHPublicKeyParameters(y, dhParams, algOid);
        }
    }
}
