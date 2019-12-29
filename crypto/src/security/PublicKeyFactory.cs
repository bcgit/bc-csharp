using System;
using System.Collections;
using System.IO;
using System.Text;

using Org.BouncyCastle.Asn1;
using Org.BouncyCastle.Asn1.CryptoPro;
using Org.BouncyCastle.Asn1.EdEC;
using Org.BouncyCastle.Asn1.Oiw;
using Org.BouncyCastle.Asn1.Pkcs;
using Org.BouncyCastle.Asn1.Rosstandart;
using Org.BouncyCastle.Asn1.Sec;
using Org.BouncyCastle.Asn1.X509;
using Org.BouncyCastle.Asn1.X9;
using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Crypto.Generators;
using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.Math;
using Org.BouncyCastle.Math.EC;
using Org.BouncyCastle.Utilities;
using Org.BouncyCastle.Utilities.Encoders;

namespace Org.BouncyCastle.Security
{
    public sealed class PublicKeyFactory
    {
        private PublicKeyFactory()
        {
        }

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
            AlgorithmIdentifier algID = keyInfo.AlgorithmID;
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
                ElGamalParameter para = new ElGamalParameter(
                    Asn1Sequence.GetInstance(algID.Parameters.ToAsn1Object()));
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
                X962Parameters para = new X962Parameters(algID.Parameters.ToAsn1Object());

                X9ECParameters x9;
                if (para.IsNamedCurve)
                {
                    x9 = ECKeyPairGenerator.FindECCurveByOid((DerObjectIdentifier)para.Parameters);
                }
                else
                {
                    x9 = new X9ECParameters((Asn1Sequence)para.Parameters);
                }

                Asn1OctetString key = new DerOctetString(keyInfo.PublicKeyData.GetBytes());
                X9ECPoint derQ = new X9ECPoint(x9.Curve, key);
                ECPoint q = derQ.Point;

                if (para.IsNamedCurve)
                {
                    return new ECPublicKeyParameters("EC", q, (DerObjectIdentifier)para.Parameters);
                }

                ECDomainParameters dParams = new ECDomainParameters(x9.Curve, x9.G, x9.N, x9.H, x9.GetSeed());
                return new ECPublicKeyParameters(q, dParams);
            }
            else if (algOid.Equals(CryptoProObjectIdentifiers.GostR3410x2001))
            {
                Gost3410PublicKeyAlgParameters gostParams = Gost3410PublicKeyAlgParameters.GetInstance(algID.Parameters);
                DerObjectIdentifier publicKeyParamSet = gostParams.PublicKeyParamSet;

                ECDomainParameters ecP = ECGost3410NamedCurves.GetByOid(publicKeyParamSet);
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

                byte[] keyBytes = Arrays.Reverse(key.GetOctets()); // was little endian

                BigInteger y = new BigInteger(1, keyBytes);

                return new Gost3410PublicKeyParameters(y, algParams.PublicKeyParamSet);
            }
            else if (algOid.Equals(EdECObjectIdentifiers.id_X25519))
            {
                return new X25519PublicKeyParameters(GetRawKey(keyInfo, X25519PublicKeyParameters.KeySize), 0);
            }
            else if (algOid.Equals(EdECObjectIdentifiers.id_X448))
            {
                return new X448PublicKeyParameters(GetRawKey(keyInfo, X448PublicKeyParameters.KeySize), 0);
            }
            else if (algOid.Equals(EdECObjectIdentifiers.id_Ed25519))
            {
                return new Ed25519PublicKeyParameters(GetRawKey(keyInfo, Ed25519PublicKeyParameters.KeySize), 0);
            }
            else if (algOid.Equals(EdECObjectIdentifiers.id_Ed448))
            {
                return new Ed448PublicKeyParameters(GetRawKey(keyInfo, Ed448PublicKeyParameters.KeySize), 0);
            }
            else if (algOid.Equals(RosstandartObjectIdentifiers.id_tc26_gost_3410_12_256)
                ||   algOid.Equals(RosstandartObjectIdentifiers.id_tc26_gost_3410_12_512))
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
            else
            {
                throw new SecurityUtilityException("algorithm identifier in public key not recognised: " + algOid);
            }
        }

        private static byte[] GetRawKey(SubjectPublicKeyInfo keyInfo, int expectedSize)
        {
            /*
             * TODO[RFC 8422]
             * - Require keyInfo.Algorithm.Parameters == null?
             */
            byte[] result = keyInfo.PublicKeyData.GetOctets();
            if (expectedSize != result.Length)
                throw new SecurityUtilityException("public key encoding has incorrect length");

            return result;
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
            DHParameter para = new DHParameter(seq);

            BigInteger lVal = para.L;
            int l = lVal == null ? 0 : lVal.IntValue;
            DHParameters dhParams = new DHParameters(para.P, para.G, null, l);

            return new DHPublicKeyParameters(y, dhParams, algOid);
        }
    }
}
