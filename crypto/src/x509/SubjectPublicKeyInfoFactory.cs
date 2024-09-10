using System;

using Org.BouncyCastle.Asn1;
using Org.BouncyCastle.Asn1.CryptoPro;
using Org.BouncyCastle.Asn1.EdEC;
using Org.BouncyCastle.Asn1.Oiw;
using Org.BouncyCastle.Asn1.Pkcs;
using Org.BouncyCastle.Asn1.Rosstandart;
using Org.BouncyCastle.Asn1.X509;
using Org.BouncyCastle.Asn1.X9;
using Org.BouncyCastle.crypto.parameters;
using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.Crypto.Utilities;
using Org.BouncyCastle.Math;
using Org.BouncyCastle.Math.EC;
using Org.BouncyCastle.Pqc.Crypto.Crystals.Dilithium;
using Org.BouncyCastle.Pqc.Crypto.Crystals.Kyber;
using Org.BouncyCastle.Pqc.Crypto.SphincsPlus;
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
        public static SubjectPublicKeyInfo CreateSubjectPublicKeyInfo(
            AsymmetricKeyParameter publicKey)
        {
            if (publicKey == null)
                throw new ArgumentNullException("publicKey");
            if (publicKey.IsPrivate)
                throw new ArgumentException("Private key passed - public key expected.", "publicKey");

            if (publicKey is ElGamalPublicKeyParameters)
            {
                ElGamalPublicKeyParameters _key = (ElGamalPublicKeyParameters)publicKey;
                ElGamalParameters kp = _key.Parameters;

                SubjectPublicKeyInfo info = new SubjectPublicKeyInfo(
                    new AlgorithmIdentifier(
                        OiwObjectIdentifiers.ElGamalAlgorithm,
                        new ElGamalParameter(kp.P, kp.G).ToAsn1Object()),
                        new DerInteger(_key.Y));

                return info;
            }

            if (publicKey is DsaPublicKeyParameters)
            {
                DsaPublicKeyParameters _key = (DsaPublicKeyParameters) publicKey;
                DsaParameters kp = _key.Parameters;
                Asn1Encodable ae = kp == null
                    ?	null
                    :	new DsaParameter(kp.P, kp.Q, kp.G).ToAsn1Object();

                return new SubjectPublicKeyInfo(
                    new AlgorithmIdentifier(X9ObjectIdentifiers.IdDsa, ae),
                    new DerInteger(_key.Y));
            }

            if (publicKey is DHPublicKeyParameters)
            {
                DHPublicKeyParameters _key = (DHPublicKeyParameters) publicKey;
                DHParameters kp = _key.Parameters;

                SubjectPublicKeyInfo info = new SubjectPublicKeyInfo(
                    new AlgorithmIdentifier(
                        _key.AlgorithmOid,
                        new DHParameter(kp.P, kp.G, kp.L).ToAsn1Object()),
                        new DerInteger(_key.Y));

                return info;
            } // End of DH

            if (publicKey is RsaKeyParameters)
            {
                RsaKeyParameters _key = (RsaKeyParameters) publicKey;

                SubjectPublicKeyInfo info = new SubjectPublicKeyInfo(
                    new AlgorithmIdentifier(PkcsObjectIdentifiers.RsaEncryption, DerNull.Instance),
                    new RsaPublicKeyStructure(_key.Modulus, _key.Exponent).ToAsn1Object());

                return info;
            } // End of RSA.

            if (publicKey is ECPublicKeyParameters)
            {            
               
                ECPublicKeyParameters _key = (ECPublicKeyParameters) publicKey;


                if (_key.Parameters is ECGost3410Parameters)
                {
                    ECGost3410Parameters gostParams = (ECGost3410Parameters)_key.Parameters;

                    BigInteger bX = _key.Q.AffineXCoord.ToBigInteger();
                    BigInteger bY = _key.Q.AffineYCoord.ToBigInteger();
                    bool is512 = (bX.BitLength > 256);

                    Gost3410PublicKeyAlgParameters parameters = new Gost3410PublicKeyAlgParameters(
                        gostParams.PublicKeyParamSet,
                        gostParams.DigestParamSet,
                        gostParams.EncryptionParamSet);

                    int encKeySize;
                    int offset;
                    DerObjectIdentifier algIdentifier;
                    if (is512)
                    {
                        encKeySize = 128;
                        offset = 64;
                        algIdentifier = RosstandartObjectIdentifiers.id_tc26_gost_3410_12_512;
                    }
                    else
                    {
                        encKeySize = 64;
                        offset = 32;
                        algIdentifier = RosstandartObjectIdentifiers.id_tc26_gost_3410_12_256;
                    }

                    byte[] encKey = new byte[encKeySize];
               
                    ExtractBytes(encKey, encKeySize / 2, 0, bX);
                    ExtractBytes(encKey, encKeySize / 2, offset, bY);
                  
                    return new SubjectPublicKeyInfo(new AlgorithmIdentifier(algIdentifier, parameters), new DerOctetString(encKey));
                   

                } // End of ECGOST3410_2012





                if (_key.AlgorithmName == "ECGOST3410")
                {
                    if (_key.PublicKeyParamSet == null)
                        throw new NotImplementedException("Not a CryptoPro parameter set");

                    ECPoint q = _key.Q.Normalize();
                    BigInteger bX = q.AffineXCoord.ToBigInteger();
                    BigInteger bY = q.AffineYCoord.ToBigInteger();

                    byte[] encKey = new byte[64];
                    ExtractBytes(encKey, 0, bX);
                    ExtractBytes(encKey, 32, bY);

                    Gost3410PublicKeyAlgParameters gostParams = new Gost3410PublicKeyAlgParameters(
                        _key.PublicKeyParamSet, CryptoProObjectIdentifiers.GostR3411x94CryptoProParamSet);

                    AlgorithmIdentifier algID = new AlgorithmIdentifier(
                        CryptoProObjectIdentifiers.GostR3410x2001,
                        gostParams.ToAsn1Object());

                    return new SubjectPublicKeyInfo(algID, new DerOctetString(encKey));
                }
                else
                {
                    X962Parameters x962;
                    if (_key.PublicKeyParamSet == null)
                    {
                        ECDomainParameters kp = _key.Parameters;
                        X9ECParameters ecP = new X9ECParameters(kp.Curve, new X9ECPoint(kp.G, false), kp.N, kp.H,
                            kp.GetSeed());

                        x962 = new X962Parameters(ecP);
                    }
                    else
                    {
                        x962 = new X962Parameters(_key.PublicKeyParamSet);
                    }

                    var q = _key.Q;

#if NETCOREAPP2_1_OR_GREATER || NETSTANDARD2_1_OR_GREATER
                    int encodedLength = q.GetEncodedLength(false);
                    Span<byte> pubKey = encodedLength <= 512
                        ? stackalloc byte[encodedLength]
                        : new byte[encodedLength];
                    q.EncodeTo(false, pubKey);
#else
                    byte[] pubKey = q.GetEncoded(false);
#endif

                    AlgorithmIdentifier algID = new AlgorithmIdentifier(
                        X9ObjectIdentifiers.IdECPublicKey, x962.ToAsn1Object());

                    return new SubjectPublicKeyInfo(algID, pubKey);
                }
            } // End of EC

            if (publicKey is Gost3410PublicKeyParameters)
            {
                Gost3410PublicKeyParameters _key = (Gost3410PublicKeyParameters) publicKey;

                if (_key.PublicKeyParamSet == null)
                    throw new NotImplementedException("Not a CryptoPro parameter set");

                // must be little endian
                byte[] keyEnc = Arrays.ReverseInPlace(_key.Y.ToByteArrayUnsigned());

                Gost3410PublicKeyAlgParameters algParams = new Gost3410PublicKeyAlgParameters(
                    _key.PublicKeyParamSet, CryptoProObjectIdentifiers.GostR3411x94CryptoProParamSet);

                AlgorithmIdentifier algID = new AlgorithmIdentifier(
                    CryptoProObjectIdentifiers.GostR3410x94,
                    algParams.ToAsn1Object());

                return new SubjectPublicKeyInfo(algID, new DerOctetString(keyEnc));
            }

            if (publicKey is X448PublicKeyParameters)
            {
                X448PublicKeyParameters key = (X448PublicKeyParameters)publicKey;

#if NETCOREAPP2_1_OR_GREATER || NETSTANDARD2_1_OR_GREATER
                return new SubjectPublicKeyInfo(new AlgorithmIdentifier(EdECObjectIdentifiers.id_X448), key.DataSpan);
#else
                return new SubjectPublicKeyInfo(new AlgorithmIdentifier(EdECObjectIdentifiers.id_X448), key.GetEncoded());
#endif
            }

            if (publicKey is X25519PublicKeyParameters)
            {
                X25519PublicKeyParameters key = (X25519PublicKeyParameters)publicKey;

#if NETCOREAPP2_1_OR_GREATER || NETSTANDARD2_1_OR_GREATER
                return new SubjectPublicKeyInfo(new AlgorithmIdentifier(EdECObjectIdentifiers.id_X25519), key.DataSpan);
#else
                return new SubjectPublicKeyInfo(new AlgorithmIdentifier(EdECObjectIdentifiers.id_X25519), key.GetEncoded());
#endif
            }

            if (publicKey is Ed448PublicKeyParameters)
            {
                Ed448PublicKeyParameters key = (Ed448PublicKeyParameters)publicKey;

                return new SubjectPublicKeyInfo(new AlgorithmIdentifier(EdECObjectIdentifiers.id_Ed448), key.GetEncoded());
            }

            if (publicKey is Ed25519PublicKeyParameters)
            {
                Ed25519PublicKeyParameters key = (Ed25519PublicKeyParameters)publicKey;

                return new SubjectPublicKeyInfo(new AlgorithmIdentifier(EdECObjectIdentifiers.id_Ed25519), key.GetEncoded());
            }

            if (publicKey is HybridKeyParameters)
            {
                HybridKeyParameters key = (HybridKeyParameters)publicKey;
                var names = key.CanonicalName.Split(Convert.ToChar("_"));
                var classicalName = names[0];
                var postQuantumName = names[1];

                byte[] classicalBytes = null;
                switch (classicalName)
                {
                    case "p256":
                    case "p384":
                    case "p521":
                        classicalBytes = (key.Classical as ECPublicKeyParameters).Q.GetEncoded();
                        break;
                    case "x25519":
                        classicalBytes = (key.Classical as X25519PublicKeyParameters).GetEncoded();
                        break;
                    case "x448":
                        classicalBytes = (key.Classical as X448PublicKeyParameters).GetEncoded();
                        break;
                    case "ed25519":
                        classicalBytes = (key.Classical as Ed25519PublicKeyParameters).GetEncoded();
                        break;
                    case "ed448":
                        classicalBytes = (key.Classical as Ed448PublicKeyParameters).GetEncoded();
                        break;
                }

                if (classicalBytes == null)
                {
                    throw new Exception("Classical algorithm not supported");
                }

                byte[] postQuantumBytes = null;
                switch (postQuantumName)
                {
                    case "mlkem512":
                    case "mlkem768":
                    case "mlkem1024":
                        postQuantumBytes = (key.PostQuantum as KyberPublicKeyParameters).GetEncoded();
                        break;
                    case "mldsa44":
                    case "mldsa65":
                    case "mldsa87":
                        postQuantumBytes = (key.PostQuantum as DilithiumPublicKeyParameters).GetEncoded();
                        break;
                    case "slhdsasha2128f":
                    case "slhdsasha2192f":
                    case "slhdsasha2256f":
                    case "slhdsasha2128s":
                    case "slhdsasha2192s":
                    case "slhdsasha2256s":
                    case "slhdsashake128f":
                    case "slhdsashake192f":
                    case "slhdsashake256f":
                    case "slhdsashake128s":
                    case "slhdsashake192s":
                    case "slhdsashake256s":
                        postQuantumBytes = (key.PostQuantum as SphincsPlusPublicKeyParameters).GetEncoded();
                        break;
                }

                if (postQuantumBytes == null)
                {
                    throw new Exception("Post-quantum algorithm not supported");
                }

                byte[] combinedBytes = new byte[4 + classicalBytes.Length + postQuantumBytes.Length];
                Pack.UInt32_To_BE((uint)classicalBytes.Length, combinedBytes);
                Array.Copy(classicalBytes, 0, combinedBytes, 4, classicalBytes.Length);
                Array.Copy(postQuantumBytes, 0, combinedBytes, 4 + classicalBytes.Length, postQuantumBytes.Length);
                return new SubjectPublicKeyInfo(new AlgorithmIdentifier(key.AlgorithmOid), combinedBytes);
            }

            throw new ArgumentException("Class provided no convertible: " + Platform.GetTypeName(publicKey));
        }

        private static void ExtractBytes(
            byte[]		encKey,
            int			offset,
            BigInteger	bI)
        {
            byte[] val = bI.ToByteArray();
            int n = (bI.BitLength + 7) / 8;

            for (int i = 0; i < n; ++i)
            {
                encKey[offset + i] = val[val.Length - 1 - i];
            }
        }


        private static void ExtractBytes(byte[] encKey, int size, int offSet, BigInteger bI)
        {
            byte[] val = bI.ToByteArray();
            if (val.Length < size)
            {
                byte[] tmp = new byte[size];
                Array.Copy(val, 0, tmp, tmp.Length - val.Length, val.Length);
                val = tmp;
            }

            for (int i = 0; i != size; i++)
            {
                encKey[offSet + i] = val[val.Length - 1 - i];
            }
        }
    }
}
