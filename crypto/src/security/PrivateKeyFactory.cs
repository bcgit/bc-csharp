using System;
using System.IO;
using System.Linq;
using Org.BouncyCastle.Asn1;
using Org.BouncyCastle.Asn1.Cryptlib;
using Org.BouncyCastle.Asn1.CryptoPro;
using Org.BouncyCastle.Asn1.EdEC;
using Org.BouncyCastle.Asn1.Gnu;
using Org.BouncyCastle.Asn1.Nist;
using Org.BouncyCastle.Asn1.Oiw;
using Org.BouncyCastle.Asn1.Pkcs;
using Org.BouncyCastle.Asn1.Rosstandart;
using Org.BouncyCastle.Asn1.Sec;
using Org.BouncyCastle.Asn1.X509;
using Org.BouncyCastle.Asn1.X9;
using Org.BouncyCastle.crypto.parameters;
using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Crypto.Generators;
using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.Crypto.Utilities;
using Org.BouncyCastle.Math;
using Org.BouncyCastle.Pkcs;
using Org.BouncyCastle.Pqc.Crypto.Crystals.Dilithium;
using Org.BouncyCastle.Pqc.Crypto.MLKem;
using Org.BouncyCastle.Pqc.Crypto.SphincsPlus;
using Org.BouncyCastle.Pqc.Crypto.Utilities;

namespace Org.BouncyCastle.Security
{
    public static class PrivateKeyFactory
    {
        public static AsymmetricKeyParameter CreateKey(
            byte[] privateKeyInfoData)
        {
            return CreateKey(
                PrivateKeyInfo.GetInstance(
                    Asn1Object.FromByteArray(privateKeyInfoData)));
        }

        public static AsymmetricKeyParameter CreateKey(
            Stream inStr)
        {
            return CreateKey(
                PrivateKeyInfo.GetInstance(
                    Asn1Object.FromStream(inStr)));
        }

        public static AsymmetricKeyParameter CreateKey(
            PrivateKeyInfo keyInfo)
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
            //			else if (algOid.Equals(X9ObjectIdentifiers.DHPublicNumber))
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
            else if (algOid.Equals(X9ObjectIdentifiers.IdECPublicKey))
            {
                ECPrivateKeyStructure ecPrivateKey = ECPrivateKeyStructure.GetInstance(keyInfo.ParsePrivateKey());

                X962Parameters parameters = X962Parameters.GetInstance(algID.Parameters.ToAsn1Object());
                if (parameters.IsNamedCurve)
                {
                    return new ECPrivateKeyParameters(
                        algorithm: "EC",
                        d: ecPrivateKey.GetKey(),
                        publicKeyParamSet: DerObjectIdentifier.GetInstance(parameters.Parameters));
                }

                X9ECParameters x9 = X9ECParameters.GetInstance(parameters.Parameters);
                return new ECPrivateKeyParameters(
                    algorithm: "EC",
                    d: ecPrivateKey.GetKey(),
                    parameters: new ECDomainParameters(x9));
            }
            else if (algOid.Equals(CryptoProObjectIdentifiers.GostR3410x2001) ||
                     algOid.Equals(RosstandartObjectIdentifiers.id_tc26_gost_3410_12_512) ||
                     algOid.Equals(RosstandartObjectIdentifiers.id_tc26_gost_3410_12_256))
            {
                Asn1Object p = algID.Parameters.ToAsn1Object();
                Gost3410PublicKeyAlgParameters gostParams = Gost3410PublicKeyAlgParameters.GetInstance(p);

                ECGost3410Parameters ecSpec;
                BigInteger d;

                if (p is Asn1Sequence seq && (seq.Count == 2 || seq.Count == 3))
                {
                    X9ECParameters ecP = ECGost3410NamedCurves.GetByOid(gostParams.PublicKeyParamSet);
                    if (ecP == null)
                        throw new ArgumentException("Unrecognized curve OID for GostR3410x2001 private key");

                    ecSpec = new ECGost3410Parameters(
                        new ECNamedDomainParameters(gostParams.PublicKeyParamSet, ecP),
                        gostParams.PublicKeyParamSet,
                        gostParams.DigestParamSet,
                        gostParams.EncryptionParamSet);

                    int privateKeyLength = keyInfo.PrivateKeyLength;

                    if (privateKeyLength == 32 || privateKeyLength == 64)
                    {
                        d = new BigInteger(1, keyInfo.PrivateKey.GetOctets(), bigEndian: false);
                    }
                    else
                    {
                        Asn1Object privKey = keyInfo.ParsePrivateKey();
                        if (privKey is DerInteger derInteger)
                        {
                            d = derInteger.PositiveValue;
                        }
                        else
                        {
                            byte[] dVal = Asn1OctetString.GetInstance(privKey).GetOctets();
                            d = new BigInteger(1, dVal, bigEndian: false);
                        }
                    }
                }
                else
                {
                    X962Parameters x962Parameters = X962Parameters.GetInstance(p);

                    if (x962Parameters.IsNamedCurve)
                    {
                        DerObjectIdentifier oid = DerObjectIdentifier.GetInstance(x962Parameters.Parameters);
                        X9ECParameters ecP = ECNamedCurveTable.GetByOid(oid);
                        if (ecP == null)
                            throw new ArgumentException("Unrecognized curve OID for GostR3410x2001 private key");

                        ecSpec = new ECGost3410Parameters(
                            new ECNamedDomainParameters(oid, ecP),
                            gostParams.PublicKeyParamSet,
                            gostParams.DigestParamSet,
                            gostParams.EncryptionParamSet);
                    }
                    else if (x962Parameters.IsImplicitlyCA)
                    {
                        ecSpec = null;
                    }
                    else
                    {
                        X9ECParameters ecP = X9ECParameters.GetInstance(x962Parameters.Parameters);

                        ecSpec = new ECGost3410Parameters(
                            new ECNamedDomainParameters(algOid, ecP),
                            gostParams.PublicKeyParamSet,
                            gostParams.DigestParamSet,
                            gostParams.EncryptionParamSet);
                    }

                    Asn1Object privKey = keyInfo.ParsePrivateKey();
                    if (privKey is DerInteger derD)
                    {
                        d = derD.Value;
                    }
                    else
                    {
                        ECPrivateKeyStructure ec = ECPrivateKeyStructure.GetInstance(privKey);

                        d = ec.GetKey();
                    }
                }

                return new ECPrivateKeyParameters(
                    d,
                    new ECGost3410Parameters(
                        ecSpec,
                        gostParams.PublicKeyParamSet,
                        gostParams.DigestParamSet,
                        gostParams.EncryptionParamSet));
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
            else if (algOid.Equals(RosstandartObjectIdentifiers.id_tc26_gost_3410_12_256)
                ||   algOid.Equals(RosstandartObjectIdentifiers.id_tc26_gost_3410_12_512)
                ||   algOid.Equals(RosstandartObjectIdentifiers.id_tc26_agreement_gost_3410_12_256)
                ||   algOid.Equals(RosstandartObjectIdentifiers.id_tc26_agreement_gost_3410_12_512))
            {
                Gost3410PublicKeyAlgParameters gostParams = Gost3410PublicKeyAlgParameters.GetInstance(
                    keyInfo.PrivateKeyAlgorithm.Parameters);
                ECGost3410Parameters ecSpec;
                BigInteger d;
                Asn1Object p = keyInfo.PrivateKeyAlgorithm.Parameters.ToAsn1Object();
                if (p is Asn1Sequence && (Asn1Sequence.GetInstance(p).Count == 2 || Asn1Sequence.GetInstance(p).Count == 3))
                {
                    X9ECParameters ecP = ECGost3410NamedCurves.GetByOid(gostParams.PublicKeyParamSet);

                    ecSpec = new ECGost3410Parameters(
                        new ECNamedDomainParameters(
                            gostParams.PublicKeyParamSet, ecP),
                            gostParams.PublicKeyParamSet,
                            gostParams.DigestParamSet,
                            gostParams.EncryptionParamSet);

                    int privateKeyLength = keyInfo.PrivateKeyLength;

                    if (privateKeyLength == 32 || privateKeyLength == 64)
                    {
                        d = new BigInteger(1, keyInfo.PrivateKey.GetOctets(), bigEndian: false);
                    }
                    else
                    {
                        Asn1Encodable privKey = keyInfo.ParsePrivateKey();
                        if (privKey is DerInteger)
                        {
                            d = DerInteger.GetInstance(privKey).PositiveValue;
                        }
                        else
                        {
                            byte[] dVal = Asn1OctetString.GetInstance(privKey).GetOctets();
                            d = new BigInteger(1, dVal, bigEndian: false);
                        }
                    }
                }
                else
                {
                    X962Parameters parameters = X962Parameters.GetInstance(keyInfo.PrivateKeyAlgorithm.Parameters);

                    if (parameters.IsNamedCurve)
                    {
                        DerObjectIdentifier oid = DerObjectIdentifier.GetInstance(parameters.Parameters);
                        X9ECParameters ecP = ECKeyPairGenerator.FindECCurveByOid(oid);

                        ecSpec = new ECGost3410Parameters(new ECNamedDomainParameters(oid, ecP),
                            gostParams.PublicKeyParamSet, gostParams.DigestParamSet,
                            gostParams.EncryptionParamSet);
                    }
                    else if (parameters.IsImplicitlyCA)
                    {
                        ecSpec = null;
                    }
                    else
                    {
                        X9ECParameters ecP = X9ECParameters.GetInstance(parameters.Parameters);
                        ecSpec = new ECGost3410Parameters(new ECNamedDomainParameters(algOid, ecP),
                            gostParams.PublicKeyParamSet, gostParams.DigestParamSet,
                            gostParams.EncryptionParamSet);
                    }

                    Asn1Encodable privKey = keyInfo.ParsePrivateKey();
                    if (privKey is DerInteger)
                    {
                        DerInteger derD = DerInteger.GetInstance(privKey);
                        d = derD.Value;
                    }
                    else
                    {
                        ECPrivateKeyStructure ec = ECPrivateKeyStructure.GetInstance(privKey);
                        d = ec.GetKey();
                    }
                }

                return new ECPrivateKeyParameters(
                    d,
                    new ECGost3410Parameters(
                        ecSpec,
                        gostParams.PublicKeyParamSet,
                        gostParams.DigestParamSet,
                        gostParams.EncryptionParamSet));

            }
            else if (NistObjectIdentifiers.IdMLDsa44.Equals(algOid)
                ||   NistObjectIdentifiers.IdMLDsa65.Equals(algOid)
                ||   NistObjectIdentifiers.IdMLDsa87.Equals(algOid))
            {
                var parameters = MLDsaParameters.FromOid(algOid);
                var encoding = Asn1OctetString.GetInstance(keyInfo.ParsePrivateKey());

                // TODO Add support?
                //DerBitString publicKeyData = keyInfo.PublicKey;
                //MLDsaPublicKeyParameters pubKey = null;
                //if (publicKeyData != null)
                //{
                //    pubKey = PublicKeyFactory.GetMLDsaPublicKey(parameters, publicKeyData);
                //}

                return new MLDsaPrivateKeyParameters(parameters, encoding.GetOctets());
            }
            else if (HybridParameters.HybridOidToName.ContainsKey(algOid.Id))
            {
                var hybridName = HybridParameters.HybridOidToName[algOid.Id];
                var names = hybridName.Split(Convert.ToChar("_"));
                var classicalName = names[0];
                var postQuantumName = names[1];

                var hybridBytes = GetRawKey(keyInfo).ToArray();

                var keyParameters = new HybridKeyGenerationParameters(new SecureRandom(), classicalName, postQuantumName);

                AsymmetricKeyParameter classicalKey = null;
                int classicalKeySize = 0;
                if (keyParameters.ClassicalParameters is ECKeyGenerationParameters ecKeyParameters)
                {
                    if (hybridBytes.Length <= 4)
                    {
                        throw new Exception("Encoded hybrid private key has wrong size");
                    }
                    try
                    {
                        classicalKeySize = Convert.ToInt32(Pack.BE_To_UInt32(hybridBytes.Take(4).ToArray()));
                    }
                    catch
                    {
                        throw new Exception("Invalid encoding");
                    }

                    if (hybridBytes.Length <= 4 + classicalKeySize)
                    {
                        throw new Exception("Encoded hybrid private key has wrong size");
                    }

                    var obj = Asn1Object.FromByteArray(hybridBytes.Skip(4).Take(classicalKeySize).ToArray());

                    var structure = ECPrivateKeyStructure.GetInstance(obj);
                    classicalKey = new ECPrivateKeyParameters(structure.GetKey(), ecKeyParameters.DomainParameters);
                }
                else if (keyParameters.ClassicalParameters is X25519KeyGenerationParameters)
                {
                    classicalKeySize = X25519PrivateKeyParameters.KeySize;
                    if (hybridBytes.Length <= 4 + classicalKeySize)
                    {
                        throw new Exception("Encoded hybrid private key has wrong size");
                    }

                    classicalKey = new X25519PrivateKeyParameters(hybridBytes.Skip(4).Take(classicalKeySize).ToArray());
                }
                else if (keyParameters.ClassicalParameters is Ed25519KeyGenerationParameters)
                {
                    classicalKeySize = Ed25519PrivateKeyParameters.KeySize;
                    if (hybridBytes.Length <= 4 + classicalKeySize)
                    {
                        throw new Exception("Encoded hybrid private key has wrong size");
                    }

                    classicalKey = new Ed25519PrivateKeyParameters(hybridBytes.Skip(4).Take(classicalKeySize).ToArray());
                }
                else if (keyParameters.ClassicalParameters is X448KeyGenerationParameters)
                {
                    classicalKeySize = X448PrivateKeyParameters.KeySize;
                    if (hybridBytes.Length <= 4 + classicalKeySize)
                    {
                        throw new Exception("Encoded hybrid private key has wrong size");
                    }

                    classicalKey = new X448PrivateKeyParameters(hybridBytes.Skip(4).Take(classicalKeySize).ToArray());
                }
                else if (keyParameters.ClassicalParameters is Ed448KeyGenerationParameters)
                {
                    classicalKeySize = Ed448PrivateKeyParameters.KeySize;
                    if (hybridBytes.Length <= 4 + classicalKeySize)
                    {
                        throw new Exception("Encoded hybrid private key has wrong size");
                    }

                    classicalKey = new Ed448PrivateKeyParameters(hybridBytes.Skip(4).Take(classicalKeySize).ToArray());
                }
                else if (keyParameters.ClassicalParameters is RsaKeyGenerationParameters)
                {
                    // TODO
                    throw new Exception("Rsa hybrid keys not supported");
                }

                if (classicalKey == null)
                {
                    throw new Exception("Classical keytype not supported");
                }

                hybridBytes = hybridBytes.Skip(4 + classicalKeySize).ToArray();

                AsymmetricKeyParameter postQuantumKey = null;
                if (keyParameters.PostQuantumParameters is MLKemKeyGenerationParameters mlkemParameters)
                {
                    int postQuantumKeySize = 0;
                    MLKemParameters parameters;
                    switch (mlkemParameters.Parameters.Name)
                    {
                        case "ML-KEM-512":
                            postQuantumKeySize = 1632;
                            parameters = MLKemParameters.ML_KEM_512;
                            break;
                        case "ML-KEM-768":
                            postQuantumKeySize = 2400;
                            parameters = MLKemParameters.ML_KEM_768;
                            break;
                        case "ML-KEM-1024":
                            postQuantumKeySize = 3168;
                            parameters = MLKemParameters.ML_KEM_1024;
                            break;
                        default:
                            throw new Exception("Post-quantum keytype not supported");
                    }

                    if (hybridBytes.Length != postQuantumKeySize)
                    {
                        throw new Exception("Encoded hybrid private key has wrong size");
                    }

                    postQuantumKey = new MLKemPrivateKeyParameters(parameters, hybridBytes);
                }
                else if (keyParameters.PostQuantumParameters is DilithiumKeyGenerationParameters dilithiumParameters)
                {
                    int postQuantumKeySize = 0;
                    DilithiumParameters parameters;
                    switch (dilithiumParameters.Parameters.Name)
                    {
                        case "dilithium2":
                            postQuantumKeySize = 2560;
                            parameters = DilithiumParameters.Dilithium2;
                            break;
                        case "dilithium3":
                            postQuantumKeySize = 4032;
                            parameters = DilithiumParameters.Dilithium3;
                            break;
                        case "dilithium5":
                            postQuantumKeySize = 4896;
                            parameters = DilithiumParameters.Dilithium5;
                            break;
                        default:
                            throw new Exception("Post-quantum keytype not supported");
                    }

                    if (hybridBytes.Length != postQuantumKeySize)
                    {
                        throw new Exception("Encoded hybrid private key has wrong size");
                    }

                    var publicParams = new DilithiumPublicKeyParameters(parameters, hybridBytes);

                    postQuantumKey = new DilithiumPrivateKeyParameters(parameters, hybridBytes, publicParams);
                }
                else if (keyParameters.PostQuantumParameters is SphincsPlusKeyGenerationParameters sphincsParameters)
                {
                    int postQuantumKeySize = 0;
                    SphincsPlusParameters parameters;
                    switch (sphincsParameters.Parameters.Name)
                    {
                        case "sha2-128f-simple":
                            postQuantumKeySize = 64;
                            parameters = SphincsPlusParameters.sha2_128f_simple;
                            break;
                        case "sha2-128s-simple":
                            postQuantumKeySize = 64;
                            parameters = SphincsPlusParameters.sha2_128s_simple;
                            break;
                        case "sha2-192f-simple":
                            postQuantumKeySize = 96;
                            parameters = SphincsPlusParameters.sha2_192f_simple;
                            break;
                        case "sha2-192s-simple":
                            postQuantumKeySize = 96;
                            parameters = SphincsPlusParameters.sha2_192s_simple;
                            break;
                        case "sha2-256f-simple":
                            postQuantumKeySize = 128;
                            parameters = SphincsPlusParameters.sha2_256f_simple;
                            break;
                        case "sha2-256s-simple":
                            postQuantumKeySize = 128;
                            parameters = SphincsPlusParameters.sha2_256s_simple;
                            break;
                        case "shake-128f-simple":
                            postQuantumKeySize = 64;
                            parameters = SphincsPlusParameters.shake_128f_simple;
                            break;
                        case "shake-128s-simple":
                            postQuantumKeySize = 64;
                            parameters = SphincsPlusParameters.shake_128s_simple;
                            break;
                        case "shake-192f-simple":
                            postQuantumKeySize = 96;
                            parameters = SphincsPlusParameters.shake_192f_simple;
                            break;
                        case "shake-192s-simple":
                            postQuantumKeySize = 96;
                            parameters = SphincsPlusParameters.shake_192s_simple;
                            break;
                        case "shake-256f-simple":
                            postQuantumKeySize = 128;
                            parameters = SphincsPlusParameters.shake_256f_simple;
                            break;
                        case "shake-256s-simple":
                            postQuantumKeySize = 128;
                            parameters = SphincsPlusParameters.shake_256s_simple;
                            break;
                        default:
                            throw new Exception("Post-quantum keytype not supported");
                    }

                    if (hybridBytes.Length != postQuantumKeySize)
                    {
                        throw new Exception("Encoded hybrid private key has wrong size");
                    }

                    postQuantumKey = new SphincsPlusPrivateKeyParameters(parameters, hybridBytes);
                }

                if (postQuantumKey == null)
                {
                    throw new Exception("Post-quantum keytype not supported");
                }

                return new HybridKeyParameters(classicalKey, postQuantumKey);
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

        public static AsymmetricKeyParameter DecryptKey(
            char[] passPhrase,
            EncryptedPrivateKeyInfo encInfo)
        {
            return CreateKey(PrivateKeyInfoFactory.CreatePrivateKeyInfo(passPhrase, encInfo));
        }

        public static AsymmetricKeyParameter DecryptKey(
            char[] passPhrase,
            byte[] encryptedPrivateKeyInfoData)
        {
            return DecryptKey(passPhrase, Asn1Object.FromByteArray(encryptedPrivateKeyInfoData));
        }

        public static AsymmetricKeyParameter DecryptKey(
            char[] passPhrase,
            Stream encryptedPrivateKeyInfoStream)
        {
            return DecryptKey(passPhrase, Asn1Object.FromStream(encryptedPrivateKeyInfoStream));
        }

        private static AsymmetricKeyParameter DecryptKey(
            char[] passPhrase,
            Asn1Object asn1Object)
        {
            return DecryptKey(passPhrase, EncryptedPrivateKeyInfo.GetInstance(asn1Object));
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
