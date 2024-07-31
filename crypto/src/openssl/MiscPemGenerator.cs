using System;
using System.Collections.Generic;
using System.IO;

using Org.BouncyCastle.Asn1;
using Org.BouncyCastle.Asn1.CryptoPro;
using Org.BouncyCastle.Asn1.Oiw;
using Org.BouncyCastle.Asn1.Pkcs;
using Org.BouncyCastle.Asn1.X509;
using Org.BouncyCastle.Asn1.X9;
using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Math;
using Org.BouncyCastle.Pkcs;
using Org.BouncyCastle.Security;
using Org.BouncyCastle.Security.Certificates;
using Org.BouncyCastle.Utilities;
using Org.BouncyCastle.Utilities.Encoders;
using Org.BouncyCastle.Utilities.IO.Pem;
using Org.BouncyCastle.X509;

namespace Org.BouncyCastle.OpenSsl
{
    /**
    * PEM generator for the original set of PEM objects used in Open SSL.
    */
    public class MiscPemGenerator
        : PemObjectGenerator
    {
        private readonly object obj;
        private readonly string algorithm;
        private readonly char[] password;
        private readonly SecureRandom random;

        public MiscPemGenerator(object obj)
            : this(obj, null, null, null)
        {
        }

        public MiscPemGenerator(object obj, string algorithm, char[] password, SecureRandom random)
        {
            this.obj = obj;
            this.algorithm = algorithm;
            this.password = password;
            this.random = random;
        }

        private static PemObject CreatePemObject(object obj)
        {
            if (obj == null)
                throw new ArgumentNullException(nameof(obj));

            if (obj is AsymmetricCipherKeyPair keyPair)
                return CreatePemObject(keyPair.Private);

            string type;
            byte[] encoding;

            if (obj is PemObject pemObject)
                return pemObject;

            if (obj is PemObjectGenerator pemObjectGenerator)
                return pemObjectGenerator.Generate();

            if (obj is X509Certificate certificate)
            {
                // TODO Should we prefer "X509 CERTIFICATE" here?
                type = "CERTIFICATE";
                try
                {
                    encoding = certificate.GetEncoded();
                }
                catch (CertificateEncodingException e)
                {
                    throw new IOException("Cannot Encode object: " + e.ToString());
                }
            }
            else if (obj is X509Crl crl)
            {
                type = "X509 CRL";
                try
                {
                    encoding = crl.GetEncoded();
                }
                catch (CrlException e)
                {
                    throw new IOException("Cannot Encode object: " + e.ToString());
                }
            }
            else if (obj is AsymmetricKeyParameter akp)
            {
                if (akp.IsPrivate)
                {
                    encoding = EncodePrivateKey(akp, out type);
                }
                else
                {
                    encoding = EncodePublicKey(akp, out type);
                }
            }
            else if (obj is PrivateKeyInfo privateKeyInfo)
            {
                encoding = EncodePrivateKeyInfo(privateKeyInfo, out type);
            }
            else if (obj is SubjectPublicKeyInfo subjectPublicKeyInfo)
            {
                encoding = EncodePublicKeyInfo(subjectPublicKeyInfo, out type);
            }
            else if (obj is X509V2AttributeCertificate attrCert)
            {
                type = "ATTRIBUTE CERTIFICATE";
                encoding = attrCert.GetEncoded();
            }
            else if (obj is Pkcs8EncryptedPrivateKeyInfo pkcs8EncryptedPrivateKeyInfo)
            {
                type = "ENCRYPTED PRIVATE KEY";
                encoding = pkcs8EncryptedPrivateKeyInfo.GetEncoded();
            }
            else if (obj is Pkcs10CertificationRequest certReq)
            {
                type = "CERTIFICATE REQUEST";
                encoding = certReq.GetEncoded();
            }
            else if (obj is Asn1.Cms.ContentInfo cmsContentInfo)
            {
                type = "PKCS7";
                encoding = cmsContentInfo.GetEncoded();
            }
            else if (obj is Asn1.Pkcs.ContentInfo pkcsContentInfo)
            {
                type = "PKCS7";
                encoding = pkcsContentInfo.GetEncoded();
            }
            else
            {
                throw new PemGenerationException("Object type not supported: " + Platform.GetTypeName(obj));
            }

            return new PemObject(type, encoding);
        }

#if NETCOREAPP2_1_OR_GREATER || NETSTANDARD2_1_OR_GREATER
        private static PemObject CreatePemObject(object obj, string algorithm, ReadOnlySpan<char> password,
            SecureRandom random)
        {
            if (obj == null)
                throw new ArgumentNullException("obj");
            if (algorithm == null)
                throw new ArgumentNullException("algorithm");
            if (random == null)
                throw new ArgumentNullException("random");

            if (obj is AsymmetricCipherKeyPair keyPair)
            {
                return CreatePemObject(keyPair.Private, algorithm, password, random);
            }

            string type = null;
            byte[] keyData = null;

            if (obj is AsymmetricKeyParameter akp)
            {
                if (akp.IsPrivate)
                {
                    keyData = EncodePrivateKey(akp, out type);
                }
            }

            if (type == null || keyData == null)
            {
                // TODO Support other types?
                throw new PemGenerationException("Object type not supported: " + Platform.GetTypeName(obj));
            }


            string dekAlgName = algorithm.ToUpperInvariant();

            // Note: For backward compatibility
            if (dekAlgName == "DESEDE")
            {
                dekAlgName = "DES-EDE3-CBC";
            }

            int ivLength = Platform.StartsWith(dekAlgName, "AES-") ? 16 : 8;

            byte[] iv = new byte[ivLength];
            random.NextBytes(iv);

            byte[] encData = PemUtilities.Crypt(true, keyData, password, dekAlgName, iv);

            var headers = new List<PemHeader>(2);
            headers.Add(new PemHeader("Proc-Type", "4,ENCRYPTED"));
            headers.Add(new PemHeader("DEK-Info", dekAlgName + "," + Hex.ToHexString(iv, true)));

            return new PemObject(type, headers, encData);
        }
#else
        private static PemObject CreatePemObject(
            object			obj,
            string			algorithm,
            char[]			password,
            SecureRandom	random)
        {
            if (obj == null)
                throw new ArgumentNullException("obj");
            if (algorithm == null)
                throw new ArgumentNullException("algorithm");
            if (password == null)
                throw new ArgumentNullException("password");
            if (random == null)
                throw new ArgumentNullException("random");

            if (obj is AsymmetricCipherKeyPair keyPair)
            {
                return CreatePemObject(keyPair.Private, algorithm, password, random);
            }

            string type = null;
            byte[] keyData = null;

            if (obj is AsymmetricKeyParameter akp)
            {
                if (akp.IsPrivate)
                {
                    keyData = EncodePrivateKey(akp, out type);
                }
            }

            if (type == null || keyData == null)
            {
                // TODO Support other types?
                throw new PemGenerationException("Object type not supported: " + Platform.GetTypeName(obj));
            }


            string dekAlgName = algorithm.ToUpperInvariant();

            // Note: For backward compatibility
            if (dekAlgName == "DESEDE")
            {
                dekAlgName = "DES-EDE3-CBC";
            }

            int ivLength = Platform.StartsWith(dekAlgName, "AES-") ? 16 : 8;

            byte[] iv = new byte[ivLength];
            random.NextBytes(iv);

            byte[] encData = PemUtilities.Crypt(true, keyData, password, dekAlgName, iv);

            var headers = new List<PemHeader>(2);
            headers.Add(new PemHeader("Proc-Type", "4,ENCRYPTED"));
            headers.Add(new PemHeader("DEK-Info", dekAlgName + "," + Hex.ToHexString(iv, true)));

            return new PemObject(type, headers, encData);
        }
#endif

        public PemObject Generate()
        {
            try
            {
                if (algorithm != null)
                    return CreatePemObject(obj, algorithm, password, random);

                return CreatePemObject(obj);
            }
            catch (IOException e)
            {
                throw new PemGenerationException("encoding exception", e);
            }
        }

        private static byte[] EncodePrivateKey(AsymmetricKeyParameter akp, out string keyType)
        {
            PrivateKeyInfo info = PrivateKeyInfoFactory.CreatePrivateKeyInfo(akp);
            return EncodePrivateKeyInfo(info, out keyType);
        }

        private static byte[] EncodePrivateKeyInfo(PrivateKeyInfo info, out string keyType)
        {
            var algID = info.PrivateKeyAlgorithm;
            var algOid = algID.Algorithm;

            if (algOid.Equals(PkcsObjectIdentifiers.RsaEncryption))
            {
                keyType = "RSA PRIVATE KEY";

                return info.ParsePrivateKey().GetEncoded();
            }
            else if (algOid.Equals(X9ObjectIdentifiers.IdECPublicKey) ||
                     algOid.Equals(CryptoProObjectIdentifiers.GostR3410x2001))
            {
                keyType = "EC PRIVATE KEY";

                return info.ParsePrivateKey().GetEncoded();
            }
            else if (algOid.Equals(X9ObjectIdentifiers.IdDsa) ||
                     algOid.Equals(OiwObjectIdentifiers.DsaWithSha1))
            {
                keyType = "DSA PRIVATE KEY";

                DsaParameter p = DsaParameter.GetInstance(algID.Parameters);
                BigInteger x = DerInteger.GetInstance(info.ParsePrivateKey()).Value;
                BigInteger y = p.G.ModPow(x, p.P);

                var sequence = new DerSequence(
                    DerInteger.Zero,
                    new DerInteger(p.P),
                    new DerInteger(p.Q),
                    new DerInteger(p.G),
                    new DerInteger(y),
                    new DerInteger(x));
                return sequence.GetEncoded();
            }
            else
            {
                keyType = "PRIVATE KEY";

                return info.GetEncoded();
            }
        }

        private static byte[] EncodePublicKey(AsymmetricKeyParameter akp, out string keyType)
        {
            SubjectPublicKeyInfo info = SubjectPublicKeyInfoFactory.CreateSubjectPublicKeyInfo(akp);
            return EncodePublicKeyInfo(info, out keyType);
        }

        private static byte[] EncodePublicKeyInfo(SubjectPublicKeyInfo info, out string keyType)
        {
            keyType = "PUBLIC KEY";

            return info.GetEncoded();
        }
    }
}
