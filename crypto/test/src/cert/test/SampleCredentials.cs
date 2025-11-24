using System;
using System.IO;

using NUnit.Framework;

using Org.BouncyCastle.Asn1.X509;
using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Security;
using Org.BouncyCastle.Utilities.IO.Pem;
using Org.BouncyCastle.Utilities.Test;
using Org.BouncyCastle.X509;

namespace Org.BouncyCastle.Cert.Tests
{
    public sealed class SampleCredentials
    {
        public static readonly SampleCredentials ML_DSA_44 = Load("ML-DSA-44", "pkix/cert/mldsa", "ML-DSA-44.pem");
        public static readonly SampleCredentials ML_DSA_65 = Load("ML-DSA-65", "pkix/cert/mldsa", "ML-DSA-65.pem");
        public static readonly SampleCredentials ML_DSA_87 = Load("ML-DSA-87", "pkix/cert/mldsa", "ML-DSA-87.pem");

        public static readonly SampleCredentials ML_KEM_512 = Load("ML-KEM-512", "pkix/cert/mlkem", "ML-KEM-512.pem");
        public static readonly SampleCredentials ML_KEM_768 = Load("ML-KEM-768", "pkix/cert/mlkem", "ML-KEM-768.pem");
        public static readonly SampleCredentials ML_KEM_1024 = Load("ML-KEM-1024", "pkix/cert/mlkem", "ML-KEM-1024.pem");

        public static readonly SampleCredentials SLH_DSA_SHA2_128S = Load("SLH-DSA-SHA2-128S", "pkix/cert/slhdsa",
            "SLH-DSA-SHA2-128S.pem");

        private static PemObject ExpectPemObject(PemReader pemReader, string type)
        {
            PemObject result = pemReader.ReadPemObject();
            if (!type.Equals(result.Type))
                throw new InvalidOperationException();

            return result;
        }

        private static SampleCredentials Load(string algorithm, string path, string name)
        {
            using (var pemReader = new PemReader(new StreamReader(SimpleTest.FindTestResource(path, name))))
            {
                PemObject pemPriv = ExpectPemObject(pemReader, "PRIVATE KEY");
                PemObject pemPub = ExpectPemObject(pemReader, "PUBLIC KEY");
                PemObject pemCert = ExpectPemObject(pemReader, "CERTIFICATE");

                var privateKey = PrivateKeyFactory.CreateKey(pemPriv.Content);

                var spki = SubjectPublicKeyInfo.GetInstance(pemPub.Content);
                var publicKey = PublicKeyFactory.CreateKey(spki);

                var keyPair = new AsymmetricCipherKeyPair(publicKey, privateKey);

                var certificate = new X509Certificate(pemCert.Content);

                Assert.AreEqual(spki, certificate.SubjectPublicKeyInfo);

                return new SampleCredentials(keyPair, certificate);
            }
        }

        private readonly AsymmetricCipherKeyPair m_keyPair;
        private readonly X509Certificate m_certificate;

        private SampleCredentials(AsymmetricCipherKeyPair keyPair, X509Certificate certificate)
        {
            m_keyPair = keyPair;
            m_certificate = certificate;
        }

        public X509Certificate Certificate => m_certificate;

        public AsymmetricCipherKeyPair KeyPair => m_keyPair;
    }
}
