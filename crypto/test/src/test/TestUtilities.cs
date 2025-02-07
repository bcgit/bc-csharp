using System;
using System.Threading;

using Org.BouncyCastle.Asn1.Oiw;
using Org.BouncyCastle.Asn1.X509;
using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Crypto.Operators;
using Org.BouncyCastle.Math;
using Org.BouncyCastle.Security;
using Org.BouncyCastle.X509;
using Org.BouncyCastle.X509.Extension;

namespace Org.BouncyCastle.Tests
{
    /**
	 * Test Utils
	 */
    internal static class TestUtilities
    {
        private static long serialNumber = DateTime.UtcNow.Ticks;

        private static long NextSerialNumber() => Interlocked.Increment(ref serialNumber);

        public static X509Certificate CreateSelfSignedCert(string dn, string sigName, AsymmetricCipherKeyPair keyPair) =>
            CreateSelfSignedCert(new X509Name(dn), sigName, keyPair);

        public static X509Certificate CreateSelfSignedCert(X509Name dn, string sigName, AsymmetricCipherKeyPair keyPair)
        {
            DateTime utcNow = DateTime.UtcNow;

            var certGen = new X509V1CertificateGenerator();

            certGen.SetSerialNumber(BigInteger.ValueOf(NextSerialNumber()));
            certGen.SetIssuerDN(dn);
            certGen.SetNotBefore(utcNow.AddSeconds(-5));
            certGen.SetNotAfter(utcNow.AddMinutes(30));
            certGen.SetSubjectDN(dn);
            certGen.SetPublicKey(keyPair.Public);

            return certGen.Generate(new Asn1SignatureFactory(sigName, keyPair.Private, null));
        }

        public static X509Certificate CreateCert(X509Name signerName, AsymmetricKeyParameter signerKey, string dn,
            string sigName, X509Extensions extensions, AsymmetricKeyParameter pubKey)
        {
            return CreateCert(signerName, signerKey, new X509Name(dn), sigName, extensions, pubKey);
        }

        public static X509Certificate CreateCert(X509Name signerName, AsymmetricKeyParameter signerKey, X509Name dn,
            string sigName, X509Extensions extensions, AsymmetricKeyParameter pubKey)
        {
            DateTime utcNow = DateTime.UtcNow;

            var certGen = new X509V3CertificateGenerator();

            certGen.SetSerialNumber(BigInteger.ValueOf(NextSerialNumber()));
            certGen.SetIssuerDN(signerName);
            certGen.SetNotBefore(utcNow.AddSeconds(-5));
            certGen.SetNotAfter(utcNow.AddMinutes(30));
            certGen.SetSubjectDN(dn);
            certGen.SetPublicKey(pubKey);

            certGen.AddExtensions(extensions);

            return certGen.Generate(new Asn1SignatureFactory(sigName, signerKey, null));
        }

        public static X509Crl CreateCrl(X509Certificate caCert, AsymmetricKeyParameter caKey, BigInteger serialNumber)
        {
            DateTime utcNow = DateTime.UtcNow;

            var crlGen = new X509V2CrlGenerator();

            crlGen.SetIssuerDN(caCert.SubjectDN);

            crlGen.SetThisUpdate(utcNow);
            crlGen.SetNextUpdate(utcNow.AddSeconds(100));

            crlGen.AddCrlEntry(serialNumber, utcNow, CrlReason.PrivilegeWithdrawn);

            crlGen.AddExtension(X509Extensions.AuthorityKeyIdentifier, false, new AuthorityKeyIdentifierStructure(caCert));
            crlGen.AddExtension(X509Extensions.CrlNumber, false, new CrlNumber(BigInteger.One));

            return crlGen.Generate(new Asn1SignatureFactory("SHA256withRSA", caKey, null));
        }

        /**
		 * Create a random 1024 bit RSA key pair
		 */
        public static AsymmetricCipherKeyPair GenerateRsaKeyPair()
        {
            IAsymmetricCipherKeyPairGenerator kpGen = GeneratorUtilities.GetKeyPairGenerator("RSA");

            kpGen.Init(new KeyGenerationParameters(new SecureRandom(), 1024));

            return kpGen.GenerateKeyPair();
        }

        public static X509Certificate GenerateRootCert(AsymmetricCipherKeyPair keyPair) =>
            CreateSelfSignedCert("CN=Test CA Certificate", "SHA256withRSA", keyPair);

        public static X509Certificate GenerateRootCert(AsymmetricCipherKeyPair keyPair, X509Name dn) =>
            CreateSelfSignedCert(dn, "SHA256withRSA", keyPair);

        public static X509Certificate GenerateIntermediateCert(AsymmetricKeyParameter intKey,
            AsymmetricKeyParameter caKey, X509Certificate caCert)
        {
            return GenerateIntermediateCert(intKey, new X509Name("CN=Test Intermediate Certificate"), caKey, caCert);
        }

        public static X509Certificate GenerateIntermediateCert(AsymmetricKeyParameter intKey, X509Name subject,
            AsymmetricKeyParameter caKey, X509Certificate caCert)
        {
            var caCertLw = caCert.CertificateStructure;

            var extGen = new X509ExtensionsGenerator();

            extGen.AddExtension(X509Extensions.AuthorityKeyIdentifier, false,
                new AuthorityKeyIdentifier(
                    GetDigest(caCertLw.SubjectPublicKeyInfo),
                    new GeneralNames(new GeneralName(caCertLw.Issuer)),
                    caCertLw.SerialNumber.Value));
            extGen.AddExtension(X509Extensions.SubjectKeyIdentifier, false,
                new SubjectKeyIdentifier(SubjectPublicKeyInfoFactory.CreateSubjectPublicKeyInfo(intKey)));
            extGen.AddExtension(X509Extensions.BasicConstraints, true, new BasicConstraints(0));
            extGen.AddExtension(X509Extensions.KeyUsage, true,
                new KeyUsage(KeyUsage.DigitalSignature | KeyUsage.KeyCertSign | KeyUsage.CrlSign));

            return CreateCert(caCertLw.Subject, caKey, subject, "SHA256withRSA", extGen.Generate(), intKey);
        }

        public static X509Certificate GenerateEndEntityCert(AsymmetricKeyParameter entityKey,
            AsymmetricKeyParameter caKey, X509Certificate caCert)
        {
            return GenerateEndEntityCert(entityKey, new X509Name("CN=Test End Certificate"), caKey, caCert);
        }

        public static X509Certificate GenerateEndEntityCert(AsymmetricKeyParameter entityKey, X509Name subject,
            AsymmetricKeyParameter caKey, X509Certificate caCert)
        {
            var caCertLw = caCert.CertificateStructure;

            var extGen = new X509ExtensionsGenerator();

            extGen.AddExtension(X509Extensions.AuthorityKeyIdentifier, false,
                new AuthorityKeyIdentifier(
                    GetDigest(caCertLw.SubjectPublicKeyInfo),
                    new GeneralNames(new GeneralName(caCertLw.Issuer)),
                    caCertLw.SerialNumber.Value));
            extGen.AddExtension(X509Extensions.SubjectKeyIdentifier, false,
                new SubjectKeyIdentifier(SubjectPublicKeyInfoFactory.CreateSubjectPublicKeyInfo(entityKey)));
            extGen.AddExtension(X509Extensions.BasicConstraints, true, new BasicConstraints(0));
            extGen.AddExtension(X509Extensions.KeyUsage, true,
                new KeyUsage(KeyUsage.DigitalSignature | KeyUsage.KeyCertSign | KeyUsage.CrlSign));

            return CreateCert(caCertLw.Subject, caKey, subject, "SHA256withRSA", extGen.Generate(), entityKey);
        }

        public static X509Certificate GenerateEndEntityCert(AsymmetricKeyParameter entityKey, X509Name subject,
            KeyPurposeID keyPurpose, AsymmetricKeyParameter caKey, X509Certificate caCert)
        {
            return GenerateEndEntityCert(entityKey, subject, keyPurpose, null, caKey, caCert);
        }

        public static X509Certificate GenerateEndEntityCert(AsymmetricKeyParameter entityKey, X509Name subject,
            KeyPurposeID keyPurpose1, KeyPurposeID keyPurpose2, AsymmetricKeyParameter caKey, X509Certificate caCert)
        {
            var caCertLw = caCert.CertificateStructure;

            var extGen = new X509ExtensionsGenerator();

            extGen.AddExtension(X509Extensions.AuthorityKeyIdentifier, false,
                new AuthorityKeyIdentifier(
                    GetDigest(caCertLw.SubjectPublicKeyInfo),
                    new GeneralNames(new GeneralName(caCertLw.Issuer)),
                    caCertLw.SerialNumber.Value));
            extGen.AddExtension(X509Extensions.SubjectKeyIdentifier, false,
                new SubjectKeyIdentifier(SubjectPublicKeyInfoFactory.CreateSubjectPublicKeyInfo(entityKey)));
            extGen.AddExtension(X509Extensions.BasicConstraints, true, new BasicConstraints(0));
            extGen.AddExtension(X509Extensions.KeyUsage, true,
                new KeyUsage(KeyUsage.DigitalSignature | KeyUsage.KeyCertSign | KeyUsage.CrlSign));
            if (keyPurpose2 == null)
            {
                extGen.AddExtension(X509Extensions.ExtendedKeyUsage, true, new ExtendedKeyUsage(keyPurpose1));
            }
            else
            {
                extGen.AddExtension(X509Extensions.ExtendedKeyUsage, true,
                    new ExtendedKeyUsage(new KeyPurposeID[] { keyPurpose1, keyPurpose2 }));
            }

            return CreateCert(caCertLw.Subject, caKey, subject, "SHA256withRSA", extGen.Generate(), entityKey);
        }

        private static byte[] GetDigest(SubjectPublicKeyInfo spki) => GetDigest(spki.PublicKey.GetBytes());

        private static byte[] GetDigest(byte[] bytes) =>
            DigestUtilities.CalculateDigest(OiwObjectIdentifiers.IdSha1, bytes);
    }
}
