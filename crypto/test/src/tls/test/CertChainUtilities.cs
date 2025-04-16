using System;
using System.Threading;

using Org.BouncyCastle.Asn1.X509;
using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Crypto.Operators;
using Org.BouncyCastle.Math;
using Org.BouncyCastle.Security;
using Org.BouncyCastle.X509;
using Org.BouncyCastle.X509.Extension;

namespace Org.BouncyCastle.Tls.Tests
{
    public static class CertChainUtilities
    {
        private static readonly SecureRandom Random = new SecureRandom();

        private static long _serialNumber = 0L;
        private static BigInteger AllocateSerialNumber() =>
            BigInteger.ValueOf(Interlocked.Increment(ref _serialNumber));

        /// <summary>We generate the CA's certificate.</summary>
        public static X509Certificate CreateMasterCert(string rootDN, AsymmetricCipherKeyPair keyPair)
        {
            //
            // create the certificate - version 1
            //
            X509V1CertificateGenerator gen = new X509V1CertificateGenerator();
            gen.SetIssuerDN(new X509Name(rootDN));
            gen.SetSerialNumber(AllocateSerialNumber());
            gen.SetNotBefore(DateTime.UtcNow.AddDays(-30));
            gen.SetNotAfter(DateTime.UtcNow.AddDays(30));
            gen.SetSubjectDN(new X509Name(rootDN));
            gen.SetPublicKey(keyPair.Public);

            return SignV1(gen, keyPair.Private);
        }

        /// <summary>We generate an intermediate certificate signed by our CA.</summary>
        public static X509Certificate CreateIntermediateCert(string interDN, AsymmetricKeyParameter pubKey,
            AsymmetricKeyParameter caPrivKey, X509Certificate caCert)
        {
            var spki = SubjectPublicKeyInfoFactory.CreateSubjectPublicKeyInfo(pubKey);

            //
            // create the certificate - version 3
            //
            X509V3CertificateGenerator gen = new X509V3CertificateGenerator();
            gen.SetIssuerDN(caCert.SubjectDN);
            gen.SetSerialNumber(AllocateSerialNumber());
            gen.SetNotBefore(DateTime.UtcNow.AddDays(-30));
            gen.SetNotAfter(DateTime.UtcNow.AddDays(30));
            gen.SetSubjectDN(new X509Name(interDN));
            gen.SetSubjectPublicKeyInfo(spki);

            //
            // extensions
            //
            gen.AddExtension(X509Extensions.SubjectKeyIdentifier, false,
                X509ExtensionUtilities.CreateSubjectKeyIdentifier(spki));
            gen.AddExtension(X509Extensions.AuthorityKeyIdentifier, false,
                X509ExtensionUtilities.CreateAuthorityKeyIdentifier(caCert));
            gen.AddExtension(X509Extensions.BasicConstraints, true,
                new BasicConstraints(0));

            return SignV3(gen, caPrivKey);
        }

        /// <summary>We generate a certificate signed by our CA's intermediate certificate.</summary>
        public static X509Certificate CreateEndEntityCert(string endEntityDN, AsymmetricKeyParameter pubKey,
            AsymmetricKeyParameter caPrivKey, X509Certificate caCert)
        {
            X509V3CertificateGenerator gen = CreateBaseEndEntityGenerator(endEntityDN, pubKey, caCert);

            return SignV3(gen, caPrivKey);
        }

        /// <summary>We generate a certificate signed by our CA's intermediate certificate with ExtendedKeyUsage
        /// extension.</summary>
        public static X509Certificate CreateEndEntityCert(string endEntityDN, AsymmetricKeyParameter pubKey,
            AsymmetricKeyParameter caPrivKey, X509Certificate caCert, KeyPurposeID keyPurposeID)
        {
            X509V3CertificateGenerator gen = CreateBaseEndEntityGenerator(endEntityDN, pubKey, caCert);

            gen.AddExtension(X509Extensions.ExtendedKeyUsage, true, new ExtendedKeyUsage(keyPurposeID));

            return SignV3(gen, caPrivKey);
        }

        private static X509V3CertificateGenerator CreateBaseEndEntityGenerator(string endEntityDN,
            AsymmetricKeyParameter pubKey, X509Certificate caCert)
        {
            var spki = SubjectPublicKeyInfoFactory.CreateSubjectPublicKeyInfo(pubKey);

            //
            // create the certificate - version 3
            //
            X509V3CertificateGenerator gen = new X509V3CertificateGenerator();
            gen.SetIssuerDN(caCert.SubjectDN);
            gen.SetSerialNumber(AllocateSerialNumber());
            gen.SetNotBefore(DateTime.UtcNow.AddDays(-30));
            gen.SetNotAfter(DateTime.UtcNow.AddDays(30));
            gen.SetSubjectDN(new X509Name(endEntityDN));
            gen.SetSubjectPublicKeyInfo(spki);

            //
            // add the extensions
            //
            gen.AddExtension(X509Extensions.SubjectKeyIdentifier, false,
                X509ExtensionUtilities.CreateSubjectKeyIdentifier(spki));
            gen.AddExtension(X509Extensions.AuthorityKeyIdentifier, false,
                X509ExtensionUtilities.CreateAuthorityKeyIdentifier(caCert));
            gen.AddExtension(X509Extensions.BasicConstraints, true,
                new BasicConstraints(false));

            return gen;
        }

        private static X509Certificate SignV1(X509V1CertificateGenerator gen, AsymmetricKeyParameter caPrivKey) =>
            gen.Generate(new Asn1SignatureFactory("SHA256withRSA", caPrivKey, Random));

        private static X509Certificate SignV3(X509V3CertificateGenerator gen, AsymmetricKeyParameter caPrivKey) =>
            gen.Generate(new Asn1SignatureFactory("SHA256withRSA", caPrivKey, Random));
    }
}
