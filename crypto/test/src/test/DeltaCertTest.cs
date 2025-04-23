using System;
using System.IO;

using NUnit.Framework;

using Org.BouncyCastle.Asn1.Sec;
using Org.BouncyCastle.Asn1.X509;
using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Crypto.Operators;
using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.Math;
using Org.BouncyCastle.OpenSsl;
using Org.BouncyCastle.Security;
using Org.BouncyCastle.Utilities.Date;
using Org.BouncyCastle.Utilities.Test;
using Org.BouncyCastle.X509;

namespace Org.BouncyCastle.Tests
{
    [TestFixture]
    public class DeltaCertTest
    {
        private static readonly SecureRandom Random = new SecureRandom();

        [Test]
        public void SameName()
        {
            var rsaKeyGen = GeneratorUtilities.GetKeyPairGenerator("RSA");
            rsaKeyGen.Init(new KeyGenerationParameters(Random, 2048));

            var deltaKeyPair = rsaKeyGen.GenerateKeyPair();
            var baseKeyPair = rsaKeyGen.GenerateKeyPair();

            // Generate a self-signed Delta Certificate
            var deltaCertBuilder = new X509V3CertificateGenerator();
            deltaCertBuilder.SetIssuerDN(new X509Name("CN=Issuer"));
            deltaCertBuilder.SetSerialNumber(BigInteger.One);
            deltaCertBuilder.SetNotBefore(DateTime.UtcNow);
            deltaCertBuilder.SetNotAfter(DateTime.UtcNow.AddYears(1));
            deltaCertBuilder.SetSubjectDN(new X509Name("CN=Subject"));
            deltaCertBuilder.SetPublicKey(deltaKeyPair.Public);

            var deltaCert = deltaCertBuilder.Generate(
                new Asn1SignatureFactory("SHA256withRSA", deltaKeyPair.Private, Random));

            // Generate a self-signed Base Certificate
            var baseCertBuilder = new X509V3CertificateGenerator();
            baseCertBuilder.SetIssuerDN(new X509Name("CN=Issuer"));
            baseCertBuilder.SetSerialNumber(BigInteger.Two);
            baseCertBuilder.SetNotBefore(DateTime.UtcNow);
            baseCertBuilder.SetNotAfter(DateTime.UtcNow.AddYears(1));
            baseCertBuilder.SetSubjectDN(new X509Name("CN=Subject"));
            baseCertBuilder.SetPublicKey(baseKeyPair.Public);

            // Create Delta Extension
            Extension deltaExt = DeltaCertificateTool.CreateDeltaCertificateExtension(isCritical: false, deltaCert);
            // Add Delta Extension to Base Certificate
            baseCertBuilder.AddExtension(deltaExt);
            // Build Base Certificate
            var baseCert = baseCertBuilder.Generate(
                new Asn1SignatureFactory("SHA256withRSA", baseKeyPair.Private, Random));
        }

        [Test]
        public void DeltaCertWithExtensions()
        {
            X509Name subject = new X509Name("CN=Test Subject");

            var kpgA = GeneratorUtilities.GetKeyPairGenerator("RSA");
            kpgA.Init(new KeyGenerationParameters(Random, 2048));

            var kpA = kpgA.GenerateKeyPair();

            var kpgB = GeneratorUtilities.GetKeyPairGenerator("EC");
            kpgB.Init(new ECKeyGenerationParameters(SecObjectIdentifiers.SecP256r1, Random));

            var kpB = kpgB.GenerateKeyPair();

            var signerA = new Asn1SignatureFactory("SHA256withRSA", kpA.Private);

            DateTime notBefore = DateTime.UtcNow.AddSeconds(-5);
            DateTime notAfter = DateTime.UtcNow.AddHours(1);

            X509V3CertificateGenerator bldr = new X509V3CertificateGenerator();
            bldr.SetIssuerDN(new X509Name("CN=Chameleon CA 1"));
            bldr.SetSerialNumber(BigInteger.ValueOf(DateTimeUtilities.CurrentUnixMs()));
            bldr.SetNotBefore(notBefore);
            bldr.SetNotAfter(notAfter);
            bldr.SetSubjectDN(subject);
            bldr.SetPublicKey(kpA.Public);

            bldr.AddExtension(X509Extensions.BasicConstraints, true, new BasicConstraints(false));

            var signerB = new Asn1SignatureFactory("SHA256withECDSA", kpB.Private);

            X509V3CertificateGenerator deltaBldr = new X509V3CertificateGenerator();
            deltaBldr.SetIssuerDN(new X509Name("CN=Chameleon CA 2"));
            deltaBldr.SetSerialNumber(BigInteger.ValueOf(DateTimeUtilities.CurrentUnixMs()));
            deltaBldr.SetNotBefore(notBefore);
            deltaBldr.SetNotAfter(notAfter);
            deltaBldr.SetSubjectDN(subject);
            deltaBldr.SetPublicKey(kpB.Public);

            deltaBldr.AddExtension(X509Extensions.BasicConstraints, true, new BasicConstraints(false));

            X509Certificate deltaCert = deltaBldr.Generate(signerB);

            Extension deltaExt = DeltaCertificateTool.CreateDeltaCertificateExtension(isCritical: false, deltaCert);
            bldr.AddExtension(deltaExt);

            X509Certificate chameleonCert = bldr.Generate(signerA);

            Assert.True(chameleonCert.IsSignatureValid(kpA.Public));

            DeltaCertificateDescriptor deltaCertDesc = DeltaCertificateDescriptor.FromExtensions(
                chameleonCert.CertificateStructure.Extensions);

            Assert.Null(deltaCertDesc.Extensions);
            Assert.Null(deltaCertDesc.Subject);
            Assert.NotNull(deltaCertDesc.Issuer);

            X509Certificate exDeltaCert = DeltaCertificateTool.ExtractDeltaCertificate(chameleonCert);

            Assert.True(exDeltaCert.IsSignatureValid(kpB.Public));
        }

        [Test]
        public void CheckCreationAltCertWithDelta()
        {
            var kpgB = GeneratorUtilities.GetKeyPairGenerator("EC");
            kpgB.Init(new ECKeyGenerationParameters(SecObjectIdentifiers.SecP256r1, Random));

            var kpB = kpgB.GenerateKeyPair();

            var kpGen = GeneratorUtilities.GetKeyPairGenerator("ML-DSA");
            kpGen.Init(new MLDsaKeyGenerationParameters(Random, MLDsaParameters.ml_dsa_44));

            var kp = kpGen.GenerateKeyPair();

            var privKey = kp.Private;
            var pubKey = kp.Public;

            var ecKpGen = GeneratorUtilities.GetKeyPairGenerator("EC");
            ecKpGen.Init(new ECKeyGenerationParameters(SecObjectIdentifiers.SecP256r1, Random));

            var ecKp = ecKpGen.GenerateKeyPair();

            var ecPrivKey = ecKp.Private;
            var ecPubKey = ecKp.Public;

            DateTime notBefore = DateTime.UtcNow.AddSeconds(-5);
            DateTime notAfter = DateTime.UtcNow.AddHours(1);

            //
            // distinguished name table.
            //
            var issuer = new X509Name("CN=Chameleon Base Issuer");
            var subject = new X509Name("CN=Chameleon Base Subject");

            //
            // create base certificate - version 3
            //
            var sigGen = new Asn1SignatureFactory("SHA256withECDSA", ecPrivKey);

            var altSigGen = new Asn1SignatureFactory("ML-DSA-44", privKey);

            X509V3CertificateGenerator certGen = new X509V3CertificateGenerator();
            certGen.SetIssuerDN(issuer);
            certGen.SetSerialNumber(BigInteger.One);
            certGen.SetNotBefore(notBefore);
            certGen.SetNotAfter(notAfter);
            certGen.SetSubjectDN(subject);
            certGen.SetPublicKey(ecPubKey);

            certGen.AddExtension(X509Extensions.BasicConstraints, true, new BasicConstraints(false));
            certGen.AddExtension(X509Extensions.SubjectAltPublicKeyInfo, false,
                SubjectAltPublicKeyInfo.GetInstance(
                    SubjectPublicKeyInfoFactory.CreateSubjectPublicKeyInfo(kp.Public).GetEncoded()));

            var signerB = new Asn1SignatureFactory("SHA256withECDSA", kpB.Private);

            X509V3CertificateGenerator deltaBldr = new X509V3CertificateGenerator();
            deltaBldr.SetIssuerDN(new X509Name("CN=Chameleon CA 2"));
            deltaBldr.SetSerialNumber(BigInteger.ValueOf(DateTimeUtilities.CurrentUnixMs()));
            deltaBldr.SetNotBefore(notBefore);
            deltaBldr.SetNotAfter(notAfter);
            deltaBldr.SetSubjectDN(subject);
            deltaBldr.SetPublicKey(kpB.Public);

            deltaBldr.AddExtension(X509Extensions.BasicConstraints, true, new BasicConstraints(false));
            deltaBldr.AddExtension(X509Extensions.SubjectAltPublicKeyInfo, false,
                SubjectAltPublicKeyInfo.GetInstance(
                    SubjectPublicKeyInfoFactory.CreateSubjectPublicKeyInfo(kp.Public).GetEncoded()));

            X509Certificate deltaCert = deltaBldr.Generate(signerB, false, altSigGen);

            Assert.True(deltaCert.IsSignatureValid(kpB.Public));

            Extension deltaExt = DeltaCertificateTool.CreateDeltaCertificateExtension(isCritical: false, deltaCert);
            certGen.AddExtension(deltaExt);

            X509Certificate cert = certGen.Generate(sigGen, false, altSigGen);

            //
            // copy certificate           exDeltaCert
            //

            cert.CheckValidity();

            cert.Verify(cert.GetPublicKey());

            // check encoded works
            cert.GetEncoded();

            Assert.True(cert.IsAlternativeSignatureValid(pubKey), "alt sig value wrong");

            X509Certificate exDeltaCert = DeltaCertificateTool.ExtractDeltaCertificate(cert);

            Assert.True(exDeltaCert.IsSignatureValid(kpB.Public));
            Assert.True(exDeltaCert.IsAlternativeSignatureValid(pubKey));

            Assert.True(cert.IsSignatureValid(ecPubKey));
            Assert.True(cert.IsAlternativeSignatureValid(pubKey));
        }

        [Test]
        public void DraftMLDsaRoot()
        {
            X509Certificate baseCert = ReadCert("ml_dsa_root.pem");

            Assert.True(baseCert.IsSignatureValid(baseCert.GetPublicKey()));

            X509Certificate deltaCert = DeltaCertificateTool.ExtractDeltaCertificate(baseCert);

            Assert.True(deltaCert.IsSignatureValid(deltaCert.GetPublicKey()));

            X509Certificate extCert = ReadCert("ec_dsa_root.pem");

            Assert.True(extCert.Equals(deltaCert));
        }

        [Test]
        public void DraftMLDsaEndEntity()
        {
            X509Certificate rootCert = ReadCert("ml_dsa_root.pem");
            X509Certificate ecRootCert = ReadCert("ec_dsa_root.pem");
            X509Certificate baseCert = ReadCert("ec_dsa_ee.pem");

            Assert.True(baseCert.IsSignatureValid(ecRootCert.GetPublicKey()));

            X509Certificate deltaCert = DeltaCertificateTool.ExtractDeltaCertificate(baseCert);

            Assert.True(deltaCert.IsSignatureValid(rootCert.GetPublicKey()));

            X509Certificate extCert = ReadCert("ml_dsa_ee.pem");

            Assert.True(extCert.Equals(deltaCert));
        }

        [Test]
        public void DraftDualUseECDsaEndEntity()
        {
            X509Certificate ecRootCert = ReadCert("ec_dsa_root.pem");
            X509Certificate baseCert = ReadCert("ec_dsa_dual_xch_ee.pem");

            Assert.True(baseCert.IsSignatureValid(ecRootCert.GetPublicKey()));

            X509Certificate deltaCert = DeltaCertificateTool.ExtractDeltaCertificate(baseCert);

            X509Certificate extCert = ReadCert("ec_dsa_dual_sig_ee.pem");

            Assert.True(extCert.Equals(deltaCert));

            Assert.True(deltaCert.IsSignatureValid(ecRootCert.GetPublicKey()));
        }

        private static X509Certificate ReadCert(string name)
        {
            using (var pem = new PemReader(new StreamReader(SimpleTest.GetTestDataAsStream("cert.delta." + name))))
            {
                return (X509Certificate)pem.ReadObject();
            }
        }
    }
}
