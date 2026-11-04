using System;

using NUnit.Framework;

using Org.BouncyCastle.Asn1;
using Org.BouncyCastle.Asn1.X509;
using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Crypto.Operators;
using Org.BouncyCastle.Math;
using Org.BouncyCastle.X509;

namespace Org.BouncyCastle.Tsp.Tests
{
    [TestFixture]
    public class TspUtilTest
    {
        private static readonly AsymmetricCipherKeyPair KeyPair = TspTestUtil.MakeKeyPair();

        [Test]
        public void ValidateCertificateCriticalEku()
        {
            TspUtil.ValidateCertificate(MakeTsaCertificate(ekuCritical: true));
        }

        [Test]
        public void ValidateCertificateNonCriticalEku()
        {
            var cert = MakeTsaCertificate(ekuCritical: false);

            Assert.Throws<TspValidationException>(() => TspUtil.ValidateCertificate(cert));
        }

        private static X509Certificate MakeTsaCertificate(bool ekuCritical)
        {
            var name = new X509Name("CN=Test TSA");

            var gen = new X509V3CertificateGenerator();
            gen.SetSerialNumber(BigInteger.One);
            gen.SetIssuerDN(name);
            gen.SetNotBefore(DateTime.UtcNow.AddDays(-1));
            gen.SetNotAfter(DateTime.UtcNow.AddDays(1));
            gen.SetSubjectDN(name);
            gen.SetPublicKey(KeyPair.Public);
            gen.AddExtension(X509Extensions.ExtendedKeyUsage, ekuCritical,
                ExtendedKeyUsage.GetInstance(new DerSequence(KeyPurposeID.id_kp_timeStamping)));

            return gen.Generate(new Asn1SignatureFactory("SHA256WithRSAEncryption", KeyPair.Private));
        }
    }
}
