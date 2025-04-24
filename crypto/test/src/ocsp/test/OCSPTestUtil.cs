using System;
using System.Threading;

using Org.BouncyCastle.Asn1.X509;
using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Crypto.Operators;
using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.Math;
using Org.BouncyCastle.Security;
using Org.BouncyCastle.X509;
using Org.BouncyCastle.X509.Extension;

namespace Org.BouncyCastle.Ocsp.Tests
{
    public class OcspTestUtil
    {
        public static readonly SecureRandom Random = new SecureRandom();

        internal static IAsymmetricCipherKeyPairGenerator kpg, ecKpg;

        internal static int serialNumber;

        public static readonly bool Debug = true;

        private static int NextSerialNumber() => Interlocked.Increment(ref serialNumber);

        static OcspTestUtil()
        {
            kpg = GeneratorUtilities.GetKeyPairGenerator("RSA");
            kpg.Init(new RsaKeyGenerationParameters(BigInteger.ValueOf(0x10001), Random, 1024, 25));

            ecKpg = GeneratorUtilities.GetKeyPairGenerator("ECDSA");
            ecKpg.Init(new KeyGenerationParameters(Random, 192));

            serialNumber = 0;
        }

        public static AsymmetricCipherKeyPair MakeKeyPair()
        {
            return kpg.GenerateKeyPair();
        }

        public static AsymmetricCipherKeyPair MakeECKeyPair()
        {
            return ecKpg.GenerateKeyPair();
        }

        public static X509Certificate MakeCertificate(AsymmetricCipherKeyPair _subKP,
            string _subDN, AsymmetricCipherKeyPair _issKP, string _issDN)
        {
            return MakeCertificate(_subKP, _subDN, _issKP, _issDN, false);
        }

        public static X509Certificate MakeECDsaCertificate(AsymmetricCipherKeyPair _subKP,
            string _subDN, AsymmetricCipherKeyPair _issKP, string _issDN)
        {
            return MakeECDsaCertificate(_subKP, _subDN, _issKP, _issDN, false);
        }

        public static X509Certificate MakeCACertificate(AsymmetricCipherKeyPair _subKP,
            string _subDN, AsymmetricCipherKeyPair _issKP, string _issDN)
        {

            return MakeCertificate(_subKP, _subDN, _issKP, _issDN, true);
        }

        public static X509Certificate MakeCertificate(AsymmetricCipherKeyPair _subKP,
            string _subDN, AsymmetricCipherKeyPair _issKP, string _issDN, bool _ca)
        {
            return MakeCertificate(_subKP, _subDN, _issKP, _issDN, "MD5withRSA", _ca);
        }

        public static X509Certificate MakeECDsaCertificate(AsymmetricCipherKeyPair _subKP,
            string _subDN, AsymmetricCipherKeyPair _issKP, string _issDN, bool _ca)
        {
            return MakeCertificate(_subKP, _subDN, _issKP, _issDN, "SHA1WithECDSA", _ca);
        }

        public static X509Certificate MakeCertificate(AsymmetricCipherKeyPair _subKP,
            string _subDN, AsymmetricCipherKeyPair _issKP, string _issDN, string algorithm, bool _ca)
        {
            AsymmetricKeyParameter _subPub = _subKP.Public;
            AsymmetricKeyParameter _issPriv = _issKP.Private;
            AsymmetricKeyParameter _issPub = _issKP.Public;

            X509V3CertificateGenerator _v3CertGen = new X509V3CertificateGenerator();

            _v3CertGen.Reset();
            _v3CertGen.SetSerialNumber(AllocateSerialNumber());
            _v3CertGen.SetIssuerDN(new X509Name(_issDN));
            _v3CertGen.SetNotBefore(DateTime.UtcNow);
            _v3CertGen.SetNotAfter(DateTime.UtcNow.AddDays(100));
            _v3CertGen.SetSubjectDN(new X509Name(_subDN));
            _v3CertGen.SetPublicKey(_subPub);

            _v3CertGen.AddExtension(X509Extensions.SubjectKeyIdentifier, false, CreateSubjectKeyID(_subPub));

            _v3CertGen.AddExtension(X509Extensions.AuthorityKeyIdentifier, false, CreateAuthorityKeyID(_issPub));

            _v3CertGen.AddExtension(X509Extensions.BasicConstraints, false,
                new BasicConstraints(_ca));

            X509Certificate _cert = _v3CertGen.Generate(new Asn1SignatureFactory(algorithm, _issPriv, Random));

            _cert.CheckValidity(DateTime.UtcNow);
            _cert.Verify(_issPub);

            return _cert;
        }

        /*
         *
         * INTERNAL METHODS
         *
         */

        private static AuthorityKeyIdentifier CreateAuthorityKeyID(AsymmetricKeyParameter publicKey) =>
            X509ExtensionUtilities.CreateAuthorityKeyIdentifier(publicKey);

        private static SubjectKeyIdentifier CreateSubjectKeyID(AsymmetricKeyParameter publicKey) =>
            X509ExtensionUtilities.CreateSubjectKeyIdentifier(publicKey);

        private static BigInteger AllocateSerialNumber() => BigInteger.ValueOf(NextSerialNumber());
    }
}
