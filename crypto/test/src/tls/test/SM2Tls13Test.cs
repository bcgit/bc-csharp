using System;

using NUnit.Framework;

using Org.BouncyCastle.Asn1.X509;
using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Crypto.Operators;
using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.Math;
using Org.BouncyCastle.Security;
using Org.BouncyCastle.Tls.Crypto;
using Org.BouncyCastle.Tls.Crypto.Impl.BC;
using Org.BouncyCastle.X509;
using Org.BouncyCastle.X509.Extension;

namespace Org.BouncyCastle.Tls.Tests
{
    /// <summary>
    /// Test for TLS 1.3 with ShangMi (SM) cipher suites as defined in RFC 8998.
    /// </summary>
    [TestFixture]
    public class SM2Tls13Test
    {
        [Test]
        public void SM2SignerAndVerifier_BC_BC()
        {
            byte[] certificateEncoding;
            byte[] data;
            byte[] signature;

            {
                BcTlsCrypto crypto = new BcTlsCrypto(new SecureRandom());

                AsymmetricCipherKeyPair keyPair = GenerateSM2KeyPair(crypto);
                ECPrivateKeyParameters privateKey = (ECPrivateKeyParameters)keyPair.Private;

                var tlsCertificate = CreateBCCertificate(keyPair, crypto);
                certificateEncoding = tlsCertificate.GetEncoded();
                Certificate certChain = new Certificate(new TlsCertificate[]{ tlsCertificate });

                TlsCryptoParameters cryptoParams = new TestTlsCryptoParameters(ProtocolVersion.TLSv13);

                var signer = new BcDefaultTlsCredentialedSigner(cryptoParams, crypto, privateKey, certChain,
                    SignatureAndHashAlgorithm.sm2sig_sm3);

                data = SecureRandom.GetNextBytes(crypto.SecureRandom, 64);

                TlsStreamSigner streamSigner = signer.GetStreamSigner();
                using (var signerOutput = streamSigner.Stream)
                {
                    signerOutput.Write(data, 0, data.Length);
                }
                signature = streamSigner.GetSignature();

                Assert.NotNull(signature);
                Assert.True(signature.Length > 0, "Signature should be non‑empty");
            }

            {
                BcTlsCrypto crypto = new BcTlsCrypto(new SecureRandom());

                TlsCertificate tlsCertificate = crypto.CreateCertificate(certificateEncoding);

                Tls13Verifier verifier = tlsCertificate.CreateVerifier(SignatureScheme.sm2sig_sm3);
                using (var verifierOutput = verifier.Stream)
                {
                    verifierOutput.Write(data, 0, data.Length);
                }
                Assert.True(verifier.VerifySignature(signature));
            }
        }

        private static BcTlsCertificate CreateBCCertificate(AsymmetricCipherKeyPair keyPair, BcTlsCrypto crypto)
        {
            DateTime utcNow = DateTime.UtcNow;
            X509Name subject = new X509Name("CN=SM2 Test Certificate");
            ECPublicKeyParameters pubKey = (ECPublicKeyParameters)keyPair.Public;
            SubjectPublicKeyInfo pubKeyInfo = SubjectPublicKeyInfoFactory.CreateSubjectPublicKeyInfo(pubKey);
            BigInteger serial = BigInteger.ValueOf(utcNow.Ticks);

            X509V3CertificateGenerator certGen = new X509V3CertificateGenerator();
            certGen.SetIssuerDN(subject);
            certGen.SetNotAfter(utcNow.AddDays(1));
            certGen.SetNotBefore(utcNow.AddDays(-1));
            certGen.SetSerialNumber(serial);
            certGen.SetSubjectDN(subject);
            certGen.SetSubjectPublicKeyInfo(pubKeyInfo);

            certGen.AddExtension(X509Extensions.SubjectKeyIdentifier, false,
                X509ExtensionUtilities.CreateSubjectKeyIdentifier(pubKeyInfo));
            certGen.AddExtension(X509Extensions.AuthorityKeyIdentifier, false,
                X509ExtensionUtilities.CreateAuthorityKeyIdentifier(pubKeyInfo));
            certGen.AddExtension(X509Extensions.BasicConstraints, true,
                new BasicConstraints(true));

            var cert = certGen.Generate(new Asn1SignatureFactory("SM3withSM2", keyPair.Private, crypto.SecureRandom));

            return new BcTlsCertificate(crypto, cert.CertificateStructure);
        }

        private static AsymmetricCipherKeyPair GenerateSM2KeyPair(BcTlsCrypto crypto) =>
            new BcTlsECDomain(crypto, new TlsECConfig(NamedGroup.curveSM2)).GenerateKeyPair();

        private class TestTlsCryptoParameters
            : TlsCryptoParameters
        {
            private readonly ProtocolVersion m_serverVersion;

            internal TestTlsCryptoParameters(ProtocolVersion serverVersion)
                : base(null)
            {
                m_serverVersion = serverVersion;
            }

            public override ProtocolVersion ServerVersion => m_serverVersion;
        }
    }
}
