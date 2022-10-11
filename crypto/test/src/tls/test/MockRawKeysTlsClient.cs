using System;
using System.Collections.Generic;

using NUnit.Framework;

using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.Tls.Crypto;
using Org.BouncyCastle.Tls.Crypto.Impl.BC;
using Org.BouncyCastle.X509;

namespace Org.BouncyCastle.Tls.Tests
{
    internal class MockRawKeysTlsClient
        : DefaultTlsClient
    {
        private short m_serverCertType;
        private short m_clientCertType;
        private short[] m_offerServerCertTypes;
        private short[] m_offerClientCertTypes;
        private ProtocolVersion m_tlsVersion;
        private Ed25519PrivateKeyParameters m_privateKey;

        internal MockRawKeysTlsClient(short serverCertType, short clientCertType, short[] offerServerCertTypes,
            short[] offerClientCertTypes, Ed25519PrivateKeyParameters privateKey, ProtocolVersion tlsVersion)
            : base(new BcTlsCrypto())
        {
            m_serverCertType = serverCertType;
            m_clientCertType = clientCertType;
            m_offerServerCertTypes = offerServerCertTypes;
            m_offerClientCertTypes = offerClientCertTypes;
            m_privateKey = privateKey;
            m_tlsVersion = tlsVersion;
        }

        protected override ProtocolVersion[] GetSupportedVersions()
        {
            return new ProtocolVersion[]{ m_tlsVersion };
        }

        protected override int[] GetSupportedCipherSuites()
        {
            return TlsUtilities.IsTlsV13(m_tlsVersion)
                ?   new int[]{ CipherSuite.TLS_AES_128_GCM_SHA256 }
                :   new int[]{ CipherSuite.TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256 };
        }

        protected override short[] GetAllowedClientCertificateTypes() => m_offerClientCertTypes;

        protected override short[] GetAllowedServerCertificateTypes() => m_offerServerCertTypes;

        protected override CertificateStatusRequest GetCertificateStatusRequest()
        {
            return m_serverCertType == CertificateType.RawPublicKey ? null : base.GetCertificateStatusRequest();
        }

        protected override IList<CertificateStatusRequestItemV2> GetMultiCertStatusRequest()
        {
            return m_serverCertType == CertificateType.RawPublicKey ? null : base.GetMultiCertStatusRequest();
        }

        public override TlsAuthentication GetAuthentication()
        {
            return new MyTlsAuthentication(this);
        }

        internal class MyTlsAuthentication
            : TlsAuthentication
        {
            private readonly MockRawKeysTlsClient m_outer;
            private TlsCredentialedSigner m_credentials;

            internal MyTlsAuthentication(MockRawKeysTlsClient outer)
            {
                m_outer = outer;
            }

            public void NotifyServerCertificate(TlsServerCertificate serverCertificate)
            {
                Assert.AreEqual(m_outer.m_serverCertType, serverCertificate.Certificate.CertificateType,
                    "wrong certificate type from server");
            }

            public TlsCredentials GetClientCredentials(CertificateRequest certificateRequest)
            {
                var clientCertType = m_outer.m_clientCertType;
                var context = m_outer.m_context;
                var crypto = (BcTlsCrypto)m_outer.Crypto;
                var privateKey = m_outer.m_privateKey;

                if (clientCertType < 0)
                {
                    Assert.Fail("should not have received a certificate request");
                }

                Assert.AreEqual(clientCertType, context.SecurityParameters.ClientCertificateType,
                    "wrong certificate type in request");

                if (m_credentials == null)
                {
                    switch (clientCertType)
                    {
                    case CertificateType.X509:
                        m_credentials = TlsTestUtilities.LoadSignerCredentials(context,
                            certificateRequest.SupportedSignatureAlgorithms, SignatureAlgorithm.ed25519,
                            "x509-client-ed25519.pem", "x509-client-key-ed25519.pem");
                        break;
                    case CertificateType.RawPublicKey:
                        TlsCertificate rawKeyCert = new BcTlsRawKeyCertificate(crypto,
                            SubjectPublicKeyInfoFactory.CreateSubjectPublicKeyInfo(privateKey.GeneratePublicKey()));
                        Certificate cert = new Certificate(CertificateType.RawPublicKey,
                            TlsUtilities.IsTlsV13(context) ? TlsUtilities.EmptyBytes : null,
                            new CertificateEntry[]{ new CertificateEntry(rawKeyCert, null) });
                        m_credentials = new BcDefaultTlsCredentialedSigner(new TlsCryptoParameters(context),
                            crypto, privateKey, cert, SignatureAndHashAlgorithm.ed25519);
                        break;
                    default:
                        throw new ArgumentException("Only supports X509 and raw keys");
                    }
                }

                return m_credentials;
            }
        };
    }
}
