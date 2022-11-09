using System;
using System.Collections.Generic;

using NUnit.Framework;

using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.Tls.Crypto;
using Org.BouncyCastle.Tls.Crypto.Impl.BC;
using Org.BouncyCastle.X509;

namespace Org.BouncyCastle.Tls.Tests
{
    internal class MockRawKeysTlsServer
        : DefaultTlsServer
    {
        private short m_serverCertType;
        private short m_clientCertType;
        private short[] m_allowedClientCertTypes;
        private Ed25519PrivateKeyParameters m_privateKey;
        private ProtocolVersion m_tlsVersion;
        private TlsCredentialedSigner m_credentials;

        internal IDictionary<int, byte[]> m_receivedClientExtensions;

        internal MockRawKeysTlsServer(short serverCertType, short clientCertType, short[] allowedClientCertTypes,
            Ed25519PrivateKeyParameters privateKey, ProtocolVersion tlsVersion)
            : base(new BcTlsCrypto())
        {
            m_serverCertType = serverCertType;
            m_clientCertType = clientCertType;
            m_allowedClientCertTypes = allowedClientCertTypes;
            m_privateKey = privateKey;
            m_tlsVersion = tlsVersion;
        }

        public override TlsCredentials GetCredentials()
        {
            /*
             * TODO[tls13] Should really be finding the first client-supported signature scheme that the
             * server also supports and has credentials for.
             */
            if (TlsUtilities.IsTlsV13(m_context))
                return GetECDsaSignerCredentials();

            return base.GetCredentials();
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

        public override void ProcessClientExtensions(IDictionary<int, byte[]> clientExtensions)
        {
            m_receivedClientExtensions = clientExtensions;

            base.ProcessClientExtensions(clientExtensions);
        }

        protected override TlsCredentialedSigner GetECDsaSignerCredentials()
        {
            if (m_credentials == null)
            {
                var crypto = (BcTlsCrypto)Crypto;

                switch (m_serverCertType)
                {
                case CertificateType.X509:
                    m_credentials = TlsTestUtilities.LoadSignerCredentials(m_context,
                        m_context.SecurityParameters.ClientSigAlgs, SignatureAlgorithm.ed25519,
                        "x509-client-ed25519.pem", "x509-client-key-ed25519.pem");
                    break;
                case CertificateType.RawPublicKey:
                    TlsCertificate rawKeyCert = new BcTlsRawKeyCertificate(crypto,
                        SubjectPublicKeyInfoFactory.CreateSubjectPublicKeyInfo(m_privateKey.GeneratePublicKey()));
                    Certificate cert = new Certificate(CertificateType.RawPublicKey,
                        TlsUtilities.IsTlsV13(m_context) ? TlsUtilities.EmptyBytes : null,
                        new CertificateEntry[]{ new CertificateEntry(rawKeyCert, null) });
                    m_credentials = new BcDefaultTlsCredentialedSigner(new TlsCryptoParameters(m_context),
                        crypto, m_privateKey, cert, SignatureAndHashAlgorithm.ed25519);
                    break;
                default:
                    throw new ArgumentException("Only supports X509 and raw keys");
                }
            }

            return m_credentials;
        }

        protected override short[] GetAllowedClientCertificateTypes() => m_allowedClientCertTypes;

        protected override bool AllowCertificateStatus()
        {
            return m_serverCertType == CertificateType.RawPublicKey ? false : base.AllowCertificateStatus();
        }

        protected override bool AllowMultiCertStatus()
        {
            return m_serverCertType == CertificateType.RawPublicKey ? false : base.AllowMultiCertStatus();
        }

        public override CertificateRequest GetCertificateRequest()
        {
            if (m_clientCertType < 0)
                return null;

            short[] certificateTypes = new short[]{ ClientCertificateType.ecdsa_sign };

            IList<SignatureAndHashAlgorithm> serverSigAlgs = null;
            if (TlsUtilities.IsSignatureAlgorithmsExtensionAllowed(m_context.ServerVersion))
            {
                serverSigAlgs = TlsUtilities.GetDefaultSupportedSignatureAlgorithms(m_context);
            }

            return TlsUtilities.IsTlsV13(m_tlsVersion)
                ?   new CertificateRequest(TlsUtilities.EmptyBytes, serverSigAlgs, null, null)
                :   new CertificateRequest(certificateTypes, serverSigAlgs, null);
        }

        public override void NotifyClientCertificate(Certificate clientCertificate)
        {
            Assert.AreEqual(m_clientCertType, clientCertificate.CertificateType,
                "client certificate is the wrong type");
        }
    }
}
