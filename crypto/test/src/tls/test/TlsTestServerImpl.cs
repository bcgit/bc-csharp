using System;
using System.Collections.Generic;

using Org.BouncyCastle.Tls.Crypto;

namespace Org.BouncyCastle.Tls.Tests
{
    /// <summary>The server end of the generated <see cref="TlsTestSuite"/> cases, driven by a
    /// <see cref="TlsTestConfig"/>.</summary>
    internal class TlsTestServerImpl
        : MockTlsServer
    {
        protected readonly TlsTestConfig m_config;

        internal TlsTestServerImpl(TlsTestConfig config)
            : base(TlsTestSuite.GetCrypto(config))
        {
            this.m_config = config;

            ProtocolNames = null;
            SupportedVersions = config.serverSupportedVersions;
        }

        public override ProtocolVersion GetServerVersion() =>
            m_config.serverNegotiateVersion ?? base.GetServerVersion();

        public override CertificateRequest GetCertificateRequest()
        {
            if (m_config.serverCertReq == TlsTestConfig.SERVER_CERT_REQ_NONE)
                return null;

            return TlsTestUtilities.CreateCertificateRequest(m_context, m_config.serverCertReqSigAlgs);
        }

        public override void NotifyClientCertificate(Certificate clientCertificate)
        {
            bool isEmpty = (clientCertificate == null || clientCertificate.IsEmpty);

            if (isEmpty != (m_config.clientAuth == TlsTestConfig.CLIENT_AUTH_NONE))
                throw new InvalidOperationException();

            if (isEmpty && (m_config.serverCertReq == TlsTestConfig.SERVER_CERT_REQ_MANDATORY))
            {
                short alertDescription = TlsUtilities.IsTlsV13(m_context)
                    ?   AlertDescription.certificate_required
                    :   AlertDescription.handshake_failure;

                throw new TlsFatalAlert(alertDescription);
            }

            TlsTestUtilities.VerifyClientCertificate(m_context, clientCertificate,
                TlsTestUtilities.TrustedClientCertResources, m_config.serverCheckSigAlgOfClientCerts);
        }

        protected override IList<SignatureAndHashAlgorithm> GetServerSigAlgs()
        {
            if (TlsUtilities.IsTlsV12(m_context) && m_config.serverAuthSigAlg != null)
                return TlsUtilities.VectorOfOne(m_config.serverAuthSigAlg);

            return base.GetServerSigAlgs();
        }

        protected override TlsCredentialedSigner GetDsaSignerCredentials() =>
            LoadSignerCredentials(SignatureAlgorithm.dsa);

        protected override TlsCredentialedSigner GetECDsaSignerCredentials()
        {
            // TODO[RFC 8422] Code should choose based on client's supported sig algs?
            return LoadSignerCredentials(SignatureAlgorithm.ecdsa);
            //return LoadSignerCredentials(SignatureAlgorithm.ed25519);
            //return LoadSignerCredentials(SignatureAlgorithm.ed448);
        }

        private TlsCredentialedSigner LoadSignerCredentials(short signatureAlgorithm) =>
            TlsTestUtilities.LoadSignerCredentialsServer(m_context, GetServerSigAlgs(), signatureAlgorithm);
    }
}
