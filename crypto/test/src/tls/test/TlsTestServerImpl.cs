using System;
using System.Collections.Generic;
using System.IO;

using Org.BouncyCastle.Asn1.X509;
using Org.BouncyCastle.Tls.Crypto;
using Org.BouncyCastle.Utilities.Encoders;

namespace Org.BouncyCastle.Tls.Tests
{
    internal class TlsTestServerImpl
        : DefaultTlsServer
    {
        private static readonly int[] TestCipherSuites = new int[]
        {
            /*
             * TLS 1.3
             */
            CipherSuite.TLS_AES_256_GCM_SHA384,
            CipherSuite.TLS_AES_128_GCM_SHA256,
            CipherSuite.TLS_CHACHA20_POLY1305_SHA256,

            /*
             * pre-TLS 1.3
             */
            CipherSuite.TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
            CipherSuite.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
            CipherSuite.TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256,
            CipherSuite.TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA384,
            CipherSuite.TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA256,
            CipherSuite.TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA,
            CipherSuite.TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA,
            CipherSuite.TLS_DHE_RSA_WITH_AES_256_GCM_SHA384,
            CipherSuite.TLS_DHE_RSA_WITH_AES_128_GCM_SHA256,
            CipherSuite.TLS_DHE_RSA_WITH_CHACHA20_POLY1305_SHA256,
            CipherSuite.TLS_DHE_RSA_WITH_AES_256_CBC_SHA256,
            CipherSuite.TLS_DHE_RSA_WITH_AES_128_CBC_SHA256,
            CipherSuite.TLS_DHE_RSA_WITH_AES_256_CBC_SHA,
            CipherSuite.TLS_DHE_RSA_WITH_AES_128_CBC_SHA,
            CipherSuite.TLS_RSA_WITH_AES_256_GCM_SHA384,
            CipherSuite.TLS_RSA_WITH_AES_128_GCM_SHA256,
            CipherSuite.TLS_RSA_WITH_AES_256_CBC_SHA256,
            CipherSuite.TLS_RSA_WITH_AES_128_CBC_SHA256,
            CipherSuite.TLS_RSA_WITH_AES_256_CBC_SHA,
            CipherSuite.TLS_RSA_WITH_AES_128_CBC_SHA,
        };

        protected readonly TlsTestConfig m_config;

        protected int m_firstFatalAlertConnectionEnd = -1;
        protected short m_firstFatalAlertDescription = -1;

        internal byte[] m_tlsKeyingMaterial1 = null;
        internal byte[] m_tlsKeyingMaterial2 = null;
        internal byte[] m_tlsServerEndPoint = null;
        internal byte[] m_tlsUnique = null;

        internal TlsTestServerImpl(TlsTestConfig config)
            : base(TlsTestSuite.GetCrypto(config))
        {
            this.m_config = config;
        }

        internal int FirstFatalAlertConnectionEnd
        {
            get { return m_firstFatalAlertConnectionEnd; }
        }

        internal short FirstFatalAlertDescription
        {
            get { return m_firstFatalAlertDescription; }
        }

        public override TlsCredentials GetCredentials()
        {
            /*
             * TODO[tls13] Should really be finding the first client-supported signature scheme that the
             * server also supports and has credentials for.
             */
            if (TlsUtilities.IsTlsV13(m_context))
            {
                return GetRsaSignerCredentials();
            }

            return base.GetCredentials();
        }

        public override void NotifyAlertRaised(short alertLevel, short alertDescription, string message,
            Exception cause)
        {
            if (alertLevel == AlertLevel.fatal && m_firstFatalAlertConnectionEnd == -1)
            {
                m_firstFatalAlertConnectionEnd = ConnectionEnd.server;
                m_firstFatalAlertDescription = alertDescription;
            }

            if (TlsTestConfig.Debug)
            {
                TextWriter output = (alertLevel == AlertLevel.fatal) ? Console.Error : Console.Out;
                output.WriteLine("TLS server raised alert: " + AlertLevel.GetText(alertLevel)
                    + ", " + AlertDescription.GetText(alertDescription));
                if (message != null)
                {
                    output.WriteLine("> " + message);
                }
                if (cause != null)
                {
                    output.WriteLine(cause);
                }
            }
        }

        public override void NotifyAlertReceived(short alertLevel, short alertDescription)
        {
            if (alertLevel == AlertLevel.fatal && m_firstFatalAlertConnectionEnd == -1)
            {
                m_firstFatalAlertConnectionEnd = ConnectionEnd.client;
                m_firstFatalAlertDescription = alertDescription;
            }

            if (TlsTestConfig.Debug)
            {
                TextWriter output = (alertLevel == AlertLevel.fatal) ? Console.Error : Console.Out;
                output.WriteLine("TLS server received alert: " + AlertLevel.GetText(alertLevel)
                    + ", " + AlertDescription.GetText(alertDescription));
            }
        }

        public override void NotifyHandshakeComplete()
        {
            base.NotifyHandshakeComplete();

            SecurityParameters securityParameters = m_context.SecurityParameters;
            if (securityParameters.IsExtendedMasterSecret)
            {
                m_tlsKeyingMaterial1 = m_context.ExportKeyingMaterial("BC_TLS_TESTS_1", null, 16);
                m_tlsKeyingMaterial2 = m_context.ExportKeyingMaterial("BC_TLS_TESTS_2", new byte[8], 16);
            }

            m_tlsServerEndPoint = m_context.ExportChannelBinding(ChannelBinding.tls_server_end_point);
            m_tlsUnique = m_context.ExportChannelBinding(ChannelBinding.tls_unique);

            if (TlsTestConfig.Debug)
            {
                int negotiatedGroup = securityParameters.NegotiatedGroup;
                if (negotiatedGroup >= 0)
                {
                    Console.WriteLine("TLS server negotiated group: " + NamedGroup.GetText(negotiatedGroup));
                }

                Console.WriteLine("TLS server reports 'tls-server-end-point' = " + ToHexString(m_tlsServerEndPoint));
                Console.WriteLine("TLS server reports 'tls-unique' = " + ToHexString(m_tlsUnique));
            }
        }

        public override ProtocolVersion GetServerVersion()
        {
            ProtocolVersion serverVersion = m_config.serverNegotiateVersion ?? base.GetServerVersion();

            if (TlsTestConfig.Debug)
            {
                Console.WriteLine("TLS server negotiated version " + serverVersion);
            }

            return serverVersion;
        }

        public override CertificateRequest GetCertificateRequest()
        {
            if (m_config.serverCertReq == TlsTestConfig.SERVER_CERT_REQ_NONE)
                return null;

            IList<SignatureAndHashAlgorithm> serverSigAlgs = null;
            if (TlsUtilities.IsSignatureAlgorithmsExtensionAllowed(m_context.ServerVersion))
            {
                serverSigAlgs = m_config.serverCertReqSigAlgs;
                if (serverSigAlgs == null)
                {
                    serverSigAlgs = TlsUtilities.GetDefaultSupportedSignatureAlgorithms(m_context);
                }
            }

            var certificateAuthorities = new List<X509Name>();
            //certificateAuthorities.Add(TlsTestUtilities.LoadBcCertificateResource("x509-ca-dsa.pem").Subject);
            //certificateAuthorities.Add(TlsTestUtilities.LoadBcCertificateResource("x509-ca-ecdsa.pem").Subject);
            //certificateAuthorities.Add(TlsTestUtilities.LoadBcCertificateResource("x509-ca-rsa.pem").Subject);

            // All the CA certificates are currently configured with this subject
            certificateAuthorities.Add(new X509Name("CN=BouncyCastle TLS Test CA"));

            if (TlsUtilities.IsTlsV13(m_context))
            {
                // TODO[tls13] Support for non-empty request context
                byte[] certificateRequestContext = TlsUtilities.EmptyBytes;

                // TODO[tls13] Add TlsTestConfig.serverCertReqSigAlgsCert
                IList<SignatureAndHashAlgorithm> serverSigAlgsCert = null;

                return new CertificateRequest(certificateRequestContext, serverSigAlgs, serverSigAlgsCert,
                    certificateAuthorities);
            }
            else
            {
                short[] certificateTypes = new short[]{ ClientCertificateType.rsa_sign,
                    ClientCertificateType.dss_sign, ClientCertificateType.ecdsa_sign };

                return new CertificateRequest(certificateTypes, serverSigAlgs, certificateAuthorities);
            }
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

            TlsCertificate[] chain = clientCertificate.GetCertificateList();

            if (TlsTestConfig.Debug)
            {
                Console.WriteLine("TLS server received client certificate chain of length " + chain.Length);
                for (int i = 0; i < chain.Length; ++i)
                {
                    X509CertificateStructure entry = X509CertificateStructure.GetInstance(chain[0].GetEncoded());
                    // TODO Create fingerprint based on certificate signature algorithm digest
                    Console.WriteLine("    fingerprint:SHA-256 " + TlsTestUtilities.Fingerprint(entry) + " ("
                        + entry.Subject + ")");
                }
            }

            if (isEmpty)
                return;

            string[] trustedCertResources = new string[]{ "x509-client-dsa.pem", "x509-client-ecdh.pem",
                "x509-client-ecdsa.pem", "x509-client-ed25519.pem", "x509-client-ed448.pem",
                "x509-client-ml_dsa_44.pem", "x509-client-ml_dsa_65.pem", "x509-client-ml_dsa_87.pem",
                "x509-client-rsa_pss_256.pem", "x509-client-rsa_pss_384.pem", "x509-client-rsa_pss_512.pem",
                "x509-client-rsa.pem" };

            TlsCertificate[] certPath = TlsTestUtilities.GetTrustedCertPath(m_context.Crypto, chain[0],
                trustedCertResources);

            if (null == certPath)
                throw new TlsFatalAlert(AlertDescription.bad_certificate);

            if (m_config.serverCheckSigAlgOfClientCerts)
            {
                TlsUtilities.CheckPeerSigAlgs(m_context, certPath);
            }
        }

        public override void ProcessClientExtensions(IDictionary<int, byte[]> clientExtensions)
        {
            if (m_context.SecurityParameters.ClientRandom == null)
                throw new TlsFatalAlert(AlertDescription.internal_error);

            base.ProcessClientExtensions(clientExtensions);
        }

        public override IDictionary<int, byte[]> GetServerExtensions()
        {
            if (m_context.SecurityParameters.ServerRandom == null)
                throw new TlsFatalAlert(AlertDescription.internal_error);

            return base.GetServerExtensions();
        }

        public override void GetServerExtensionsForConnection(IDictionary<int, byte[]> serverExtensions)
        {
            if (m_context.SecurityParameters.ServerRandom == null)
                throw new TlsFatalAlert(AlertDescription.internal_error);

            base.GetServerExtensionsForConnection(serverExtensions);
        }

        protected virtual IList<SignatureAndHashAlgorithm> GetSupportedSignatureAlgorithms()
        {
            if (TlsUtilities.IsTlsV12(m_context) && m_config.serverAuthSigAlg != null)
            {
                return TlsUtilities.VectorOfOne(m_config.serverAuthSigAlg);
            }

            return m_context.SecurityParameters.ClientSigAlgs;
        }

        protected override TlsCredentialedSigner GetDsaSignerCredentials()
        {
            return LoadSignerCredentials(SignatureAlgorithm.dsa);
        }

        protected override TlsCredentialedSigner GetECDsaSignerCredentials()
        {
            // TODO[RFC 8422] Code should choose based on client's supported sig algs?
            return LoadSignerCredentials(SignatureAlgorithm.ecdsa);
            //return LoadSignerCredentials(SignatureAlgorithm.ed25519);
            //return LoadSignerCredentials(SignatureAlgorithm.ed448);
        }

        protected override TlsCredentialedDecryptor GetRsaEncryptionCredentials()
        {
            return TlsTestUtilities.LoadEncryptionCredentials(m_context,
                new string[]{ "x509-server-rsa-enc.pem", "x509-ca-rsa.pem" }, "x509-server-key-rsa-enc.pem");
        }

        protected override TlsCredentialedSigner GetRsaSignerCredentials()
        {
            return LoadSignerCredentials(SignatureAlgorithm.rsa);
        }

        protected override int[] GetSupportedCipherSuites()
        {
            return TlsUtilities.GetSupportedCipherSuites(Crypto, TestCipherSuites);
        }

        protected override ProtocolVersion[] GetSupportedVersions() =>
            m_config.serverSupportedVersions ?? base.GetSupportedVersions();

        protected virtual string ToHexString(byte[] data)
        {
            return data == null ? "(null)" : Hex.ToHexString(data);
        }

        private TlsCredentialedSigner LoadSignerCredentials(short signatureAlgorithm)
        {
            return TlsTestUtilities.LoadSignerCredentialsServer(m_context, GetSupportedSignatureAlgorithms(),
                signatureAlgorithm);
        }
    }
}
