using System;
using System.Collections.Generic;
using System.IO;

using Org.BouncyCastle.Asn1;
using Org.BouncyCastle.Asn1.X509;
using Org.BouncyCastle.Tls.Crypto;
using Org.BouncyCastle.Utilities;
using Org.BouncyCastle.Utilities.Encoders;

namespace Org.BouncyCastle.Tls.Tests
{
    internal class TlsTestClientImpl
        : DefaultTlsClient
    {
        private static readonly int[] TestCipherSuites = new int[]
        {
            /*
             * TLS 1.3
             */
            CipherSuite.TLS_AES_128_GCM_SHA256,
            CipherSuite.TLS_CHACHA20_POLY1305_SHA256,

            /*
             * pre-TLS 1.3
             */
            CipherSuite.TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,
            CipherSuite.TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256,
            CipherSuite.TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA256,
            CipherSuite.TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA,
            CipherSuite.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
            CipherSuite.TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256,
            CipherSuite.TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA256,
            CipherSuite.TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA,
            CipherSuite.TLS_DHE_RSA_WITH_AES_128_GCM_SHA256,
            CipherSuite.TLS_DHE_RSA_WITH_CHACHA20_POLY1305_SHA256,
            CipherSuite.TLS_DHE_RSA_WITH_AES_128_CBC_SHA256,
            CipherSuite.TLS_DHE_RSA_WITH_AES_128_CBC_SHA,
            CipherSuite.TLS_RSA_WITH_AES_128_GCM_SHA256,
            CipherSuite.TLS_RSA_WITH_AES_128_CBC_SHA256,
            CipherSuite.TLS_RSA_WITH_AES_128_CBC_SHA,
        };

        protected readonly TlsTestConfig m_config;

        protected int m_firstFatalAlertConnectionEnd = -1;
        protected short m_firstFatalAlertDescription = -1;

        internal ProtocolVersion m_negotiatedVersion = null;
        internal byte[] m_tlsKeyingMaterial1 = null;
        internal byte[] m_tlsKeyingMaterial2 = null;
        internal byte[] m_tlsServerEndPoint = null;
        internal byte[] m_tlsUnique = null;

        internal TlsTestClientImpl(TlsTestConfig config)
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

        public override IDictionary<int, byte[]> GetClientExtensions()
        {
            if (m_context.SecurityParameters.ClientRandom == null)
                throw new TlsFatalAlert(AlertDescription.internal_error);

            var clientExtensions = base.GetClientExtensions();
            if (clientExtensions != null)
            {
                if (!m_config.clientSendSignatureAlgorithms)
                {
                    clientExtensions.Remove(ExtensionType.signature_algorithms);
                    this.m_supportedSignatureAlgorithms = null;
                }
                if (!m_config.clientSendSignatureAlgorithmsCert)
                {
                    clientExtensions.Remove(ExtensionType.signature_algorithms_cert);
                    this.m_supportedSignatureAlgorithmsCert = null;
                }
            }
            return clientExtensions;
        }

        public override IList<int> GetEarlyKeyShareGroups()
        {
            if (m_config.clientEmptyKeyShare)
                return null;

            return base.GetEarlyKeyShareGroups();
        }

        protected override IList<SignatureAndHashAlgorithm> GetSupportedSignatureAlgorithms()
        {
            if (m_config.clientCHSigAlgs != null)
                return TlsUtilities.GetSupportedSignatureAlgorithms(m_context, m_config.clientCHSigAlgs);

            return base.GetSupportedSignatureAlgorithms();
        }

        public override bool IsFallback()
        {
            return m_config.clientFallback;
        }

        public override void NotifyAlertRaised(short alertLevel, short alertDescription, string message,
            Exception cause)
        {
            if (alertLevel == AlertLevel.fatal && m_firstFatalAlertConnectionEnd == -1)
            {
                m_firstFatalAlertConnectionEnd = ConnectionEnd.client;
                m_firstFatalAlertDescription = alertDescription;
            }

            if (TlsTestConfig.Debug)
            {
                TextWriter output = (alertLevel == AlertLevel.fatal) ? Console.Error : Console.Out;
                output.WriteLine("TLS client raised alert: " + AlertLevel.GetText(alertLevel)
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
                m_firstFatalAlertConnectionEnd = ConnectionEnd.server;
                m_firstFatalAlertDescription = alertDescription;
            }

            if (TlsTestConfig.Debug)
            {
                TextWriter output = (alertLevel == AlertLevel.fatal) ? Console.Error : Console.Out;
                output.WriteLine("TLS client received alert: " + AlertLevel.GetText(alertLevel)
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
                Console.WriteLine("TLS client reports 'tls-server-end-point' = " + ToHexString(m_tlsServerEndPoint));
                Console.WriteLine("TLS client reports 'tls-unique' = " + ToHexString(m_tlsUnique));
            }
        }

        public override void NotifyServerVersion(ProtocolVersion serverVersion)
        {
            base.NotifyServerVersion(serverVersion);

            this.m_negotiatedVersion = serverVersion;

            if (TlsTestConfig.Debug)
            {
                Console.WriteLine("TLS client negotiated " + serverVersion);
            }
        }

        public override TlsAuthentication GetAuthentication()
        {
            return new MyTlsAuthentication(this, m_context);
        }

        public override void ProcessServerExtensions(IDictionary<int, byte[]> serverExtensions)
        {
            if (m_context.SecurityParameters.ServerRandom == null)
                throw new TlsFatalAlert(AlertDescription.internal_error);

            base.ProcessServerExtensions(serverExtensions);
        }

        protected virtual Certificate CorruptCertificate(Certificate cert)
        {
            CertificateEntry[] certEntryList = cert.GetCertificateEntryList();
            CertificateEntry ee = certEntryList[0];
            TlsCertificate corruptCert = CorruptCertificateSignature(ee.Certificate);
            certEntryList[0] = new CertificateEntry(corruptCert, ee.Extensions);
            return new Certificate(cert.GetCertificateRequestContext(), certEntryList);
        }

        protected virtual TlsCertificate CorruptCertificateSignature(TlsCertificate tlsCertificate)
        {
            X509CertificateStructure cert = X509CertificateStructure.GetInstance(tlsCertificate.GetEncoded());

            Asn1EncodableVector v = new Asn1EncodableVector();
            v.Add(cert.TbsCertificate);
            v.Add(cert.SignatureAlgorithm);
            v.Add(CorruptSignature(cert.Signature));

            cert = X509CertificateStructure.GetInstance(new DerSequence(v));

            return Crypto.CreateCertificate(cert.GetEncoded(Asn1Encodable.Der));
        }

        protected virtual DerBitString CorruptSignature(DerBitString bs)
        {
            return new DerBitString(CorruptBit(bs.GetOctets()));
        }

        protected virtual byte[] CorruptBit(byte[] bs)
        {
            bs = Arrays.Clone(bs);

            // Flip a random bit
            int bit = m_context.Crypto.SecureRandom.Next(bs.Length << 3);
            bs[bit >> 3] ^= (byte)(1 << (bit & 7));

            return bs;
        }

        protected override int[] GetSupportedCipherSuites()
        {
            return TlsUtilities.GetSupportedCipherSuites(Crypto, TestCipherSuites);
        }

        protected override ProtocolVersion[] GetSupportedVersions()
        {
            if (null != m_config.clientSupportedVersions)
            {
                return m_config.clientSupportedVersions;
            }

            return base.GetSupportedVersions();
        }

        protected virtual string ToHexString(byte[] data)
        {
            return data == null ? "(null)" : Hex.ToHexString(data);
        }

        internal class MyTlsAuthentication
            : TlsAuthentication
        {
            private readonly TlsTestClientImpl m_outer;
            private readonly TlsContext m_context;

            internal MyTlsAuthentication(TlsTestClientImpl outer, TlsContext context)
            {
                this.m_outer = outer;
                this.m_context = context;
            }

            public virtual void NotifyServerCertificate(TlsServerCertificate serverCertificate)
            {
                TlsCertificate[] chain = serverCertificate.Certificate.GetCertificateList();

                if (TlsTestConfig.Debug)
                {
                    Console.WriteLine("TLS client received server certificate chain of length " + chain.Length);
                    for (int i = 0; i < chain.Length; ++i)
                    {
                        X509CertificateStructure entry = X509CertificateStructure.GetInstance(chain[i].GetEncoded());
                        // TODO Create fingerprint based on certificate signature algorithm digest
                        Console.WriteLine("    fingerprint:SHA-256 " + TlsTestUtilities.Fingerprint(entry) + " ("
                            + entry.Subject + ")");
                    }
                }

                bool isEmpty = serverCertificate == null || serverCertificate.Certificate == null
                    || serverCertificate.Certificate.IsEmpty;

                if (isEmpty)
                    throw new TlsFatalAlert(AlertDescription.bad_certificate);

                string[] trustedCertResources = new string[]{ "x509-server-dsa.pem", "x509-server-ecdh.pem",
                    "x509-server-ecdsa.pem", "x509-server-ed25519.pem", "x509-server-ed448.pem",
                    "x509-server-rsa_pss_256.pem", "x509-server-rsa_pss_384.pem", "x509-server-rsa_pss_512.pem",
                    "x509-server-rsa-enc.pem", "x509-server-rsa-sign.pem" };

                TlsCertificate[] certPath = TlsTestUtilities.GetTrustedCertPath(m_context.Crypto, chain[0],
                    trustedCertResources);

                if (null == certPath)
                    throw new TlsFatalAlert(AlertDescription.bad_certificate);

                if (m_outer.m_config.clientCheckSigAlgOfServerCerts)
                {
                    TlsUtilities.CheckPeerSigAlgs(m_context, certPath);
                }
            }

            public virtual TlsCredentials GetClientCredentials(CertificateRequest certificateRequest)
            {
                TlsTestConfig config = m_outer.m_config;

                if (config.serverCertReq == TlsTestConfig.SERVER_CERT_REQ_NONE)
                    throw new InvalidOperationException();
                if (config.clientAuth == TlsTestConfig.CLIENT_AUTH_NONE)
                    return null;

                bool isTlsV13 = TlsUtilities.IsTlsV13(m_context);

                if (!isTlsV13)
                {
                    short[] certificateTypes = certificateRequest.CertificateTypes;
                    if (certificateTypes == null || !Arrays.Contains(certificateTypes, ClientCertificateType.rsa_sign))
                        return null;
                }

                var supportedSigAlgs = certificateRequest.SupportedSignatureAlgorithms;
                if (supportedSigAlgs != null && config.clientAuthSigAlg != null)
                {
                    supportedSigAlgs = TlsUtilities.VectorOfOne(config.clientAuthSigAlg);
                }

                // TODO[tls13] Check also supportedSigAlgsCert against the chain signature(s)

                TlsCredentialedSigner signerCredentials = TlsTestUtilities.LoadSignerCredentials(m_context,
                    supportedSigAlgs, SignatureAlgorithm.rsa, "x509-client-rsa.pem", "x509-client-key-rsa.pem");
                if (signerCredentials == null && supportedSigAlgs != null)
                {
                    SignatureAndHashAlgorithm pss = SignatureAndHashAlgorithm.rsa_pss_rsae_sha256;
                    if (TlsUtilities.ContainsSignatureAlgorithm(supportedSigAlgs, pss))
                    {
                        signerCredentials = TlsTestUtilities.LoadSignerCredentials(m_context,
                            new string[]{ "x509-client-rsa.pem" }, "x509-client-key-rsa.pem", pss);
                    }
                }

                if (config.clientAuth == TlsTestConfig.CLIENT_AUTH_VALID)
                    return signerCredentials;

                return new MyTlsCredentialedSigner(m_outer, signerCredentials);
            }
        }

        internal class MyTlsCredentialedSigner
            : TlsCredentialedSigner
        {
            private readonly TlsTestClientImpl m_outer;
            private readonly TlsCredentialedSigner m_inner;

            internal MyTlsCredentialedSigner(TlsTestClientImpl outer, TlsCredentialedSigner inner)
            {
                this.m_outer = outer;
                this.m_inner = inner;
            }

            public virtual byte[] GenerateRawSignature(byte[] hash)
            {
                byte[] sig = m_inner.GenerateRawSignature(hash);

                if (m_outer.m_config.clientAuth == TlsTestConfig.CLIENT_AUTH_INVALID_VERIFY)
                {
                    sig = m_outer.CorruptBit(sig);
                }

                return sig;
            }

            public virtual Certificate Certificate
            {
                get
                {
                    Certificate cert = m_inner.Certificate;

                    if (m_outer.m_config.clientAuth == TlsTestConfig.CLIENT_AUTH_INVALID_CERT)
                    {
                        cert = m_outer.CorruptCertificate(cert);
                    }

                    return cert;
                }
            }

            public virtual SignatureAndHashAlgorithm SignatureAndHashAlgorithm
            {
                get { return m_inner.SignatureAndHashAlgorithm; }
            }

            public virtual TlsStreamSigner GetStreamSigner()
            {
                TlsStreamSigner streamSigner = m_inner.GetStreamSigner();

                if (streamSigner != null && m_outer.m_config.clientAuth == TlsTestConfig.CLIENT_AUTH_INVALID_VERIFY)
                    return new CorruptingStreamSigner(m_outer, streamSigner);

                return streamSigner;
            }
        }

        internal class CorruptingStreamSigner
            : TlsStreamSigner
        {
            private readonly TlsTestClientImpl m_outer;
            private readonly TlsStreamSigner m_inner;

            internal CorruptingStreamSigner(TlsTestClientImpl outer, TlsStreamSigner inner)
            {
                this.m_outer = outer;
                this.m_inner = inner;
            }

            public Stream Stream
            {
                get { return m_inner.Stream; }
            }

            public byte[] GetSignature()
            {
                return m_outer.CorruptBit(m_inner.GetSignature());
            }
        }
    }
}
