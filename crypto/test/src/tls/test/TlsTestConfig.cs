using System;
using System.Collections.Generic;

namespace Org.BouncyCastle.Tls.Tests
{
    public class TlsTestConfig
    {
        // TODO[tls-port]
        public static readonly bool Debug = false;

        /// <summary>Client does not authenticate, ignores any certificate request.</summary>
        public const int CLIENT_AUTH_NONE = 0;

        /// <summary>Client will authenticate if it receives a certificate request.</summary>
        public const int CLIENT_AUTH_VALID = 1;

        /// <summary>Client will authenticate if it receives a certificate request, with an invalid certificate.
        /// </summary>
        public const int CLIENT_AUTH_INVALID_CERT = 2;

        /// <summary>Client will authenticate if it receives a certificate request, with an invalid CertificateVerify
        /// signature.</summary>
        public const int CLIENT_AUTH_INVALID_VERIFY = 3;

        public const int CRYPTO_BC = 0;

        /// <summary>Server will not request a client certificate.</summary>
        public const int SERVER_CERT_REQ_NONE = 0;

        /// <summary>Server will request a client certificate but receiving one is optional.</summary>
        public const int SERVER_CERT_REQ_OPTIONAL = 1;

        /// <summary>Server will request a client certificate and receiving one is mandatory.</summary>
        public const int SERVER_CERT_REQ_MANDATORY = 2;

        /// <summary>Configures the client authentication behaviour of the test client. Use CLIENT_AUTH_* constants.
        /// </summary>
        public int clientAuth = CLIENT_AUTH_VALID;

        /// <summary>If not null, and TLS 1.2 or higher is negotiated, selects a fixed signature/ hash algorithm to be
        /// used for the CertificateVerify signature(if one is sent).</summary>
        public SignatureAndHashAlgorithm clientAuthSigAlg = null;

        /// <summary>If not null, and TLS 1.2 or higher is negotiated, selects a fixed signature/ hash algorithm to be
        /// _claimed_ in the CertificateVerify (if one is sent), independently of what was actually used.</summary>
        public SignatureAndHashAlgorithm clientAuthSigAlgClaimed = null;

        /// <summary>If TLS 1.2 or higher is negotiated, configures the set of supported signature algorithms in the
        /// ClientHello. If null, uses a default set.</summary>
        public IList<SignatureAndHashAlgorithm> clientCHSigAlgs = null;

        /// <summary>Control whether the client will call
        /// <see cref="TlsUtilities.CheckPeerSigAlgs(TlsContext, Crypto.TlsCertificate[])"/> to check the server
        /// certificate chain.</summary>
        public bool clientCheckSigAlgOfServerCerts = true;

        public int clientCrypto = CRYPTO_BC;

        /// <summary>Configures whether the client will send an empty key_share extension in initial ClientHello.
        /// </summary>
        public bool clientEmptyKeyShare = false;

        /// <summary>Configures whether the client will indicate version fallback via TLS_FALLBACK_SCSV.</summary>
        public bool clientFallback = false;

        /// <summary>Configures whether a (TLS 1.2+) client may send the signature_algorithms extension in ClientHello.
        /// </summary>
        public bool clientSendSignatureAlgorithms = true;

        /// <summary>Configures whether a (TLS 1.2+) client may send the signature_algorithms_cert extension in
        /// ClientHello.</summary>
        public bool clientSendSignatureAlgorithmsCert = true;

        /// <summary>Configures the supported protocol versions for the client. If null, uses the library's default.
        /// </summary>
        public ProtocolVersion[] clientSupportedVersions = null;

        /// <summary>If not null, and TLS 1.2 or higher is negotiated, selects a fixed signature/ hash algorithm to be
        /// used for the ServerKeyExchange signature(if one is sent).</summary>
        public SignatureAndHashAlgorithm serverAuthSigAlg = null;

        /// <summary>Configures whether the test server will send a certificate request.</summary>
        public int serverCertReq = SERVER_CERT_REQ_OPTIONAL;

        /// <summary>If TLS 1.2 or higher is negotiated, configures the set of supported signature algorithms in the
        /// CertificateRequest (if one is sent). If null, uses a default set.</summary>
        public IList<SignatureAndHashAlgorithm> serverCertReqSigAlgs = null;

        /// <summary>Control whether the server will call
        /// <see cref="TlsUtilities.CheckPeerSigAlgs(TlsContext, Crypto.TlsCertificate[])"/> to check the client
        /// certificate chain.</summary>
        public bool serverCheckSigAlgOfClientCerts = true;

        public int serverCrypto = CRYPTO_BC;

        /// <summary>Configures a protocol version the server will unconditionally negotiate.</summary>
        /// <remarks>
        /// Ignored if null.
        /// </remarks>
        public ProtocolVersion serverNegotiateVersion = null;

        /// <summary>Configures the supported protocol versions for the server.</summary>
        /// <remarks>
        /// If null, uses the library's default.
        /// </remarks>
        public ProtocolVersion[] serverSupportedVersions = null;

        /// <summary>Configures the connection end at which a fatal alert is expected to be raised.</summary>
        /// <remarks>
        /// Use <see cref="ConnectionEnd"/> constants.
        /// </remarks>
        public int expectFatalAlertConnectionEnd = -1;

        /// <summary>Configures the type of fatal alert expected to be raised.</summary>
        /// <remarks>
        /// Use <see cref="AlertDescription"/> constants.
        /// </remarks>
        public short expectFatalAlertDescription = -1;

        public virtual void ExpectClientFatalAlert(short alertDescription)
        {
            this.expectFatalAlertConnectionEnd = ConnectionEnd.client;
            this.expectFatalAlertDescription = alertDescription;
        }

        public virtual void ExpectServerFatalAlert(short alertDescription)
        {
            this.expectFatalAlertConnectionEnd = ConnectionEnd.server;
            this.expectFatalAlertDescription = alertDescription;
        }
    }
}
