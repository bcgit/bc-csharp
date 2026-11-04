using System.Collections.Generic;

using Org.BouncyCastle.Tls.Crypto;

namespace Org.BouncyCastle.Tls
{
    /// <summary>The security parameters of a TLS connection, negotiated during the handshake.</summary>
    public sealed class SecurityParameters
    {
        internal int m_entity = -1;
        internal bool m_resumedSession = false;
        internal bool m_secureRenegotiation = false;
        internal int m_cipherSuite = Tls.CipherSuite.TLS_NULL_WITH_NULL_NULL;
        internal short m_maxFragmentLength = -1;
        internal int m_prfAlgorithm = -1;
        internal int m_prfCryptoHashAlgorithm = -1;
        internal int m_prfHashLength = -1;
        internal int m_verifyDataLength = -1;
        internal TlsSecret m_baseKeyClient = null;
        internal TlsSecret m_baseKeyServer = null;
        internal TlsSecret m_earlyExporterMasterSecret = null;
        internal TlsSecret m_earlySecret = null;
        internal TlsSecret m_exporterMasterSecret = null;
        internal TlsSecret m_handshakeSecret = null;
        internal TlsSecret m_masterSecret = null;
        internal TlsSecret m_trafficSecretClient = null;
        internal TlsSecret m_trafficSecretServer = null;
        internal byte[] m_clientRandom = null;
        internal byte[] m_serverRandom = null;
        internal byte[] m_sessionHash = null;
        internal byte[] m_sessionID = null;
        internal byte[] m_pskIdentity = null;
        internal byte[] m_srpIdentity = null;
        internal byte[] m_tlsServerEndPoint = null;
        internal byte[] m_tlsUnique = null;
        internal bool m_encryptThenMac = false;
        internal bool m_extendedMasterSecret = false;
        internal bool m_extendedPadding = false;
        internal bool m_truncatedHmac = false;
        internal ProtocolName m_applicationProtocol = null;
        internal bool m_applicationProtocolSet = false;
        internal short[] m_clientCertTypes = null;
        internal IList<ServerName> m_clientServerNames = null;
        internal IList<SignatureAndHashAlgorithm> m_clientSigAlgs = null;
        internal IList<SignatureAndHashAlgorithm> m_clientSigAlgsCert = null;
        internal int[] m_clientSupportedGroups = null;
        internal IList<SignatureAndHashAlgorithm> m_serverSigAlgs = null;
        internal IList<SignatureAndHashAlgorithm> m_serverSigAlgsCert = null;
        internal int[] m_serverSupportedGroups = null;
        internal int m_keyExchangeAlgorithm = -1;
        internal Certificate m_localCertificate = null;
        internal Certificate m_peerCertificate = null;
        internal ProtocolVersion m_negotiatedVersion = null;
        internal int m_negotiatedGroup = -1;
        internal int m_statusRequestVersion = 0;
        internal short m_clientCertificateType = CertificateType.X509;
        internal short m_serverCertificateType = CertificateType.X509;

        // TODO[tls-ops] Investigate whether we can handle verify data using TlsSecret
        internal byte[] m_localVerifyData = null;
        internal byte[] m_peerVerifyData = null;

        /// <summary>Connection ID we use during communication to the peer.</summary>
        internal byte[] m_connectionIDLocal;
        /// <summary>Connection ID our peer uses for communication to us.</summary>
        internal byte[] m_connectionIDPeer;

        internal void Clear()
        {
            this.m_sessionHash = null;
            this.m_sessionID = null;
            this.m_clientCertTypes = null;
            this.m_clientServerNames = null;
            this.m_clientSigAlgs = null;
            this.m_clientSigAlgsCert = null;
            this.m_clientSupportedGroups = null;
            this.m_serverSigAlgs = null;
            this.m_serverSigAlgsCert = null;
            this.m_serverSupportedGroups = null;
            this.m_statusRequestVersion = 0;

            this.m_baseKeyClient = ClearSecret(m_baseKeyClient);
            this.m_baseKeyServer = ClearSecret(m_baseKeyServer);
            this.m_earlyExporterMasterSecret = ClearSecret(m_earlyExporterMasterSecret);
            this.m_earlySecret = ClearSecret(m_earlySecret);
            this.m_exporterMasterSecret = ClearSecret(m_exporterMasterSecret);
            this.m_handshakeSecret = ClearSecret(m_handshakeSecret);
            this.m_masterSecret = ClearSecret(m_masterSecret);
        }

        /// <summary>Gets the application protocol.</summary>
        public ProtocolName ApplicationProtocol
        {
            get { return m_applicationProtocol; }
        }

        /// <summary>Gets the base key client.</summary>
        public TlsSecret BaseKeyClient
        {
            get { return m_baseKeyClient; }
        }

        /// <summary>Gets the base key server.</summary>
        public TlsSecret BaseKeyServer
        {
            get { return m_baseKeyServer; }
        }

        /// <summary>Gets the cipher suite.</summary>
        public int CipherSuite
        {
            get { return m_cipherSuite; }
        }

        /// <summary>Gets the client certificate type.</summary>
        public short ClientCertificateType
        {
            get { return m_clientCertificateType; }
        }

        /// <summary>Gets the client cert types.</summary>
        public short[] ClientCertTypes
        {
            get { return m_clientCertTypes; }
        }

        /// <summary>Gets the client random.</summary>
        public byte[] ClientRandom
        {
            get { return m_clientRandom; }
        }

        /// <summary>Gets the client server names.</summary>
        public IList<ServerName> ClientServerNames
        {
            get { return m_clientServerNames; }
        }

        /// <summary>Gets the client sig algs.</summary>
        public IList<SignatureAndHashAlgorithm> ClientSigAlgs
        {
            get { return m_clientSigAlgs; }
        }

        /// <summary>Gets the client sig algs cert.</summary>
        public IList<SignatureAndHashAlgorithm> ClientSigAlgsCert
        {
            get { return m_clientSigAlgsCert; }
        }

        /// <summary>Gets the client supported groups.</summary>
        public int[] ClientSupportedGroups
        {
            get { return m_clientSupportedGroups; }
        }

        /// <summary>Gets the connection ID local.</summary>
        public byte[] ConnectionIDLocal => m_connectionIDLocal;

        /// <summary>Gets the connection ID peer.</summary>
        public byte[] ConnectionIDPeer => m_connectionIDPeer;

        /// <summary>Gets the early exporter master secret.</summary>
        public TlsSecret EarlyExporterMasterSecret
        {
            get { return m_earlyExporterMasterSecret; }
        }

        /// <summary>Gets the early secret.</summary>
        public TlsSecret EarlySecret
        {
            get { return m_earlySecret; }
        }

        /// <summary>Gets the exporter master secret.</summary>
        public TlsSecret ExporterMasterSecret
        {
            get { return m_exporterMasterSecret; }
        }

        /// <summary>Gets the entity.</summary>
        public int Entity
        {
            get { return m_entity; }
        }

        /// <summary>Gets the handshake secret.</summary>
        public TlsSecret HandshakeSecret
        {
            get { return m_handshakeSecret; }
        }

        /// <summary>Gets a value indicating whether this is application protocol set.</summary>
        public bool IsApplicationProtocolSet
        {
            get { return m_applicationProtocolSet; }
        }

        /// <summary>Gets a value indicating whether this is encrypt then mac.</summary>
        public bool IsEncryptThenMac
        {
            get { return m_encryptThenMac; }
        }

        /// <summary>Gets a value indicating whether this is extended master secret.</summary>
        public bool IsExtendedMasterSecret
        {
            get { return m_extendedMasterSecret; }
        }

        /// <summary>Gets a value indicating whether this is extended padding.</summary>
        public bool IsExtendedPadding
        {
            get { return m_extendedPadding; }
        }

        /// <summary>Gets a value indicating whether this is resumed session.</summary>
        public bool IsResumedSession
        {
            get { return m_resumedSession; }
        }

        /// <summary>Gets a value indicating whether this is secure renegotiation.</summary>
        public bool IsSecureRenegotiation
        {
            get { return m_secureRenegotiation; }
        }

        /// <summary>Gets a value indicating whether this is truncated hmac.</summary>
        public bool IsTruncatedHmac
        {
            get { return m_truncatedHmac; }
        }

        /// <summary>Gets the key exchange algorithm.</summary>
        public int KeyExchangeAlgorithm
        {
            get { return m_keyExchangeAlgorithm; }
        }

        /// <summary>Gets the local certificate.</summary>
        public Certificate LocalCertificate
        {
            get { return m_localCertificate; }
        }

        /// <summary>Gets the local verify data.</summary>
        public byte[] LocalVerifyData
        {
            get { return m_localVerifyData; }
        }

        /// <summary>Gets the master secret.</summary>
        public TlsSecret MasterSecret
        {
            get { return m_masterSecret; }
        }

        /// <summary>Gets the max fragment length.</summary>
        public short MaxFragmentLength
        {
            get { return m_maxFragmentLength; }
        }

        /// <summary>
        /// The named group selected by the server for key exchange (if any), or -1 when not negotiated.
        /// </summary>
        /// <remarks>
        /// See <see cref="NamedGroup"/> for group constants. Currently not set (i.e. -1) when pre-1.3 version
        /// negotiated. Not all TLS 1.3 key exchanges negotiate a group (e.g. PskKeyExchangeMode.psk_ke).
        /// </remarks>
        public int NegotiatedGroup => m_negotiatedGroup;

        /// <summary>Gets the negotiated version.</summary>
        public ProtocolVersion NegotiatedVersion
        {
            get { return m_negotiatedVersion; }
        }

        /// <summary>Gets the peer certificate.</summary>
        public Certificate PeerCertificate
        {
            get { return m_peerCertificate; }
        }

        /// <summary>Gets the peer verify data.</summary>
        public byte[] PeerVerifyData
        {
            get { return m_peerVerifyData; }
        }

        /// <summary>Gets the prf algorithm.</summary>
        public int PrfAlgorithm
        {
            get { return m_prfAlgorithm; }
        }

        /// <summary>Gets the prf crypto hash algorithm.</summary>
        public int PrfCryptoHashAlgorithm
        {
            get { return m_prfCryptoHashAlgorithm; }
        }

        /// <summary>Gets the prf hash length.</summary>
        public int PrfHashLength
        {
            get { return m_prfHashLength; }
        }

        /// <summary>Gets the psk identity.</summary>
        public byte[] PskIdentity
        {
            get { return m_pskIdentity; }
        }

        /// <summary>Gets the server certificate type.</summary>
        public short ServerCertificateType
        {
            get { return m_serverCertificateType; }
        }

        /// <summary>Gets the server random.</summary>
        public byte[] ServerRandom
        {
            get { return m_serverRandom; }
        }

        /// <summary>Gets the server sig algs.</summary>
        public IList<SignatureAndHashAlgorithm> ServerSigAlgs
        {
            get { return m_serverSigAlgs; }
        }

        /// <summary>Gets the server sig algs cert.</summary>
        public IList<SignatureAndHashAlgorithm> ServerSigAlgsCert
        {
            get { return m_serverSigAlgsCert; }
        }

        /// <summary>Gets the server supported groups.</summary>
        public int[] ServerSupportedGroups
        {
            get { return m_serverSupportedGroups; }
        }

        /// <summary>Gets the session hash.</summary>
        public byte[] SessionHash
        {
            get { return m_sessionHash; }
        }

        /// <summary>Gets the session ID.</summary>
        public byte[] SessionID
        {
            get { return m_sessionID; }
        }

        /// <summary>Gets the srp identity.</summary>
        public byte[] SrpIdentity
        {
            get { return m_srpIdentity; }
        }

        /// <summary>Gets the status request version.</summary>
        public int StatusRequestVersion
        {
            get { return m_statusRequestVersion; }
        }

        /// <summary>Gets the tls server end point.</summary>
        public byte[] TlsServerEndPoint
        {
            get { return m_tlsServerEndPoint; }
        }

        /// <summary>Gets the tls unique.</summary>
        public byte[] TlsUnique
        {
            get { return m_tlsUnique; }
        }

        /// <summary>Gets the traffic secret client.</summary>
        public TlsSecret TrafficSecretClient
        {
            get { return m_trafficSecretClient; }
        }

        /// <summary>Gets the traffic secret server.</summary>
        public TlsSecret TrafficSecretServer
        {
            get { return m_trafficSecretServer; }
        }

        /// <summary>Gets the verify data length.</summary>
        public int VerifyDataLength
        {
            get { return m_verifyDataLength; }
        }

        private static TlsSecret ClearSecret(TlsSecret secret)
        {
            if (null != secret)
            {
                secret.Destroy();
            }
            return null;
        }
    }
}
