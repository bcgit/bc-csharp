using System.Collections.Generic;
using System.IO;

using Org.BouncyCastle.Tls.Crypto;
using Org.BouncyCastle.Utilities;

namespace Org.BouncyCastle.Tls
{
    /// <summary>Base class for a TLS server.</summary>
    public abstract class AbstractTlsServer
        : AbstractTlsPeer, TlsServer
    {
        /// <summary>The context.</summary>
        protected TlsServerContext m_context;
        /// <summary>The protocol versions.</summary>
        protected ProtocolVersion[] m_protocolVersions;
        /// <summary>The cipher suites.</summary>
        protected int[] m_cipherSuites;

        /// <summary>The offered cipher suites.</summary>
        protected int[] m_offeredCipherSuites;
        /// <summary>The client extensions.</summary>
        protected IDictionary<int, byte[]> m_clientExtensions;

        /// <summary>The encrypt then MAC offered.</summary>
        protected bool m_encryptThenMACOffered;
        /// <summary>The max fragment length offered.</summary>
        protected short m_maxFragmentLengthOffered;
        /// <summary>The truncated h mac offered.</summary>
        protected bool m_truncatedHMacOffered;
        /// <summary>The client sent EC point formats.</summary>
        protected bool m_clientSentECPointFormats;
        /// <summary>The certificate status request.</summary>
        protected CertificateStatusRequest m_certificateStatusRequest;
        /// <summary>The status request v 2.</summary>
        protected IList<CertificateStatusRequestItemV2> m_statusRequestV2;
        /// <summary>The trusted CA keys.</summary>
        protected IList<TrustedAuthority> m_trustedCAKeys;

        /// <summary>The selected cipher suite.</summary>
        protected int m_selectedCipherSuite;
        /// <summary>The client protocol names.</summary>
        protected IList<ProtocolName> m_clientProtocolNames;
        /// <summary>The selected protocol name.</summary>
        protected ProtocolName m_selectedProtocolName;

        /// <summary>The server extensions.</summary>
        protected readonly IDictionary<int, byte[]> m_serverExtensions = new Dictionary<int, byte[]>();

        /// <summary>Create a new <see cref="AbstractTlsServer"/>.</summary>
        /// <param name="crypto">The crypto.</param>
        public AbstractTlsServer(TlsCrypto crypto)
            : base(crypto)
        {
        }

        /// <summary>
        /// Whether to echo a client's "status_request" extension (<i>RFC 6066 sec. 8</i>) in the extended server hello,
        /// so that a stapled OCSP response can be sent.
        /// </summary>
        /// <remarks>
        /// Echoing it makes <see cref="GetCertificateStatus"/> be called with
        /// <see cref="SecurityParameters.StatusRequestVersion"/> of 1; it does not oblige the server to actually supply
        /// a response.
        /// <para>
        /// This governs (D)TLS 1.2 and earlier, where the echo is what announces the "certificate_status" message. TLS
        /// 1.3 has no echo to send - the response rides in a per-<see cref="CertificateEntry"/> extension - so there
        /// <see cref="GetCertificateStatus"/> is called whenever the client offered "status_request", whatever this
        /// returns, and returning null from it is how a TLS 1.3 server declines to staple.
        /// </para>
        /// </remarks>
        /// <returns><c>true</c> (the default) to echo "status_request" when the client offered it.</returns>
        protected virtual bool AllowCertificateStatus() => true;

        /// <summary>Determine whether the encrypt_then_mac extension may be negotiated.</summary>
        /// <returns>true if the extension may be negotiated, false otherwise.</returns>
        protected virtual bool AllowEncryptThenMac() => true;

        /// <summary>
        /// Whether to echo a client's "status_request_v2" extension (<i>RFC 6961 sec. 2.2</i>) in the extended server
        /// hello.
        /// </summary>
        /// <remarks>
        /// When the client offered both, echoing this one takes precedence over "status_request", and
        /// <see cref="GetCertificateStatus"/> is then called with <see cref="SecurityParameters.StatusRequestVersion"/>
        /// of 2 - so a server overriding this must be prepared to return a
        /// <see cref="CertificateStatusType.ocsp_multi"/> status.
        /// /// </remarks>
        /// <returns><c>false</c> (the default) to leave "status_request_v2" unanswered.</returns>
        protected virtual bool AllowMultiCertStatus() => false;

        /// <summary>Determine whether the truncated_hmac extension may be negotiated.</summary>
        /// <returns>true if the extension may be negotiated, false otherwise.</returns>
        protected virtual bool AllowTruncatedHmac() => false;

        /// <summary>Determine whether the trusted_ca_keys extension may be acknowledged.</summary>
        /// <returns>true if the extension may be acknowledged, false otherwise.</returns>
        protected virtual bool AllowTrustedCAIndication() => false;

        /// <summary>Return the detail message no cipher suite.</summary>
        protected virtual string GetDetailMessageNoCipherSuite() => "No selectable cipher suite";

        /// <summary>Return the maximum default curve bits.</summary>
        protected virtual int GetMaximumDefaultCurveBits() => NamedGroup.GetCurveBits(NamedGroup.secp521r1);

        /// <summary>Return the maximum default finite field bits.</summary>
        protected virtual int GetMaximumDefaultFiniteFieldBits() => NamedGroup.GetFiniteFieldBits(NamedGroup.ffdhe8192);

        /// <summary>Return the maximum negotiable curve bits.</summary>
        protected virtual int GetMaximumNegotiableCurveBits()
        {
            int maxBits = 0;
            int[] clientSupportedGroups = m_context.SecurityParameters.ClientSupportedGroups;
            if (clientSupportedGroups != null)
            {
                for (int i = 0; i < clientSupportedGroups.Length; ++i)
                {
                    maxBits = System.Math.Max(maxBits, NamedGroup.GetCurveBits(clientSupportedGroups[i]));
                }
            }
            else
            {
                /*
                 * RFC 4492 4. A client that proposes ECC cipher suites may choose not to include these
                 * extensions. In this case, the server is free to choose any one of the elliptic curves or point
                 * formats [...].
                 */
                maxBits = GetMaximumDefaultCurveBits();
            }
            return maxBits;
        }

        /// <summary>Return the maximum negotiable finite field bits.</summary>
        protected virtual int GetMaximumNegotiableFiniteFieldBits()
        {
            int maxBits = 0;
            bool anyPeerFF = false;
            int[] clientSupportedGroups = m_context.SecurityParameters.ClientSupportedGroups;
            if (clientSupportedGroups != null)
            {
                for (int i = 0; i < clientSupportedGroups.Length; ++i)
                {
                    anyPeerFF |= NamedGroup.IsFiniteField(clientSupportedGroups[i]);
                    maxBits = System.Math.Max(maxBits, NamedGroup.GetFiniteFieldBits(clientSupportedGroups[i]));
                }
            }
            if (!anyPeerFF)
            {
                /*
                 * RFC 7919 4. If [...] the Supported Groups extension is either absent from the ClientHello
                 * entirely or contains no FFDHE groups (i.e., no codepoints between 256 and 511, inclusive), then
                 * the server [...] MAY select an FFDHE cipher suite and offer an FFDHE group of its choice [...].
                 */
                maxBits = GetMaximumDefaultFiniteFieldBits();
            }
            return maxBits;
        }

        /// <summary>Return the protocol names.</summary>
        protected virtual IList<ProtocolName> GetProtocolNames() => null;

        /// <summary>Determine whether a cipher suite can be selected, given what the client supports.</summary>
        /// <param name="cipherSuite">The cipher suite.</param>
        /// <param name="availCurveBits">
        /// The size in bits of the largest elliptic curve that can be used, or 0 if none.
        /// </param>
        /// <param name="availFiniteFieldBits">
        /// The size in bits of the largest finite field group that can be used, or 0 if none.
        /// </param>
        /// <param name="sigAlgs">The signature algorithms that can be used.</param>
        /// <returns>true if the cipher suite can be selected, false otherwise.</returns>
        protected virtual bool IsSelectableCipherSuite(int cipherSuite, int availCurveBits, int availFiniteFieldBits,
            IList<short> sigAlgs)
        {
            return TlsUtilities.IsValidVersionForCipherSuite(cipherSuite, m_context.ServerVersion)
                && availCurveBits >= TlsEccUtilities.GetMinimumCurveBits(cipherSuite)
                && availFiniteFieldBits >= TlsDHUtilities.GetMinimumFiniteFieldBits(cipherSuite)
                && TlsUtilities.IsValidCipherSuiteForSignatureAlgorithms(cipherSuite, sigAlgs);
        }

        /// <summary>
        /// Determine whether the server's order of preference for cipher suites takes precedence over the client's.
        /// </summary>
        /// <returns>true if the server's preference is used, false if the client's is.</returns>
        protected virtual bool PreferLocalCipherSuites() => false;

        /// <summary>
        /// Determine whether the server's order of preference for supported groups takes precedence over the client's.
        /// </summary>
        /// <returns>true if the server's preference is used, false if the client's is.</returns>
        public virtual bool PreferLocalSupportedGroups() => false;

        /// <exception cref="IOException"/>
        protected virtual bool SelectCipherSuite(int cipherSuite)
        {
            m_selectedCipherSuite = cipherSuite;
            return true;
        }

        /// <summary>Select a finite field Diffie-Hellman group.</summary>
        /// <param name="minimumFiniteFieldBits">The minimum size in bits of the group.</param>
        /// <returns>The named group selected, or -1 if no suitable group is available.</returns>
        // TODO[api] Preferably return TlsDHConfig from here to support custom DH groups more easily
        protected virtual int SelectDH(int minimumFiniteFieldBits)
        {
            bool anyPeerFF = false;
            int[] clientSupportedGroups = m_context.SecurityParameters.ClientSupportedGroups;
            if (clientSupportedGroups != null)
            {
                // Try to find a supported named group of the required size from the client's list.
                for (int i = 0; i < clientSupportedGroups.Length; ++i)
                {
                    int namedGroup = clientSupportedGroups[i];
                    anyPeerFF |= NamedGroup.IsFiniteField(namedGroup);

                    if (NamedGroup.GetFiniteFieldBits(namedGroup) >= minimumFiniteFieldBits)
                    {
                        // This default server implementation supports all NamedGroup finite fields
                        return namedGroup;
                    }
                }
            }
            if (!anyPeerFF)
            {
                /*
                 * RFC 7919 4. If [...] the Supported Groups extension is either absent from the ClientHello
                 * entirely or contains no FFDHE groups (i.e., no codepoints between 256 and 511, inclusive), then
                 * the server [...] MAY select an FFDHE cipher suite and offer an FFDHE group of its choice [...].
                 */
                return SelectDHDefault(minimumFiniteFieldBits);
            }
            return -1;
        }

        /// <summary>Select a finite field Diffie-Hellman group.</summary>
        /// <param name="minimumFiniteFieldBits">The minimum size in bits of the group.</param>
        /// <returns>The named group selected, or -1 if no suitable group is available.</returns>
        // TODO[api] Preferably return TlsDHConfig from here to support custom DH groups more easily
        protected virtual int SelectDHDefault(int minimumFiniteFieldBits)
        {
            return minimumFiniteFieldBits <= 2048 ? NamedGroup.ffdhe2048
                :  minimumFiniteFieldBits <= 3072 ? NamedGroup.ffdhe3072
                :  minimumFiniteFieldBits <= 4096 ? NamedGroup.ffdhe4096
                :  minimumFiniteFieldBits <= 6144 ? NamedGroup.ffdhe6144
                :  minimumFiniteFieldBits <= 8192 ? NamedGroup.ffdhe8192
                :  -1;
        }

        /// <summary>Select an elliptic curve group.</summary>
        /// <param name="minimumCurveBits">The minimum size in bits of the curve.</param>
        /// <returns>The named group selected, or -1 if no suitable group is available.</returns>
        protected virtual int SelectECDH(int minimumCurveBits)
        {
            int[] clientSupportedGroups = m_context.SecurityParameters.ClientSupportedGroups;
            if (clientSupportedGroups == null)
            {
                /*
                 * RFC 4492 4. A client that proposes ECC cipher suites may choose not to include these
                 * extensions. In this case, the server is free to choose any one of the elliptic curves or point
                 * formats [...].
                 */
                return SelectECDHDefault(minimumCurveBits);
            }

            // Try to find a supported named group of the required size from the client's list.
            for (int i = 0; i < clientSupportedGroups.Length; ++i)
            {
                int namedGroup = clientSupportedGroups[i];
                if (NamedGroup.GetCurveBits(namedGroup) >= minimumCurveBits)
                {
                    // This default server implementation supports all NamedGroup curves
                    return namedGroup;
                }
            }

            return -1;
        }

        /// <summary>Select an elliptic curve group.</summary>
        /// <param name="minimumCurveBits">The minimum size in bits of the curve.</param>
        /// <returns>The named group selected, or -1 if no suitable group is available.</returns>
        protected virtual int SelectECDHDefault(int minimumCurveBits)
        {
            return minimumCurveBits <= 256 ? NamedGroup.secp256r1
                :  minimumCurveBits <= 384 ? NamedGroup.secp384r1
                :  minimumCurveBits <= 521 ? NamedGroup.secp521r1
                :  -1;
        }

        /// <summary>Select the application protocol to use from those offered by the client.</summary>
        /// <returns>The selected protocol name, or null if none is selected.</returns>
        protected virtual ProtocolName SelectProtocolName()
        {
            IList<ProtocolName> serverProtocolNames = GetProtocolNames();
            if (null == serverProtocolNames || serverProtocolNames.Count < 1)
                return null;

            ProtocolName result = SelectProtocolName(m_clientProtocolNames, serverProtocolNames);
            if (null == result)
                throw new TlsFatalAlert(AlertDescription.no_application_protocol);

            return result;
        }

        /// <summary>
        /// Select the application protocol to use, given the protocol names of the client and server.
        /// </summary>
        /// <param name="clientProtocolNames">The protocol names offered by the client.</param>
        /// <param name="serverProtocolNames">
        /// The protocol names supported by the server, in order of preference.
        /// </param>
        /// <returns>The selected protocol name, or null if none is selected.</returns>
        protected virtual ProtocolName SelectProtocolName(IList<ProtocolName> clientProtocolNames,
            IList<ProtocolName> serverProtocolNames)
        {
            foreach (ProtocolName serverProtocolName in serverProtocolNames)
            {
                if (clientProtocolNames.Contains(serverProtocolName))
                    return serverProtocolName;
            }
            return null;
        }

        /// <summary>Determine whether the application protocol should be selected before the cipher suite.</summary>
        /// <returns>true if the protocol name is selected early, false otherwise.</returns>
        protected virtual bool ShouldSelectProtocolNameEarly() => true;

        /// <summary>
        /// Determine whether the server's order of preference for client certificate types takes precedence over the
        /// client's.
        /// </summary>
        /// <returns>true if the server's preference is used, false if the client's is.</returns>
        protected virtual bool PreferLocalClientCertificateTypes() => false;

        /// <summary>Return the allowed client certificate types.</summary>
        protected virtual short[] GetAllowedClientCertificateTypes() => null;

        /// <summary>RFC 9146 DTLS connection ID.</summary>
        /// <remarks>
        /// This method will be called if a connection_id extension was sent by the client.
        /// If the return value is non-null, the server will send this connection ID to the client to use in future packets.
        /// As future communication doesn't include the connection IDs length, this should either be fixed-length
        /// or include the connection ID's length. (see explanation in RFC 9146 4. "cid:")
        /// </remarks>
        /// <returns>The connection ID to use.</returns>
        protected virtual byte[] GetNewConnectionID() => null;

        /// <inheritdoc/>
        public virtual void Init(TlsServerContext context)
        {
            m_context = context;

            m_protocolVersions = GetSupportedVersions();
            m_cipherSuites = GetSupportedCipherSuites();
        }

        /// <inheritdoc/>
        public override ProtocolVersion[] GetProtocolVersions() => m_protocolVersions;

        /// <inheritdoc/>
        public override int[] GetCipherSuites() => m_cipherSuites;

        /// <inheritdoc/>
        public override void NotifyHandshakeBeginning()
        {
            base.NotifyHandshakeBeginning();

            m_offeredCipherSuites = null;
            m_clientExtensions = null;
            m_encryptThenMACOffered = false;
            m_maxFragmentLengthOffered = 0;
            m_truncatedHMacOffered = false;
            m_clientSentECPointFormats = false;
            m_certificateStatusRequest = null;
            m_statusRequestV2 = null;
            m_trustedCAKeys = null;
            m_selectedCipherSuite = -1;
            m_selectedProtocolName = null;
            m_serverExtensions.Clear();
        }

        /// <inheritdoc/>
        public virtual TlsSession GetSessionToResume(byte[] sessionID) => null;

        /// <inheritdoc/>
        public virtual byte[] GetNewSessionID() => null;

        /// <inheritdoc/>
        public virtual TlsPskExternal GetExternalPsk(IList<PskIdentity> identities) => null;

        /// <inheritdoc/>
        public virtual void NotifySession(TlsSession session)
        {
        }

        /// <inheritdoc/>
        public virtual void NotifyClientVersion(ProtocolVersion clientVersion)
        {
        }

        /// <inheritdoc/>
        public virtual void NotifyFallback(bool isFallback)
        {
            /*
             * RFC 7507 3. If TLS_FALLBACK_SCSV appears in ClientHello.cipher_suites and the highest
             * protocol version supported by the server is higher than the version indicated in
             * ClientHello.client_version, the server MUST respond with a fatal inappropriate_fallback
             * alert [..].
             */
            if (isFallback)
            {
                ProtocolVersion[] serverVersions = GetProtocolVersions();
                ProtocolVersion clientVersion = m_context.ClientVersion;

                ProtocolVersion latestServerVersion;
                if (clientVersion.IsTls)
                {
                    latestServerVersion = ProtocolVersion.GetLatestTls(serverVersions);
                }
                else if (clientVersion.IsDtls)
                {
                    latestServerVersion = ProtocolVersion.GetLatestDtls(serverVersions);
                }
                else
                {
                    throw new TlsFatalAlert(AlertDescription.internal_error);
                }

                if (null != latestServerVersion && latestServerVersion.IsLaterVersionOf(clientVersion))
                {
                    throw new TlsFatalAlert(AlertDescription.inappropriate_fallback);
                }
            }
        }

        /// <inheritdoc/>
        public virtual void NotifyOfferedCipherSuites(int[] offeredCipherSuites)
        {
            m_offeredCipherSuites = offeredCipherSuites;
        }

        /// <inheritdoc/>
        public virtual void ProcessClientExtensions(IDictionary<int, byte[]> clientExtensions)
        {
            m_clientExtensions = clientExtensions;

            if (null != clientExtensions)
            {
                m_clientProtocolNames = TlsExtensionsUtilities.GetAlpnExtensionClient(clientExtensions);

                if (ShouldSelectProtocolNameEarly())
                {
                    if (null != m_clientProtocolNames && m_clientProtocolNames.Count > 0)
                    {
                        m_selectedProtocolName = SelectProtocolName();
                    }
                }

                // TODO[tls13] Don't need these if we have negotiated (D)TLS 1.3+
                {
                    m_encryptThenMACOffered = TlsExtensionsUtilities.HasEncryptThenMacExtension(clientExtensions);
                    m_truncatedHMacOffered = TlsExtensionsUtilities.HasTruncatedHmacExtension(clientExtensions);
                    m_statusRequestV2 = TlsExtensionsUtilities.GetStatusRequestV2Extension(clientExtensions);
                    m_trustedCAKeys = TlsExtensionsUtilities.GetTrustedCAKeysExtensionClient(clientExtensions);

                    // We only support uncompressed format, this is just to validate the extension, and note its presence.
                    m_clientSentECPointFormats =
                        null != TlsExtensionsUtilities.GetSupportedPointFormatsExtension(clientExtensions);
                }

                m_certificateStatusRequest = TlsExtensionsUtilities.GetStatusRequestExtension(clientExtensions);

                m_maxFragmentLengthOffered = TlsExtensionsUtilities.GetMaxFragmentLengthExtension(clientExtensions);
                if (m_maxFragmentLengthOffered >= 0 && !MaxFragmentLength.IsValid(m_maxFragmentLengthOffered))
                    throw new TlsFatalAlert(AlertDescription.illegal_parameter);
            }
        }

        /// <inheritdoc/>
        public virtual ProtocolVersion GetServerVersion()
        {
            ProtocolVersion[] serverVersions = GetProtocolVersions();
            ProtocolVersion[] clientVersions = m_context.ClientSupportedVersions;

            foreach (ProtocolVersion clientVersion in clientVersions)
            {
                if (ProtocolVersion.Contains(serverVersions, clientVersion))
                    return clientVersion;
            }

            throw new TlsFatalAlert(AlertDescription.protocol_version);
        }

        /// <inheritdoc/>
        public virtual int[] GetSupportedGroups()
        {
            // TODO[tls13] The rest of this class assumes all named groups are supported
            return new int[]{ NamedGroup.x25519, NamedGroup.x448, NamedGroup.secp256r1, NamedGroup.secp384r1,
                NamedGroup.ffdhe2048, NamedGroup.ffdhe3072, NamedGroup.ffdhe4096 };
        }

        /// <inheritdoc/>
        public virtual int GetSelectedCipherSuite()
        {
            SecurityParameters securityParameters = m_context.SecurityParameters;
            ProtocolVersion negotiatedVersion = securityParameters.NegotiatedVersion;

            if (TlsUtilities.IsTlsV13(negotiatedVersion))
            {
                int commonCipherSuite13 = TlsUtilities.GetCommonCipherSuite13(negotiatedVersion, m_offeredCipherSuites,
                    GetCipherSuites(), PreferLocalCipherSuites());

                if (commonCipherSuite13 >= 0 && SelectCipherSuite(commonCipherSuite13))
                {
                    return commonCipherSuite13;
                }
            }
            else
            {
                /*
                 * RFC 5246 7.4.3. In order to negotiate correctly, the server MUST check any candidate
                 * cipher suites against the "signature_algorithms" extension before selecting them. This is
                 * somewhat inelegant but is a compromise designed to minimize changes to the original
                 * cipher suite design.
                 */
                var sigAlgs = TlsUtilities.GetUsableSignatureAlgorithms(securityParameters.ClientSigAlgs);

                /*
                 * RFC 4429 5.1. A server that receives a ClientHello containing one or both of these
                 * extensions MUST use the client's enumerated capabilities to guide its selection of an
                 * appropriate cipher suite. One of the proposed ECC cipher suites must be negotiated only
                 * if the server can successfully complete the handshake while using the curves and point
                 * formats supported by the client [...].
                 */
                int availCurveBits = GetMaximumNegotiableCurveBits();
                int availFiniteFieldBits = GetMaximumNegotiableFiniteFieldBits();

                int[] cipherSuites = TlsUtilities.GetCommonCipherSuites(m_offeredCipherSuites, GetCipherSuites(),
                    PreferLocalCipherSuites());

                for (int i = 0; i < cipherSuites.Length; ++i)
                {
                    int cipherSuite = cipherSuites[i];
                    if (IsSelectableCipherSuite(cipherSuite, availCurveBits, availFiniteFieldBits, sigAlgs)
                        && SelectCipherSuite(cipherSuite))
                    {
                        return cipherSuite;
                    }
                }
            }

            throw new TlsFatalAlert(AlertDescription.handshake_failure, GetDetailMessageNoCipherSuite());
        }

        /// <inheritdoc/>
        // IDictionary is (Int32 -> byte[])
        public virtual IDictionary<int, byte[]> GetServerExtensions()
        {
            bool isTlsV13 = TlsUtilities.IsTlsV13(m_context);

            if (isTlsV13)
            {
                /*
                 * RFC 8446 4.4.2.1. There is no "status_request" echo to add here: the response travels in a
                 * "status_request" extension of the CertificateEntry containing the certificate it answers for, which
                 * TlsServerProtocol attaches from GetCertificateStatus(). Nor is "status_request_v2" honoured - RFC
                 * 8446 sec. 4.2.1 leaves it out of TLS 1.3.
                 */
            }
            else
            {
                if (m_encryptThenMACOffered && AllowEncryptThenMac())
                {
                    /*
                     * RFC 7366 3. If a server receives an encrypt-then-MAC request extension from a client
                     * and then selects a stream or Authenticated Encryption with Associated Data (AEAD)
                     * ciphersuite, it MUST NOT send an encrypt-then-MAC response extension back to the
                     * client.
                     */
                    if (TlsUtilities.IsBlockCipherSuite(m_selectedCipherSuite))
                    {
                        TlsExtensionsUtilities.AddEncryptThenMacExtension(m_serverExtensions);
                    }
                }

                if (m_truncatedHMacOffered && AllowTruncatedHmac())
                {
                    TlsExtensionsUtilities.AddTruncatedHmacExtension(m_serverExtensions);
                }

                if (m_clientSentECPointFormats && TlsEccUtilities.IsEccCipherSuite(m_selectedCipherSuite))
                {
                    /*
                     * RFC 4492 5.2. A server that selects an ECC cipher suite in response to a ClientHello
                     * message including a Supported Point Formats Extension appends this extension (along
                     * with others) to its ServerHello message, enumerating the point formats it can parse.
                     */
                    TlsExtensionsUtilities.AddSupportedPointFormatsExtension(m_serverExtensions,
                        new short[]{ ECPointFormat.uncompressed });
                }

                if (null != m_statusRequestV2 && AllowMultiCertStatus())
                {
                    /*
                     * RFC 6961 2.2. If a server returns a "CertificateStatus" message in response to a
                     * "status_request_v2" request, then the server MUST have included an extension of type
                     * "status_request_v2" with empty "extension_data" in the extended server hello..
                     */
                    TlsExtensionsUtilities.AddEmptyExtensionData(m_serverExtensions, ExtensionType.status_request_v2);
                }
                else if (null != m_certificateStatusRequest && AllowCertificateStatus())
                {
                    /*
                     * RFC 6066 8. If a server returns a "CertificateStatus" message, then the server MUST
                     * have included an extension of type "status_request" with empty "extension_data" in
                     * the extended server hello.
                     */
                    TlsExtensionsUtilities.AddEmptyExtensionData(m_serverExtensions, ExtensionType.status_request);
                }

                if (null != m_trustedCAKeys && AllowTrustedCAIndication())
                {
                    TlsExtensionsUtilities.AddTrustedCAKeysExtensionServer(m_serverExtensions);
                }
            }

            if (m_maxFragmentLengthOffered >= 0 && MaxFragmentLength.IsValid(m_maxFragmentLengthOffered))
            {
                TlsExtensionsUtilities.AddMaxFragmentLengthExtension(m_serverExtensions, m_maxFragmentLengthOffered);
            }

            // RFC 7250 4.2 for server_certificate_type
            short[] serverCertTypes = TlsExtensionsUtilities.GetServerCertificateTypeExtensionClient(
                m_clientExtensions);
            if (serverCertTypes != null)
            {
                TlsCredentials credentials = GetCredentials();
                if (credentials != null)
                {
                    // TODO An X509 certificate should still be usable as RawPublicKey
                    short serverCertificateType = credentials.Certificate.CertificateType;

                    if (CertificateType.OpenPGP == serverCertificateType && isTlsV13)
                    {
                        throw new TlsFatalAlert(AlertDescription.internal_error,
                            "The OpenPGP certificate type MUST NOT be used with TLS 1.3");
                    }

                    if (!Arrays.Contains(serverCertTypes, serverCertificateType))
                    {
                        // outcome 2: we support the extension but have no common types
                        throw new TlsFatalAlert(AlertDescription.unsupported_certificate);
                    }

                    // outcome 3: we support the extension and have a common type
                    TlsExtensionsUtilities.AddServerCertificateTypeExtensionServer(m_serverExtensions,
                        serverCertificateType);
                }
            }

            // TODO If we won't be sending a CertificateRequest, this extension can be ignored
            // RFC 7250 4.2 for client_certificate_type
            short[] remoteClientCertTypes = TlsExtensionsUtilities.GetClientCertificateTypeExtensionClient(
                m_clientExtensions);
            if (remoteClientCertTypes != null)
            {
                short[] localClientCertTypes = GetAllowedClientCertificateTypes();
                if (localClientCertTypes != null)
                {
                    short[] preferredTypes;
                    short[] nonPreferredTypes;
                    if (PreferLocalClientCertificateTypes())
                    {
                        preferredTypes = localClientCertTypes;
                        nonPreferredTypes = remoteClientCertTypes;
                    }
                    else
                    {
                        preferredTypes = remoteClientCertTypes;
                        nonPreferredTypes = localClientCertTypes;
                    }

                    short selectedType = -1;
                    for (int i = 0; i < preferredTypes.Length; i++)
                    {
                        short preferredType = preferredTypes[i];
                        if (CertificateType.OpenPGP == preferredType && isTlsV13)
                            continue;

                        if (Arrays.Contains(nonPreferredTypes, preferredType))
                        {
                            selectedType = preferredType;
                            break;
                        }
                    }

                    // TODO Shouldn't be an error unless we REQUIRE client authentication
                    if (selectedType == -1)
                    {
                        // outcome 2: we support the extension but have no common types
                        throw new TlsFatalAlert(AlertDescription.unsupported_certificate);
                    }

                    // outcome 3: we support the extension and have a common type
                    TlsExtensionsUtilities.AddClientCertificateTypeExtensionServer(m_serverExtensions, selectedType);
                } // else outcome 1: we don't support the extension
            }

            return m_serverExtensions;
        }

        /// <inheritdoc/>
        public virtual void GetServerExtensionsForConnection(IDictionary<int, byte[]> serverExtensions)
        {
            if (!ShouldSelectProtocolNameEarly())
            {
                if (null != m_clientProtocolNames && m_clientProtocolNames.Count > 0)
                {
                    m_selectedProtocolName = SelectProtocolName();
                }
            }

            /*
             * RFC 7301 3.1. When session resumption or session tickets [...] are used, the previous
             * contents of this extension are irrelevant, and only the values in the new handshake
             * messages are considered.
             */
            if (null == m_selectedProtocolName)
            {
                serverExtensions.Remove(ExtensionType.application_layer_protocol_negotiation);
            }
            else
            {
                TlsExtensionsUtilities.AddAlpnExtensionServer(serverExtensions, m_selectedProtocolName);
            }

            if (ProtocolVersion.DTLSv12.Equals(m_context.ServerVersion))
            {
                /*
                 * RFC 9146 3. When a DTLS session is resumed or renegotiated, the "connection_id" extension is
                 * negotiated afresh.
                 */
                if (m_clientExtensions != null && m_clientExtensions.ContainsKey(ExtensionType.connection_id))
                {
                    var serverConnectionID = GetNewConnectionID();
                    if (serverConnectionID != null)
                    {
                        TlsExtensionsUtilities.AddConnectionIDExtension(m_serverExtensions, serverConnectionID);
                    }
                }
            }
        }

        /// <inheritdoc/>
        public virtual IList<SupplementalDataEntry> GetServerSupplementalData() => null;

        /// <inheritdoc/>
        public abstract TlsCredentials GetCredentials();

        /// <inheritdoc/>
        public virtual CertificateStatus GetCertificateStatus() => null;

        /// <inheritdoc/>
        public virtual CertificateRequest GetCertificateRequest() => null;

        /// <inheritdoc/>
        public virtual TlsPskIdentityManager GetPskIdentityManager() => null;

        /// <inheritdoc/>
        public virtual TlsSrpLoginParameters GetSrpLoginParameters() => null;

        /// <inheritdoc/>
        public virtual TlsDHConfig GetDHConfig()
        {
            int minimumFiniteFieldBits = TlsDHUtilities.GetMinimumFiniteFieldBits(m_selectedCipherSuite);
            int namedGroup = SelectDH(minimumFiniteFieldBits);
            return TlsDHUtilities.CreateNamedDHConfig(m_context, namedGroup);
        }

        /// <inheritdoc/>
        public virtual TlsECConfig GetECDHConfig()
        {
            int minimumCurveBits = TlsEccUtilities.GetMinimumCurveBits(m_selectedCipherSuite);
            int namedGroup = SelectECDH(minimumCurveBits);
            return TlsEccUtilities.CreateNamedECConfig(m_context, namedGroup);
        }

        /// <inheritdoc/>
        public virtual void ProcessClientSupplementalData(IList<SupplementalDataEntry> clientSupplementalData)
        {
            if (clientSupplementalData != null)
                throw new TlsFatalAlert(AlertDescription.unexpected_message);
        }

        /// <inheritdoc/>
        public virtual void NotifyClientCertificate(Certificate clientCertificate) =>
            throw new TlsFatalAlert(AlertDescription.internal_error);

        /// <inheritdoc/>
        public virtual NewSessionTicket GetNewSessionTicket()
        {
            /*
             * RFC 5077 3.3. If the server determines that it does not want to include a ticket after it
             * has included the SessionTicket extension in the ServerHello, then it sends a zero-length
             * ticket in the NewSessionTicket handshake message.
             */
            return new NewSessionTicket(0L, TlsUtilities.EmptyBytes);
        }
    }
}
