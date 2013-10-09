using Org.BouncyCastle.Crypto.Prng;
using Org.BouncyCastle.Security;
using System;
using Org.BouncyCastle.Ocsp;
using System.IO;
using System.Collections.Generic;
using Org.BouncyCastle.Utilities;
using System.Collections;

namespace Org.BouncyCastle.Crypto.Tls
{

    public class TlsClientProtocol : TlsProtocol
    {
        protected TlsClient tlsClient = null;
        internal TlsClientContextImpl tlsClientContext = null;

        protected byte[] selectedSessionID = null;

        protected TlsKeyExchange keyExchange = null;
        protected TlsAuthentication authentication = null;

        protected CertificateStatus certificateStatus = null;
        protected CertificateRequest certificateRequest = null;

        private static SecureRandom CreateSecureRandom()
        {
            /*
             * We use our threaded seed generator to generate a good random seed. If the user has a
             * better random seed, he should use the constructor with a SecureRandom.
             */
            ThreadedSeedGenerator tsg = new ThreadedSeedGenerator();
            SecureRandom random = new SecureRandom();

            /*
             * Hopefully, 20 bytes in fast mode are good enough.
             */
            random.SetSeed(tsg.GenerateSeed(20, true));

            return random;
        }

        public TlsClientProtocol(Stream stream)
            : this(stream, stream)
        {

        }

        public TlsClientProtocol(Stream input, Stream output)
            : this(input, output, CreateSecureRandom())
        {

        }

        public TlsClientProtocol(Stream input, Stream output, SecureRandom secureRandom)
            : base(input, output, secureRandom)
        {
        }

        /**
         * Initiates a TLS handshake in the role of client
         *
         * @param tlsClient The {@link TlsClient} to use for the handshake.
         * @throws IOException If handshake was not successful.
         */
        public void Connect(TlsClient tlsClient)
        {
            if (tlsClient == null)
            {
                throw new ArgumentException("'tlsClient' cannot be null");
            }
            if (this.tlsClient != null)
            {
                throw new InvalidOperationException("'connect' can only be called once");
            }

            this.tlsClient = tlsClient;

            this.securityParameters = new SecurityParameters();
            this.securityParameters.entity = ConnectionEnd.client;
            this.securityParameters.clientRandom = CreateRandomBlock(secureRandom);

            this.tlsClientContext = new TlsClientContextImpl(secureRandom, securityParameters);
            this.tlsClient.Init(tlsClientContext);
            this.recordStream.Init(tlsClientContext);

            TlsSession sessionToResume = tlsClient.SessionToResume;
            if (sessionToResume != null)
            {
                SessionParameters sessionParameters = sessionToResume.ExportSessionParameters();
                if (sessionParameters != null)
                {
                    this.tlsSession = sessionToResume;
                    this.sessionParameters = sessionParameters;
                }
            }

            SendClientHelloMessage();
            this.connection_state = CS_CLIENT_HELLO;

            CompleteHandshake();
        }

        protected override void CleanupHandshake()
        {
            base.CleanupHandshake();

            this.selectedSessionID = null;
            this.keyExchange = null;
            this.authentication = null;
            this.certificateStatus = null;
            this.certificateRequest = null;
        }

        protected override AbstractTlsContext Context
        {
            get
            {
                return tlsClientContext;
            }
        }

        protected override TlsPeer Peer
        {
            get
            {
                return tlsClient;
            }
        }

        protected override void HandleHandshakeMessage(HandshakeType type, byte[] data)
        {
            MemoryStream buf = new MemoryStream(data);

            if (this.resumedSession)
            {
                if (type != HandshakeType.finished || this.connection_state != CS_SERVER_HELLO)
                {
                    throw new TlsFatalAlert(AlertDescription.unexpected_message);
                }

                ProcessFinishedMessage(buf);
                this.connection_state = CS_SERVER_FINISHED;

                SendFinishedMessage();
                this.connection_state = CS_CLIENT_FINISHED;
                this.connection_state = CS_END;

                return;
            }

            switch (type)
            {
                case HandshakeType.certificate:
                    {
                        switch (this.connection_state)
                        {
                            case CS_SERVER_HELLO:
                                {
                                    HandleSupplementalData(null);
                                    // NB: Fall through to next case label
                                    goto case CS_SERVER_SUPPLEMENTAL_DATA;
                                }
                            case CS_SERVER_SUPPLEMENTAL_DATA:
                                {
                                    // Parse the Certificate message and send to cipher suite

                                    this.peerCertificate = Certificate.Parse(buf);

                                    AssertEmpty(buf);

                                    // TODO[RFC 3546] Check whether empty certificates is possible, allowed, or excludes CertificateStatus
                                    if (this.peerCertificate == null || this.peerCertificate.IsEmpty)
                                    {
                                        this.allowCertificateStatus = false;
                                    }

                                    this.keyExchange.ProcessServerCertificate(this.peerCertificate);

                                    this.authentication = tlsClient.GetAuthentication();
                                    this.authentication.NotifyServerCertificate(this.peerCertificate);

                                    break;
                                }
                            default:
                                throw new TlsFatalAlert(AlertDescription.unexpected_message);
                        }

                        this.connection_state = CS_SERVER_CERTIFICATE;
                        break;
                    }
                case HandshakeType.certificate_status:
                    {
                        switch (this.connection_state)
                        {
                            case CS_SERVER_CERTIFICATE:
                                {
                                    if (!this.allowCertificateStatus)
                                    {
                                        /*
                                         * RFC 3546 3.6. If a server returns a "CertificateStatus" message, then the
                                         * server MUST have included an extension of type "status_request" with empty
                                         * "extension_data" in the extended server hello..
                                         */
                                        throw new TlsFatalAlert(AlertDescription.unexpected_message);
                                    }

                                    this.certificateStatus = CertificateStatus.parse(buf);

                                    AssertEmpty(buf);

                                    // TODO[RFC 3546] Figure out how to provide this to the client/authentication.

                                    this.connection_state = CS_CERTIFICATE_STATUS;
                                    break;
                                }
                            default:
                                throw new TlsFatalAlert(AlertDescription.unexpected_message);
                        }
                        break;
                    }
                case HandshakeType.finished:
                    {
                        switch (this.connection_state)
                        {
                            case CS_CLIENT_FINISHED:
                                {
                                    ProcessFinishedMessage(buf);
                                    this.connection_state = CS_SERVER_FINISHED;
                                    this.connection_state = CS_END;
                                    break;
                                }
                            default:
                                throw new TlsFatalAlert(AlertDescription.unexpected_message);
                        }
                        break;
                    }
                case HandshakeType.server_hello:
                    {
                        switch (this.connection_state)
                        {
                            case CS_CLIENT_HELLO:
                                {
                                    ReceiveServerHelloMessage(buf);
                                    this.connection_state = CS_SERVER_HELLO;

                                    if (this.securityParameters.maxFragmentLength >= 0)
                                    {
                                        int plainTextLimit = 1 << (8 + this.securityParameters.maxFragmentLength);
                                        recordStream.PlaintextLimit = plainTextLimit;
                                    }

                                    this.securityParameters.prfAlgorithm = GetPRFAlgorithm(Context,
                                        this.securityParameters.CipherSuite);

                                    /*
                                     * RFC 5264 7.4.9. Any cipher suite which does not explicitly specify
                                     * verify_data_length has a verify_data_length equal to 12. This includes all
                                     * existing cipher suites.
                                     */
                                    this.securityParameters.verifyDataLength = 12;

                                    this.recordStream.NotifyHelloComplete();

                                    if (this.resumedSession)
                                    {
                                        this.securityParameters.masterSecret = Arrays.Clone(this.sessionParameters.MasterSecret);
                                        this.recordStream.SetPendingConnectionState(Peer.GetCompression(), Peer.GetCipher());

                                        SendChangeCipherSpecMessage();
                                    }
                                    else
                                    {
                                        InvalidateSession();

                                        if (this.selectedSessionID.Length > 0)
                                        {
                                            this.tlsSession = new TlsSessionImpl(this.selectedSessionID, null);
                                        }
                                    }

                                    break;
                                }
                            default:
                                throw new TlsFatalAlert(AlertDescription.unexpected_message);
                        }
                        break;
                    }
                case HandshakeType.supplemental_data:
                    {
                        switch (this.connection_state)
                        {
                            case CS_SERVER_HELLO:
                                {
                                    HandleSupplementalData(ReadSupplementalDataMessage(buf));
                                    break;
                                }
                            default:
                                throw new TlsFatalAlert(AlertDescription.unexpected_message);
                        }
                        break;
                    }
                case HandshakeType.server_hello_done:
                    {
                        switch (this.connection_state)
                        {
                            case CS_SERVER_HELLO:
                                {
                                    HandleSupplementalData(null);
                                    // NB: Fall through to next case label
                                    goto case CS_SERVER_SUPPLEMENTAL_DATA;
                                }
                            case CS_SERVER_SUPPLEMENTAL_DATA:
                                {
                                    // There was no server certificate message; check it's OK
                                    this.keyExchange.SkipServerCredentials();
                                    this.authentication = null;

                                    // NB: Fall through to next case label
                                    goto case CS_SERVER_CERTIFICATE;
                                }
                            case CS_SERVER_CERTIFICATE:
                            case CS_CERTIFICATE_STATUS:
                                {
                                    // There was no server key exchange message; check it's OK
                                    this.keyExchange.SkipServerKeyExchange();

                                    // NB: Fall through to next case label
                                    goto case CS_SERVER_KEY_EXCHANGE;
                                }
                            case CS_SERVER_KEY_EXCHANGE:
                            case CS_CERTIFICATE_REQUEST:
                                {
                                    AssertEmpty(buf);

                                    this.connection_state = CS_SERVER_HELLO_DONE;

                                    IList clientSupplementalData = tlsClient.GetClientSupplementalData();
                                    if (clientSupplementalData != null)
                                    {
                                        SendSupplementalDataMessage(clientSupplementalData);
                                    }
                                    this.connection_state = CS_CLIENT_SUPPLEMENTAL_DATA;

                                    TlsCredentials clientCreds = null;
                                    if (certificateRequest == null)
                                    {
                                        this.keyExchange.SkipClientCredentials();
                                    }
                                    else
                                    {
                                        clientCreds = this.authentication.GetClientCredentials(certificateRequest);

                                        if (clientCreds == null)
                                        {
                                            this.keyExchange.SkipClientCredentials();

                                            /*
                                             * RFC 5246 If no suitable certificate is available, the client MUST send a
                                             * certificate message containing no certificates.
                                             * 
                                             * NOTE: In previous RFCs, this was SHOULD instead of MUST.
                                             */
                                            SendCertificateMessage(Certificate.EmptyChain);
                                        }
                                        else
                                        {
                                            this.keyExchange.ProcessClientCredentials(clientCreds);

                                            SendCertificateMessage(clientCreds.Certificate);
                                        }
                                    }

                                    this.connection_state = CS_CLIENT_CERTIFICATE;

                                    /*
                                     * Send the client key exchange message, depending on the key exchange we are using
                                     * in our CipherSuite.
                                     */
                                    SendClientKeyExchangeMessage();
                                    this.connection_state = CS_CLIENT_KEY_EXCHANGE;

                                    EstablishMasterSecret(Context, keyExchange);
                                    recordStream.SetPendingConnectionState(Peer.GetCompression(), Peer.GetCipher());

                                    if (clientCreds != null && clientCreds is TlsSignerCredentials)
                                    {
                                        TlsSignerCredentials signerCreds = (TlsSignerCredentials)clientCreds;
                                        byte[] md5andsha1 = recordStream.GetCurrentHash(null);
                                        byte[] signature = signerCreds.GenerateCertificateSignature(md5andsha1);
                                        /*
                                         * TODO RFC 5246 4.7. digitally-signed element needs SignatureAndHashAlgorithm from TLS 1.2
                                         */
                                        DigitallySigned certificateVerify = new DigitallySigned(null, signature);
                                        SendCertificateVerifyMessage(certificateVerify);

                                        this.connection_state = CS_CERTIFICATE_VERIFY;
                                    }

                                    SendChangeCipherSpecMessage();
                                    SendFinishedMessage();
                                    this.connection_state = CS_CLIENT_FINISHED;
                                    break;
                                }
                            default:
                                throw new TlsFatalAlert(AlertDescription.handshake_failure);
                        }
                        break;
                    }
                case HandshakeType.server_key_exchange:
                    {
                        switch (this.connection_state)
                        {
                            case CS_SERVER_HELLO:
                                {
                                    HandleSupplementalData(null);
                                    // NB: Fall through to next case label
                                    goto case CS_SERVER_SUPPLEMENTAL_DATA;
                                }
                            case CS_SERVER_SUPPLEMENTAL_DATA:
                                {
                                    // There was no server certificate message; check it's OK
                                    this.keyExchange.SkipServerCredentials();
                                    this.authentication = null;

                                    // NB: Fall through to next case label
                                    goto case CS_SERVER_CERTIFICATE;
                                }
                            case CS_SERVER_CERTIFICATE:
                            case CS_CERTIFICATE_STATUS:
                                {
                                    this.keyExchange.ProcessServerKeyExchange(buf);

                                    AssertEmpty(buf);
                                    break;
                                }
                            default:
                                throw new TlsFatalAlert(AlertDescription.unexpected_message);
                        }

                        this.connection_state = CS_SERVER_KEY_EXCHANGE;
                        break;
                    }
                case HandshakeType.certificate_request:
                    {
                        switch (this.connection_state)
                        {
                            case CS_SERVER_CERTIFICATE:
                            case CS_CERTIFICATE_STATUS:
                                {
                                    // There was no server key exchange message; check it's OK
                                    this.keyExchange.SkipServerKeyExchange();

                                    // NB: Fall through to next case label
                                    goto case CS_SERVER_KEY_EXCHANGE;
                                }
                            case CS_SERVER_KEY_EXCHANGE:
                                {
                                    if (this.authentication == null)
                                    {
                                        /*
                                         * RFC 2246 7.4.4. It is a fatal handshake_failure alert for an anonymous server
                                         * to request client identification.
                                         */
                                        throw new TlsFatalAlert(AlertDescription.handshake_failure);
                                    }

                                    this.certificateRequest = CertificateRequest.Parse(Context, buf);

                                    AssertEmpty(buf);

                                    this.keyExchange.ValidateCertificateRequest(this.certificateRequest);

                                    break;
                                }
                            default:
                                throw new TlsFatalAlert(AlertDescription.unexpected_message);
                        }

                        this.connection_state = CS_CERTIFICATE_REQUEST;
                        break;
                    }
                case HandshakeType.session_ticket:
                    {
                        switch (this.connection_state)
                        {
                            case CS_CLIENT_FINISHED:
                                {
                                    if (!this.expectSessionTicket)
                                    {
                                        /*
                                         * RFC 5077 3.3. This message MUST NOT be sent if the server did not include a
                                         * SessionTicket extension in the ServerHello.
                                         */
                                        throw new TlsFatalAlert(AlertDescription.unexpected_message);
                                    }

                                    /*
                                     * RFC 5077 3.4. If the client receives a session ticket from the server, then it
                                     * discards any Session ID that was sent in the ServerHello.
                                     */
                                    InvalidateSession();

                                    ReceiveNewSessionTicketMessage(buf);
                                    this.connection_state = CS_SERVER_SESSION_TICKET;
                                    break;
                                }
                            default:
                                throw new TlsFatalAlert(AlertDescription.unexpected_message);
                        }
                        break;
                    }
                case HandshakeType.hello_request:
                    {
                        AssertEmpty(buf);

                        /*
                         * RFC 2246 7.4.1.1 Hello request This message will be ignored by the client if the
                         * client is currently negotiating a session. This message may be ignored by the client
                         * if it does not wish to renegotiate a session, or the client may, if it wishes,
                         * respond with a no_renegotiation alert.
                         */
                        if (this.connection_state == CS_END)
                        {
                            String message = "Renegotiation not supported";
                            RaiseWarning(AlertDescription.no_renegotiation, message);
                        }
                        break;
                    }
                case HandshakeType.client_hello:
                case HandshakeType.client_key_exchange:
                case HandshakeType.certificate_verify:
                case HandshakeType.hello_verify_request:
                default:
                    throw new TlsFatalAlert(AlertDescription.unexpected_message);
            }
        }

        protected void HandleSupplementalData(IList serverSupplementalData)
        {
            this.tlsClient.ProcessServerSupplementalData(serverSupplementalData);
            this.connection_state = CS_SERVER_SUPPLEMENTAL_DATA;

            this.keyExchange = tlsClient.GetKeyExchange();
            this.keyExchange.Init(Context);
        }

        protected void ReceiveNewSessionTicketMessage(MemoryStream buf)
        {
            NewSessionTicket newSessionTicket = NewSessionTicket.Parse(buf);

            TlsProtocol.AssertEmpty(buf);

            tlsClient.NotifyNewSessionTicket(newSessionTicket);
        }

        protected void ReceiveServerHelloMessage(MemoryStream buf)
        {
            ProtocolVersion server_version = TlsUtilities.ReadVersion(buf);
            if (server_version.IsDTLS)
            {
                throw new TlsFatalAlert(AlertDescription.illegal_parameter);
            }

            // Check that this matches what the server is sending in the record layer
            if (!server_version.Equals(this.recordStream.ReadVersion))
            {
                throw new TlsFatalAlert(AlertDescription.illegal_parameter);
            }

            ProtocolVersion client_version = Context.ClientVersion;
            if (!server_version.IsEqualOrEarlierVersionOf(client_version))
            {
                throw new TlsFatalAlert(AlertDescription.illegal_parameter);
            }

            this.recordStream.SetWriteVersion(server_version);
            Context.ServerVersion = server_version;
            this.tlsClient.NotifyServerVersion(server_version);

            /*
             * Read the server random
             */
            this.securityParameters.serverRandom = TlsUtilities.ReadFully(32, buf);

            this.selectedSessionID = TlsUtilities.ReadOpaque8(buf);
            if (this.selectedSessionID.Length > 32)
            {
                throw new TlsFatalAlert(AlertDescription.illegal_parameter);
            }

            this.tlsClient.NotifySessionID(this.selectedSessionID);

            this.resumedSession = this.selectedSessionID.Length > 0 && this.tlsSession != null
                && Arrays.AreEqual(this.selectedSessionID, this.tlsSession.GetSessionID());

            /*
             * Find out which CipherSuite the server has chosen and check that it was one of the offered
             * ones.
             */
            CipherSuite selectedCipherSuite = (CipherSuite)TlsUtilities.ReadUint16(buf);
            if (!ArrayContains(this.offeredCipherSuites, selectedCipherSuite)
                || selectedCipherSuite == CipherSuite.TLS_NULL_WITH_NULL_NULL
                || selectedCipherSuite == CipherSuite.TLS_EMPTY_RENEGOTIATION_INFO_SCSV)
            {
                throw new TlsFatalAlert(AlertDescription.illegal_parameter);
            }

            this.tlsClient.NotifySelectedCipherSuite(selectedCipherSuite);

            /*
             * Find out which CompressionMethod the server has chosen and check that it was one of the
             * offered ones.
             */
            CompressionMethod selectedCompressionMethod = (CompressionMethod)TlsUtilities.ReadUint8(buf);
            if (!ArrayContains(this.offeredCompressionMethods, selectedCompressionMethod))
            {
                throw new TlsFatalAlert(AlertDescription.illegal_parameter);
            }

            this.tlsClient.NotifySelectedCompressionMethod(selectedCompressionMethod);

            /*
             * RFC3546 2.2 The extended server hello message format MAY be sent in place of the server
             * hello message when the client has requested extended functionality via the extended
             * client hello message specified in Section 2.1. ... Note that the extended server hello
             * message is only sent in response to an extended client hello message. This prevents the
             * possibility that the extended server hello message could "break" existing TLS 1.0
             * clients.
             */
            this.serverExtensions = ReadExtensions(buf);

            /*
             * RFC 3546 2.2 Note that the extended server hello message is only sent in response to an
             * extended client hello message.
             * 
             * However, see RFC 5746 exception below. We always include the SCSV, so an Extended Server
             * Hello is always allowed.
             */
            if (this.serverExtensions != null)
            {
                foreach (var e in this.serverExtensions.Keys)
                {

                    var extType = (ExtensionType)e;

                    /*
                     * RFC 5746 3.6. Note that sending a "renegotiation_info" extension in response to a
                     * ClientHello containing only the SCSV is an explicit exception to the prohibition
                     * in RFC 5246, Section 7.4.1.4, on the server sending unsolicited extensions and is
                     * only allowed because the client is signaling its willingness to receive the
                     * extension via the TLS_EMPTY_RENEGOTIATION_INFO_SCSV SCSV.
                     */
                    if (extType.Equals(EXT_RenegotiationInfo))
                    {
                        continue;
                    }

                    /*
                     * RFC 3546 2.3. If [...] the older session is resumed, then the server MUST ignore
                     * extensions appearing in the client hello, and send a server hello containing no
                     * extensions[.]
                     */
                    if (this.resumedSession)
                    {
                        // TODO[compat-gnutls] GnuTLS test server sends server extensions e.g. ec_point_formats
                        // TODO[compat-openssl] OpenSSL test server sends server extensions e.g. ec_point_formats
                        throw new TlsFatalAlert(AlertDescription.illegal_parameter);
                    }

                    /*
                     * RFC 5246 7.4.1.4 An extension type MUST NOT appear in the ServerHello unless the
                     * same extension type appeared in the corresponding ClientHello. If a client
                     * receives an extension type in ServerHello that it did not request in the
                     * associated ClientHello, it MUST abort the handshake with an unsupported_extension
                     * fatal alert.
                     */
                    if (null == TlsUtilities.GetExtensionData(this.clientExtensions, extType))
                    {
                        throw new TlsFatalAlert(AlertDescription.unsupported_extension);
                    }
                }
            }

            /*
             * RFC 5746 3.4. Client Behavior: Initial Handshake
             */
            {
                /*
                 * When a ServerHello is received, the client MUST check if it includes the
                 * "renegotiation_info" extension:
                 */
                byte[] renegExtData = TlsUtilities.GetExtensionData(this.serverExtensions, EXT_RenegotiationInfo);
                if (renegExtData != null)
                {
                    /*
                     * If the extension is present, set the secure_renegotiation flag to TRUE. The
                     * client MUST then verify that the length of the "renegotiated_connection"
                     * field is zero, and if it is not, MUST abort the handshake (by sending a fatal
                     * handshake_failure alert).
                     */
                    this.secure_renegotiation = true;

                    if (!Arrays.ConstantTimeAreEqual(renegExtData, CreateRenegotiationInfo(TlsUtilities.EMPTY_BYTES)))
                    {
                        throw new TlsFatalAlert(AlertDescription.handshake_failure);
                    }
                }
            }

            // TODO[compat-gnutls] GnuTLS test server fails to send renegotiation_info extension when resuming
            this.tlsClient.NotifySecureRenegotiation(this.secure_renegotiation);

            IDictionary sessionClientExtensions = clientExtensions, sessionServerExtensions = serverExtensions;
            if (this.resumedSession)
            {
                if (selectedCipherSuite != this.sessionParameters.CipherSuite
                    || selectedCompressionMethod != this.sessionParameters.CompressionAlgorithm)
                {
                    throw new TlsFatalAlert(AlertDescription.illegal_parameter);
                }

                sessionClientExtensions = null;
                sessionServerExtensions = this.sessionParameters.ReadServerExtensions();
            }

            this.securityParameters.cipherSuite = selectedCipherSuite;
            this.securityParameters.compressionAlgorithm = selectedCompressionMethod;

            if (sessionServerExtensions != null)
            {
                this.securityParameters.maxFragmentLength = ProcessMaxFragmentLengthExtension(sessionClientExtensions,
                    sessionServerExtensions, AlertDescription.illegal_parameter);

                this.securityParameters.truncatedHMac = TlsExtensionsUtils.HasTruncatedHMacExtension(sessionServerExtensions);

                /*
                 * TODO It's surprising that there's no provision to allow a 'fresh' CertificateStatus to be sent in
                 * a session resumption handshake.
                 */
                this.allowCertificateStatus = !this.resumedSession
                    && TlsUtilities.HasExpectedEmptyExtensionData(sessionServerExtensions,
                        TlsExtensionsUtils.EXT_status_request, AlertDescription.illegal_parameter);

                this.expectSessionTicket = !this.resumedSession
                    && TlsUtilities.HasExpectedEmptyExtensionData(sessionServerExtensions, TlsProtocol.EXT_SessionTicket,
                        AlertDescription.illegal_parameter);
            }

            if (sessionClientExtensions != null)
            {
                this.tlsClient.ProcessServerExtensions(sessionServerExtensions);
            }
        }

        protected void SendCertificateVerifyMessage(DigitallySigned certificateVerify)
        {
            HandshakeMessage message = new HandshakeMessage(this, HandshakeType.certificate_verify);

            certificateVerify.Encode(message);

            message.WriteToRecordStream();
        }

        protected void SendClientHelloMessage()
        {
            this.recordStream.SetWriteVersion(this.tlsClient.ClientHelloRecordLayerVersion);

            ProtocolVersion client_version = this.tlsClient.ClientVersion;
            if (client_version.IsDTLS)
            {
                throw new TlsFatalAlert(AlertDescription.internal_error);
            }

            Context.ClientVersion = client_version;

            /*
             * TODO RFC 5077 3.4. When presenting a ticket, the client MAY generate and include a
             * Session ID in the TLS ClientHello.
             */
            byte[] session_id = TlsUtilities.EMPTY_BYTES;
            if (this.tlsSession != null)
            {
                session_id = this.tlsSession.GetSessionID();
                if (session_id == null || session_id.Length > 32)
                {
                    session_id = TlsUtilities.EMPTY_BYTES;
                }
            }

            this.offeredCipherSuites = this.tlsClient.GetCipherSuites();

            this.offeredCompressionMethods = this.tlsClient.GetCompressionMethods();

            if (session_id.Length > 0 && this.sessionParameters != null)
            {
                if (!ArrayContains(this.offeredCipherSuites, sessionParameters.CipherSuite)
                    || !ArrayContains(this.offeredCompressionMethods, sessionParameters.CompressionAlgorithm))
                {
                    session_id = TlsUtilities.EMPTY_BYTES;
                }
            }

            this.clientExtensions = this.tlsClient.GetClientExtensions();

            HandshakeMessage message = new HandshakeMessage(this, HandshakeType.client_hello);

            TlsUtilities.WriteVersion(client_version, message);

            var clientRandom = this.securityParameters.ClientRandom;

            message.Write(clientRandom, 0, clientRandom.Length);

            TlsUtilities.WriteOpaque8(session_id, message);

            // Cipher Suites (and SCSV)
            {
                /*
                 * RFC 5746 3.4. The client MUST include either an empty "renegotiation_info" extension,
                 * or the TLS_EMPTY_RENEGOTIATION_INFO_SCSV signaling cipher suite value in the
                 * ClientHello. Including both is NOT RECOMMENDED.
                 */
                byte[] renegExtData = TlsUtilities.GetExtensionData(clientExtensions, EXT_RenegotiationInfo);
                bool noRenegExt = (null == renegExtData);

                int count = offeredCipherSuites.Length;
                if (noRenegExt)
                {
                    // Note: 1 extra slot for TLS_EMPTY_RENEGOTIATION_INFO_SCSV
                    ++count;
                }

                int length = 2 * count;
                TlsUtilities.CheckUint16(length);
                TlsUtilities.WriteUint16(length, message);
                TlsUtilities.WriteUint16Array(offeredCipherSuites, message);

                if (noRenegExt)
                {
                    TlsUtilities.WriteUint16((int)CipherSuite.TLS_EMPTY_RENEGOTIATION_INFO_SCSV, message);
                }
            }

            TlsUtilities.CheckUint8(offeredCompressionMethods.Length);
            TlsUtilities.WriteUint8(offeredCompressionMethods.Length, message);
            TlsUtilities.WriteUint8Array(offeredCompressionMethods, message);

            if (clientExtensions != null)
            {
                WriteExtensions(message, clientExtensions);
            }

            message.WriteToRecordStream();
        }

        protected void SendClientKeyExchangeMessage()
        {
            HandshakeMessage message = new HandshakeMessage(this, HandshakeType.client_key_exchange);

            this.keyExchange.GenerateClientKeyExchange(message);

            message.WriteToRecordStream();
        }
    }

}