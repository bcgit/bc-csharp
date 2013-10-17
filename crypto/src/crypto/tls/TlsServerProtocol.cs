using System;
using System.IO;
using Org.BouncyCastle.Security;
using Org.BouncyCastle.Asn1.X509;
using Org.BouncyCastle.Utilities;
using System.Collections;

namespace Org.BouncyCastle.Crypto.Tls
{

    public class TlsServerProtocol : TlsProtocol
    {
        protected TlsServer tlsServer = null;
        internal TlsServerContextImpl tlsServerContext = null;

        protected TlsKeyExchange keyExchange = null;
        protected TlsCredentials serverCredentials = null;
        protected CertificateRequest certificateRequest = null;

        protected ClientCertificateType clientCertificateType = ClientCertificateType.empty;
        protected byte[] certificateVerifyHash = null;

        public TlsServerProtocol(Stream input, Stream output, SecureRandom secureRandom)
            : base(input, output, secureRandom)
        {

        }

        /**
         * Receives a TLS handshake in the role of server
         *
         * @param tlsServer
         * @ If handshake was not successful.
         */
        public void Accept(TlsServer tlsServer)
        {
            if (tlsServer == null)
            {
                throw new ArgumentException("'tlsServer' cannot be null");
            }
            if (this.tlsServer != null)
            {
                throw new InvalidOperationException("'accept' can only be called once");
            }

            this.tlsServer = tlsServer;

            this.securityParameters = new SecurityParameters();
            this.securityParameters.entity = ConnectionEnd.server;
            this.securityParameters.serverRandom = CreateRandomBlock(secureRandom);

            this.tlsServerContext = new TlsServerContextImpl(secureRandom, securityParameters);
            this.tlsServer.Init(tlsServerContext);
            this.recordStream.Init(tlsServerContext);

            this.recordStream.SetRestrictReadVersion(false);

            CompleteHandshake();
        }

        protected override void CleanupHandshake()
        {
            base.CleanupHandshake();

            this.keyExchange = null;
            this.serverCredentials = null;
            this.certificateRequest = null;
            this.certificateVerifyHash = null;
        }

        protected override AbstractTlsContext Context
        {
            get
            {
                return tlsServerContext;
            }
        }

        protected override TlsPeer Peer
        {
            get
            {
                return tlsServer;
            }
        }

        protected override void HandleHandshakeMessage(HandshakeType type, byte[] data)
        {
            MemoryStream buf = new MemoryStream(data);

            switch (type)
            {
                case HandshakeType.client_hello:
                    {
                        switch (this.connection_state)
                        {
                            case CS_START:
                                {
                                    ReceiveClientHelloMessage(buf);
                                    this.connection_state = CS_CLIENT_HELLO;

                                    SendServerHelloMessage();
                                    this.connection_state = CS_SERVER_HELLO;

                                    var serverSupplementalData = tlsServer.GetServerSupplementalData();
                                    if (serverSupplementalData != null)
                                    {
                                        SendSupplementalDataMessage(serverSupplementalData);
                                    }
                                    this.connection_state = CS_SERVER_SUPPLEMENTAL_DATA;

                                    this.keyExchange = tlsServer.GetKeyExchange();
                                    this.keyExchange.Init(Context);

                                    this.serverCredentials = tlsServer.Credentials;

                                    Certificate serverCertificate = null;

                                    if (this.serverCredentials == null)
                                    {
                                        this.keyExchange.SkipServerCredentials();
                                    }
                                    else
                                    {
                                        this.keyExchange.ProcessServerCredentials(this.serverCredentials);

                                        serverCertificate = this.serverCredentials.Certificate;
                                        SendCertificateMessage(serverCertificate);
                                    }
                                    this.connection_state = CS_SERVER_CERTIFICATE;

                                    // TODO[RFC 3546] Check whether empty certificates is possible, allowed, or excludes CertificateStatus
                                    if (serverCertificate == null || serverCertificate.IsEmpty)
                                    {
                                        this.allowCertificateStatus = false;
                                    }

                                    if (this.allowCertificateStatus)
                                    {
                                        CertificateStatus certificateStatus = tlsServer.CertificateStatus;
                                        if (certificateStatus != null)
                                        {
                                            SendCertificateStatusMessage(certificateStatus);
                                        }
                                    }

                                    this.connection_state = CS_CERTIFICATE_STATUS;

                                    byte[] serverKeyExchange = this.keyExchange.GenerateServerKeyExchange();
                                    if (serverKeyExchange != null)
                                    {
                                        SendServerKeyExchangeMessage(serverKeyExchange);
                                    }
                                    this.connection_state = CS_SERVER_KEY_EXCHANGE;

                                    if (this.serverCredentials != null)
                                    {
                                        this.certificateRequest = tlsServer.GetCertificateRequest();
                                        if (this.certificateRequest != null)
                                        {
                                            this.keyExchange.ValidateCertificateRequest(certificateRequest);
                                            SendCertificateRequestMessage(certificateRequest);
                                        }
                                    }
                                    this.connection_state = CS_CERTIFICATE_REQUEST;

                                    SendServerHelloDoneMessage();
                                    this.connection_state = CS_SERVER_HELLO_DONE;

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
                            case CS_SERVER_HELLO_DONE:
                                {
                                    tlsServer.ProcessClientSupplementalData(ReadSupplementalDataMessage(buf));
                                    this.connection_state = CS_CLIENT_SUPPLEMENTAL_DATA;
                                    break;
                                }
                            default:
                                throw new TlsFatalAlert(AlertDescription.unexpected_message);
                        }
                        break;
                    }
                case HandshakeType.certificate:
                    {
                        switch (this.connection_state)
                        {
                            case CS_SERVER_HELLO_DONE:
                            case CS_CLIENT_SUPPLEMENTAL_DATA:
                                if (this.connection_state == CS_SERVER_HELLO_DONE)
                                {
                                    tlsServer.ProcessClientSupplementalData(null);
                                    // NB: Fall through to next case label
                                }
                            
                                {
                                    if (this.certificateRequest == null)
                                    {
                                        throw new TlsFatalAlert(AlertDescription.unexpected_message);
                                    }
                                    ReceiveCertificateMessage(buf);
                                    this.connection_state = CS_CLIENT_CERTIFICATE;
                                    break;
                                }
                            default:
                                throw new TlsFatalAlert(AlertDescription.unexpected_message);
                        }
                        break;
                    }
                case HandshakeType.client_key_exchange:
                    {
                        switch (this.connection_state)
                        {
                            case CS_SERVER_HELLO_DONE:                                
                                {
                                    tlsServer.ProcessClientSupplementalData(null);
                                    // NB: Fall through to next case label
                                    
                                }
                                goto case CS_CLIENT_SUPPLEMENTAL_DATA;
                            case CS_CLIENT_SUPPLEMENTAL_DATA:
                                {
                                    if (this.certificateRequest == null)
                                    {
                                        this.keyExchange.SkipClientCredentials();
                                    }
                                    else
                                    {
                                        if (TlsUtilities.IsTLSv12(Context))
                                        {
                                            /*
                                             * RFC 5246 If no suitable certificate is available, the client MUST send a
                                             * certificate message containing no certificates.
                                             * 
                                             * NOTE: In previous RFCs, this was SHOULD instead of MUST.
                                             */
                                            throw new TlsFatalAlert(AlertDescription.unexpected_message);
                                        }
                                        else if (TlsUtilities.IsSSL(Context))
                                        {
                                            if (this.peerCertificate == null)
                                            {
                                                throw new TlsFatalAlert(AlertDescription.unexpected_message);
                                            }
                                        }
                                        else
                                        {
                                            NotifyClientCertificate(Certificate.EmptyChain);
                                        }
                                    }
                                    // NB: Fall through to next case label
                                }
                                goto case CS_CLIENT_CERTIFICATE;
                            case CS_CLIENT_CERTIFICATE:
                                {
                                    ReceiveClientKeyExchangeMessage(buf);
                                    this.connection_state = CS_CLIENT_KEY_EXCHANGE;
                                    break;
                                }
                            default:
                                throw new TlsFatalAlert(AlertDescription.unexpected_message);
                        }
                        break;
                    }
                case HandshakeType.certificate_verify:
                    {
                        switch (this.connection_state)
                        {
                            case CS_CLIENT_KEY_EXCHANGE:
                                {
                                    /*
                                     * RFC 5246 7.4.8 This message is only sent following a client certificate that has
                                     * signing capability (i.e., all certificates except those containing fixed
                                     * Diffie-Hellman parameters).
                                     */
                                    if (this.certificateVerifyHash == null)
                                    {
                                        throw new TlsFatalAlert(AlertDescription.unexpected_message);
                                    }
                                    ReceiveCertificateVerifyMessage(buf);
                                    this.connection_state = CS_CERTIFICATE_VERIFY;
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
                            case CS_CLIENT_KEY_EXCHANGE:
                                {
                                    if (this.certificateVerifyHash != null)
                                    {
                                        throw new TlsFatalAlert(AlertDescription.unexpected_message);
                                    }
                                    // NB: Fall through to next case label                                    
                                }
                                goto case CS_CERTIFICATE_VERIFY;
                            case CS_CERTIFICATE_VERIFY:
                                {
                                    ProcessFinishedMessage(buf);
                                    this.connection_state = CS_CLIENT_FINISHED;

                                    if (this.expectSessionTicket)
                                    {
                                        SendNewSessionTicketMessage(tlsServer.GetNewSessionTicket());
                                        SendChangeCipherSpecMessage();
                                    }
                                    this.connection_state = CS_SERVER_SESSION_TICKET;

                                    SendFinishedMessage();
                                    this.connection_state = CS_SERVER_FINISHED;
                                    this.connection_state = CS_END;
                                    break;
                                }
                            default:
                                throw new TlsFatalAlert(AlertDescription.unexpected_message);
                        }
                        break;
                    }
                case HandshakeType.hello_request:
                case HandshakeType.hello_verify_request:
                case HandshakeType.server_hello:
                case HandshakeType.server_key_exchange:
                case HandshakeType.certificate_request:
                case HandshakeType.server_hello_done:
                case HandshakeType.session_ticket:
                default:
                    throw new TlsFatalAlert(AlertDescription.unexpected_message);
            }
        }

        protected override void HandleWarningMessage(AlertDescription description)
        {
            switch (description)
            {
                case AlertDescription.no_certificate:
                    {
                        /*
                         * SSL 3.0 If the server has sent a certificate request Message, the client must send
                         * either the certificate message or a no_certificate alert.
                         */
                        if (Context.ServerVersion.IsSSL && certificateRequest != null)
                        {
                            NotifyClientCertificate(Certificate.EmptyChain);
                        }
                        break;
                    }
                default:
                    {
                        base.HandleWarningMessage(description);
                        break;
                    }
            }
        }

        protected void NotifyClientCertificate(Certificate clientCertificate)
        {
            if (certificateRequest == null)
            {
                throw new InvalidOperationException();
            }

            if (this.peerCertificate != null)
            {
                throw new TlsFatalAlert(AlertDescription.unexpected_message);
            }

            this.peerCertificate = clientCertificate;

            if (clientCertificate.IsEmpty)
            {
                this.keyExchange.SkipClientCredentials();
            }
            else
            {

                /*
                 * TODO RFC 5246 7.4.6. If the certificate_authorities list in the certificate request
                 * message was non-empty, one of the certificates in the certificate chain SHOULD be
                 * issued by one of the listed CAs.
                 */

                this.clientCertificateType = TlsUtilities.GetClientCertificateType(clientCertificate,
                    this.serverCredentials.Certificate);

                this.keyExchange.ProcessClientCertificate(clientCertificate);
            }

            /*
             * RFC 5246 7.4.6. If the client does not send any certificates, the server MAY at its
             * discretion either continue the handshake without client authentication, or respond with a
             * fatal handshake_failure alert. Also, if some aspect of the certificate chain was
             * unacceptable (e.g., it was not signed by a known, trusted CA), the server MAY at its
             * discretion either continue the handshake (considering the client unauthenticated) or send
             * a fatal alert.
             */
            this.tlsServer.NotifyClientCertificate(clientCertificate);
        }

        protected void ReceiveCertificateMessage(MemoryStream buf)
        {
            Certificate clientCertificate = Certificate.Parse(buf);

            AssertEmpty(buf);

            NotifyClientCertificate(clientCertificate);
        }

        protected void ReceiveCertificateVerifyMessage(MemoryStream buf)
        {
            DigitallySigned clientCertificateVerify = DigitallySigned.Parse(Context, buf);

            AssertEmpty(buf);

            // Verify the CertificateVerify message contains a correct signature.
            try
            {
                TlsSigner tlsSigner = TlsUtilities.CreateTlsSigner(this.clientCertificateType);
                tlsSigner.Init(Context);

                X509CertificateStructure x509Cert = this.peerCertificate.GetCertificateAt(0);
                var keyInfo = x509Cert.SubjectPublicKeyInfo;
                AsymmetricKeyParameter publicKey = PublicKeyFactory.CreateKey(keyInfo);

                tlsSigner.VerifyRawSignature(clientCertificateVerify.Signature, publicKey, this.certificateVerifyHash);
            }
            catch (Exception e)
            {
                throw new TlsFatalAlert(AlertDescription.decrypt_error, e);
            }
        }

        protected void ReceiveClientHelloMessage(MemoryStream buf)
        {
            ProtocolVersion client_version = TlsUtilities.ReadVersion(buf);
            if (client_version.IsDTLS)
            {
                throw new TlsFatalAlert(AlertDescription.illegal_parameter);
            }

            byte[] client_random = TlsUtilities.ReadFully(32, buf);

            /*
             * TODO RFC 5077 3.4. If a ticket is presented by the client, the server MUST NOT attempt to
             * use the Session ID in the ClientHello for stateful session resumption.
             */
            byte[] sessionID = TlsUtilities.ReadOpaque8(buf);
            if (sessionID.Length > 32)
            {
                throw new TlsFatalAlert(AlertDescription.illegal_parameter);
            }

            /*
             * TODO RFC 5246 7.4.1.2. If the session_id field is not empty (implying a session
             * resumption request), this vector MUST include at least the cipher_suite from that
             * session.
             */
            int cipher_suites_length = TlsUtilities.ReadUint16(buf);
            if (cipher_suites_length < 2 || (cipher_suites_length & 1) != 0)
            {
                throw new TlsFatalAlert(AlertDescription.decode_error);
            }
            this.offeredCipherSuites = TlsUtilities.ReadCipherSuiteArray(cipher_suites_length / 2, buf);

            /*
             * TODO RFC 5246 7.4.1.2. If the session_id field is not empty (implying a session
             * resumption request), it MUST include the compression_method from that session.
             */
            int compression_methods_length = TlsUtilities.ReadUint8(buf);
            if (compression_methods_length < 1)
            {
                throw new TlsFatalAlert(AlertDescription.illegal_parameter);
            }
            this.offeredCompressionMethods = TlsUtilities.ReadCompressionMethods(compression_methods_length, buf);

            /*
             * TODO RFC 3546 2.3 If [...] the older session is resumed, then the server MUST ignore
             * extensions appearing in the client hello, and send a server hello containing no
             * extensions.
             */
            this.clientExtensions = ReadExtensions(buf);

            Context.ClientVersion = client_version;

            tlsServer.NotifyClientVersion(client_version);

            securityParameters.clientRandom = client_random;

            tlsServer.NotifyOfferedCipherSuites(offeredCipherSuites);
            tlsServer.NotifyOfferedCompressionMethods(offeredCompressionMethods);

            /*
             * RFC 5746 3.6. Server Behavior: Initial Handshake
             */
            {
                /*
                 * RFC 5746 3.4. The client MUST include either an empty "renegotiation_info" extension,
                 * or the TLS_EMPTY_RENEGOTIATION_INFO_SCSV signaling cipher suite value in the
                 * ClientHello. Including both is NOT RECOMMENDED.
                 */

                /*
                 * When a ClientHello is received, the server MUST check if it includes the
                 * TLS_EMPTY_RENEGOTIATION_INFO_SCSV SCSV. If it does, set the secure_renegotiation flag
                 * to TRUE.
                 */
                if (ArrayContains(offeredCipherSuites, CipherSuite.TLS_EMPTY_RENEGOTIATION_INFO_SCSV))
                {
                    this.secure_renegotiation = true;
                }

                /*
                 * The server MUST check if the "renegotiation_info" extension is included in the
                 * ClientHello.
                 */
                byte[] renegExtData = TlsUtilities.GetExtensionData(clientExtensions, EXT_RenegotiationInfo);
                if (renegExtData != null)
                {
                    /*
                     * If the extension is present, set secure_renegotiation flag to TRUE. The
                     * server MUST then verify that the length of the "renegotiated_connection"
                     * field is zero, and if it is not, MUST abort the handshake.
                     */
                    this.secure_renegotiation = true;

                    if (!Arrays.ConstantTimeAreEqual(renegExtData, CreateRenegotiationInfo(TlsUtilities.EMPTY_BYTES)))
                    {
                        throw new TlsFatalAlert(AlertDescription.handshake_failure);
                    }
                }
            }

            tlsServer.NotifySecureRenegotiation(this.secure_renegotiation);

            if (clientExtensions != null)
            {
                tlsServer.ProcessClientExtensions(clientExtensions);
            }
        }

        protected void ReceiveClientKeyExchangeMessage(MemoryStream buf)
        {
            this.keyExchange.ProcessClientKeyExchange(buf);

            AssertEmpty(buf);

            EstablishMasterSecret(Context, keyExchange);
            recordStream.SetPendingConnectionState(Peer.GetCompression(), Peer.GetCipher());

            if (!expectSessionTicket)
            {
                SendChangeCipherSpecMessage();
            }

            if (ExpectCertificateVerifyMessage())
            {
                this.certificateVerifyHash = recordStream.GetCurrentHash(null);
            }
        }

        protected void SendCertificateRequestMessage(CertificateRequest certificateRequest)
        {
            HandshakeMessage message = new HandshakeMessage(this, HandshakeType.certificate_request);

            certificateRequest.Encode(message);

            message.WriteToRecordStream();
        }

        protected void SendCertificateStatusMessage(CertificateStatus certificateStatus)
        {
            HandshakeMessage message = new HandshakeMessage(this, HandshakeType.certificate_status);

            certificateStatus.encode(message);

            message.WriteToRecordStream();
        }

        protected void SendNewSessionTicketMessage(NewSessionTicket newSessionTicket)
        {
            if (newSessionTicket == null)
            {
                throw new TlsFatalAlert(AlertDescription.internal_error);
            }

            HandshakeMessage message = new HandshakeMessage(this, HandshakeType.session_ticket);

            newSessionTicket.Encode(message);

            message.WriteToRecordStream();
        }

        protected void SendServerHelloMessage()
        {
            HandshakeMessage message = new HandshakeMessage(this, HandshakeType.server_hello);

            ProtocolVersion server_version = tlsServer.ServerVersion;
            if (!server_version.IsEqualOrEarlierVersionOf(Context.ClientVersion))
            {
                throw new TlsFatalAlert(AlertDescription.internal_error);
            }

            recordStream.ReadVersion = server_version;
            recordStream.SetWriteVersion(server_version);
            recordStream.SetRestrictReadVersion(true);
            Context.ServerVersion = server_version;

            TlsUtilities.WriteVersion(server_version, message);

            message.Write(this.securityParameters.serverRandom, 0, this.securityParameters.serverRandom.Length);

            /*
             * The server may return an empty session_id to indicate that the session will not be cached
             * and therefore cannot be resumed.
             */
            TlsUtilities.WriteOpaque8(TlsUtilities.EMPTY_BYTES, message);

            CipherSuite selectedCipherSuite = tlsServer.SelectedCipherSuite;
            if (!ArrayContains(this.offeredCipherSuites, selectedCipherSuite)
                || selectedCipherSuite == CipherSuite.TLS_NULL_WITH_NULL_NULL
                || selectedCipherSuite == CipherSuite.TLS_EMPTY_RENEGOTIATION_INFO_SCSV)
            {
                throw new TlsFatalAlert(AlertDescription.internal_error);
            }
            securityParameters.cipherSuite = selectedCipherSuite;

            var selectedCompressionMethod = tlsServer.SelectedCompressionMethod;
            if (!ArrayContains(this.offeredCompressionMethods, selectedCompressionMethod))
            {
                throw new TlsFatalAlert(AlertDescription.internal_error);
            }
            securityParameters.compressionAlgorithm = selectedCompressionMethod;

            TlsUtilities.WriteUint16((ushort)selectedCipherSuite, message);
            TlsUtilities.WriteUint8((byte)selectedCompressionMethod, message);

            this.serverExtensions = tlsServer.GetServerExtensions();

            /*
             * RFC 5746 3.6. Server Behavior: Initial Handshake
             */
            if (this.secure_renegotiation)
            {
                byte[] renegExtData = TlsUtilities.GetExtensionData(this.serverExtensions, EXT_RenegotiationInfo);
                bool noRenegExt = (null == renegExtData);

                if (noRenegExt)
                {
                    /*
                     * Note that sending a "renegotiation_info" extension in response to a ClientHello
                     * containing only the SCSV is an explicit exception to the prohibition in RFC 5246,
                     * Section 7.4.1.4, on the server sending unsolicited extensions and is only allowed
                     * because the client is signaling its willingness to receive the extension via the
                     * TLS_EMPTY_RENEGOTIATION_INFO_SCSV SCSV.
                     */
                    if (this.serverExtensions == null)
                    {
                        this.serverExtensions = Platform.CreateHashtable();
                    }

                    /*
                     * If the secure_renegotiation flag is set to TRUE, the server MUST include an empty
                     * "renegotiation_info" extension in the ServerHello message.
                     */
                    this.serverExtensions[EXT_RenegotiationInfo] = CreateRenegotiationInfo(TlsUtilities.EMPTY_BYTES);
                }
            }

            /*
             * TODO RFC 3546 2.3 If [...] the older session is resumed, then the server MUST ignore
             * extensions appearing in the client hello, and send a server hello containing no
             * extensions.
             */

            if (this.serverExtensions != null)
            {
                this.securityParameters.maxFragmentLength = ProcessMaxFragmentLengthExtension(clientExtensions,
                    this.serverExtensions, AlertDescription.internal_error);

                this.securityParameters.truncatedHMac = TlsExtensionsUtils.HasTruncatedHMacExtension(this.serverExtensions);

                /*
                 * TODO It's surprising that there's no provision to allow a 'fresh' CertificateStatus to be sent in
                 * a session resumption handshake.
                 */
                this.allowCertificateStatus = !this.resumedSession
                    && TlsUtilities.HasExpectedEmptyExtensionData(this.serverExtensions, TlsExtensionsUtils.EXT_status_request,
                        AlertDescription.internal_error);

                this.expectSessionTicket = !this.resumedSession
                    && TlsUtilities.HasExpectedEmptyExtensionData(this.serverExtensions, TlsProtocol.EXT_SessionTicket,
                        AlertDescription.internal_error);

                WriteExtensions(message, this.serverExtensions);
            }

            if (this.securityParameters.maxFragmentLength >= 0)
            {
                int plainTextLimit = 1 << (8 + this.securityParameters.maxFragmentLength);
                recordStream.PlaintextLimit = plainTextLimit;
            }

            securityParameters.prfAlgorithm = GetPRFAlgorithm(Context, securityParameters.CipherSuite);

            /*
             * RFC 5264 7.4.9. Any cipher suite which does not explicitly specify verify_data_length has
             * a verify_data_length equal to 12. This includes all existing cipher suites.
             */
            securityParameters.verifyDataLength = 12;

            message.WriteToRecordStream();

            recordStream.NotifyHelloComplete();
        }

        protected void SendServerHelloDoneMessage()
        {
            byte[] message = new byte[4];
            TlsUtilities.WriteUint8((byte)HandshakeType.server_hello_done, message, 0);
            TlsUtilities.WriteUint24(0, message, 1);

            WriteHandshakeMessage(message, 0, message.Length);
        }

        protected void SendServerKeyExchangeMessage(byte[] serverKeyExchange)
        {
            HandshakeMessage message = new HandshakeMessage(this, HandshakeType.server_key_exchange, serverKeyExchange.Length);

            message.Write(serverKeyExchange, 0, serverKeyExchange.Length);

            message.WriteToRecordStream();
        }

        protected bool ExpectCertificateVerifyMessage()
        {
            return this.clientCertificateType >= 0 && TlsUtilities.HasSigningCapability(this.clientCertificateType);
        }
    }
}
