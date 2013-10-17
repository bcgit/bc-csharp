using System;
using System.Collections;
using Org.BouncyCastle.Security;
using System.IO;
using Org.BouncyCastle.Utilities;
using Org.BouncyCastle.Asn1.X509;

namespace Org.BouncyCastle.Crypto.Tls
{

    public class DTLSServerProtocol : DTLSProtocol
    {
        private bool verifyRequests = true;

        public DTLSServerProtocol(SecureRandom secureRandom)
            : base(secureRandom)
        {

        }

        public bool VerifyRequests
        {
            get
            {
                return verifyRequests;
            }
            set
            {
                this.verifyRequests = value;
            }
        }

        public DTLSTransport Accept(TlsServer server, DatagramTransport transport)
        {
            if (server == null)
            {
                throw new ArgumentException("'server' cannot be null");
            }
            if (transport == null)
            {
                throw new ArgumentException("'transport' cannot be null");
            }

            SecurityParameters securityParameters = new SecurityParameters();
            securityParameters.entity = ConnectionEnd.server;
            securityParameters.serverRandom = TlsProtocol.CreateRandomBlock(secureRandom);

            ServerHandshakeState state = new ServerHandshakeState();
            state.server = server;
            state.serverContext = new TlsServerContextImpl(secureRandom, securityParameters);
            server.Init(state.serverContext);

            DTLSRecordLayer recordLayer = new DTLSRecordLayer(transport, state.serverContext, server, ContentType.handshake);

            // TODO Need to handle sending of HelloVerifyRequest without entering a full connection

            try
            {
                return ServerHandshake(state, recordLayer);
            }
            catch (TlsFatalAlert fatalAlert)
            {
                recordLayer.Fail(fatalAlert.AlertDescription);
                throw fatalAlert;
            }
            catch (IOException e)
            {
                recordLayer.Fail(AlertDescription.internal_error);
                throw e;
            }
            catch (Exception e)
            {
                recordLayer.Fail(AlertDescription.internal_error);
                throw new TlsFatalAlert(AlertDescription.internal_error, e);
            }
        }

        private DTLSTransport ServerHandshake(ServerHandshakeState state, DTLSRecordLayer recordLayer)
        {
            SecurityParameters securityParameters = state.serverContext.SecurityParameters;
            DTLSReliableHandshake handshake = new DTLSReliableHandshake(state.serverContext, recordLayer);

            DTLSReliableHandshake.Message clientMessage = handshake.ReceiveMessage();

            {
                // NOTE: After receiving a record from the client, we discover the record layer version
                ProtocolVersion client_version = recordLayer.DiscoveredPeerVersion;
                // TODO Read RFCs for guidance on the expected record layer version number
                state.serverContext.ClientVersion = client_version;
            }

            if (clientMessage.Type == HandshakeType.client_hello)
            {
                ProcessClientHello(state, clientMessage.Body);
            }
            else
            {
                throw new TlsFatalAlert(AlertDescription.unexpected_message);
            }

            {
                byte[] serverHelloBody = GenerateServerHello(state);

                if (state.maxFragmentLength >= 0)
                {
                    int plainTextLimit = 1 << (8 + state.maxFragmentLength);
                    recordLayer.SetPlaintextLimit(plainTextLimit);
                }

                securityParameters.cipherSuite = state.selectedCipherSuite;
                securityParameters.compressionAlgorithm = state.selectedCompressionMethod;
                securityParameters.prfAlgorithm = TlsProtocol.GetPRFAlgorithm(state.serverContext,
                    state.selectedCipherSuite);

                /*
                 * RFC 5264 7.4.9. Any cipher suite which does not explicitly specify verify_data_length
                 * has a verify_data_length equal to 12. This includes all existing cipher suites.
                 */
                securityParameters.verifyDataLength = 12;

                handshake.SendMessage(HandshakeType.server_hello, serverHelloBody);
            }

            handshake.NotifyHelloComplete();

            IList serverSupplementalData = state.server.GetServerSupplementalData();
            if (serverSupplementalData != null)
            {
                byte[] supplementalDataBody = GenerateSupplementalData(serverSupplementalData);
                handshake.SendMessage(HandshakeType.supplemental_data, supplementalDataBody);
            }

            state.keyExchange = state.server.GetKeyExchange();
            state.keyExchange.Init(state.serverContext);

            state.serverCredentials = state.server.Credentials;

            Certificate serverCertificate = null;

            if (state.serverCredentials == null)
            {
                state.keyExchange.SkipServerCredentials();
            }
            else
            {
                state.keyExchange.ProcessServerCredentials(state.serverCredentials);

                serverCertificate = state.serverCredentials.Certificate;
                byte[] certificateBody = GenerateCertificate(serverCertificate);
                handshake.SendMessage(HandshakeType.certificate, certificateBody);
            }

            // TODO[RFC 3546] Check whether empty certificates is possible, allowed, or excludes CertificateStatus
            if (serverCertificate == null || serverCertificate.IsEmpty)
            {
                state.allowCertificateStatus = false;
            }

            if (state.allowCertificateStatus)
            {
                CertificateStatus certificateStatus = state.server.CertificateStatus;
                if (certificateStatus != null)
                {
                    byte[] certificateStatusBody = GenerateCertificateStatus(state, certificateStatus);
                    handshake.SendMessage(HandshakeType.certificate_status, certificateStatusBody);
                }
            }

            byte[] serverKeyExchange = state.keyExchange.GenerateServerKeyExchange();
            if (serverKeyExchange != null)
            {
                handshake.SendMessage(HandshakeType.server_key_exchange, serverKeyExchange);
            }

            if (state.serverCredentials != null)
            {
                state.certificateRequest = state.server.GetCertificateRequest();
                if (state.certificateRequest != null)
                {
                    state.keyExchange.ValidateCertificateRequest(state.certificateRequest);

                    byte[] certificateRequestBody = GenerateCertificateRequest(state, state.certificateRequest);
                    handshake.SendMessage(HandshakeType.certificate_request, certificateRequestBody);
                }
            }

            handshake.SendMessage(HandshakeType.server_hello_done, TlsUtilities.EMPTY_BYTES);

            clientMessage = handshake.ReceiveMessage();

            if (clientMessage.Type == HandshakeType.supplemental_data)
            {
                ProcessClientSupplementalData(state, clientMessage.Body);
                clientMessage = handshake.ReceiveMessage();
            }
            else
            {
                state.server.ProcessClientSupplementalData(null);
            }

            if (state.certificateRequest == null)
            {
                state.keyExchange.SkipClientCredentials();
            }
            else
            {
                if (clientMessage.Type == HandshakeType.certificate)
                {
                    ProcessClientCertificate(state, clientMessage.Body);
                    clientMessage = handshake.ReceiveMessage();
                }
                else
                {
                    if (TlsUtilities.IsTLSv12(state.serverContext))
                    {
                        /*
                         * RFC 5246 If no suitable certificate is available, the client MUST send a
                         * certificate message containing no certificates.
                         * 
                         * NOTE: In previous RFCs, this was SHOULD instead of MUST.
                         */
                        throw new TlsFatalAlert(AlertDescription.unexpected_message);
                    }

                    NotifyClientCertificate(state, Certificate.EmptyChain);
                }
            }

            if (clientMessage.Type == HandshakeType.client_key_exchange)
            {
                ProcessClientKeyExchange(state, clientMessage.Body);
            }
            else
            {
                throw new TlsFatalAlert(AlertDescription.unexpected_message);
            }

            TlsProtocol.EstablishMasterSecret(state.serverContext, state.keyExchange);
            recordLayer.InitPendingEpoch(state.server.GetCipher());

            /*
             * RFC 5246 7.4.8 This message is only sent following a client certificate that has signing
             * capability (i.e., all certificates except those containing fixed Diffie-Hellman
             * parameters).
             */
            if (ExpectCertificateVerifyMessage(state))
            {
                byte[] certificateVerifyHash = handshake.GetCurrentHash();
                byte[] certificateVerifyBody = handshake.ReceiveMessageBody(HandshakeType.certificate_verify);
                ProcessCertificateVerify(state, certificateVerifyBody, certificateVerifyHash);
            }

            // NOTE: Calculated exclusive of the actual Finished message from the client
            byte[] expectedClientVerifyData = TlsUtilities.CalculateVerifyData(state.serverContext, "client finished",
                handshake.GetCurrentHash());
            ProcessFinished(handshake.ReceiveMessageBody(HandshakeType.finished), expectedClientVerifyData);

            if (state.expectSessionTicket)
            {
                NewSessionTicket newSessionTicket = state.server.GetNewSessionTicket();
                byte[] newSessionTicketBody = GenerateNewSessionTicket(state, newSessionTicket);
                handshake.SendMessage(HandshakeType.session_ticket, newSessionTicketBody);
            }

            // NOTE: Calculated exclusive of the Finished message itself
            byte[] serverVerifyData = TlsUtilities.CalculateVerifyData(state.serverContext, "server finished",
                handshake.GetCurrentHash());
            handshake.SendMessage(HandshakeType.finished, serverVerifyData);

            handshake.Finish();

            state.server.NotifyHandshakeComplete();

            return new DTLSTransport(recordLayer);
        }

        protected byte[] GenerateCertificateRequest(ServerHandshakeState state, CertificateRequest certificateRequest)
        {
            MemoryStream buf = new MemoryStream();
            certificateRequest.Encode(buf);
            return buf.ToArray();
        }

        protected byte[] GenerateCertificateStatus(ServerHandshakeState state, CertificateStatus certificateStatus)
        {
            MemoryStream buf = new MemoryStream();
            certificateStatus.encode(buf);
            return buf.ToArray();
        }

        protected byte[] GenerateNewSessionTicket(ServerHandshakeState state, NewSessionTicket newSessionTicket)
        {
            MemoryStream buf = new MemoryStream();
            newSessionTicket.Encode(buf);
            return buf.ToArray();
        }

        protected byte[] GenerateServerHello(ServerHandshakeState state)
        {
            SecurityParameters securityParameters = state.serverContext.SecurityParameters;

            MemoryStream buf = new MemoryStream();

            ProtocolVersion server_version = state.server.ServerVersion;
            if (!server_version.IsEqualOrEarlierVersionOf(state.serverContext.ClientVersion))
            {
                throw new TlsFatalAlert(AlertDescription.internal_error);
            }

            // TODO Read RFCs for guidance on the expected record layer version number
            // recordStream.setReadVersion(server_version);
            // recordStream.setWriteVersion(server_version);
            // recordStream.setRestrictReadVersion(true);
            state.serverContext.ServerVersion = server_version;

            TlsUtilities.WriteVersion(state.serverContext.ServerVersion, buf);

            buf.Write(securityParameters.ServerRandom, 0, securityParameters.ServerRandom.Length);

            /*
             * The server may return an empty session_id to indicate that the session will not be cached
             * and therefore cannot be resumed.
             */
            TlsUtilities.WriteOpaque8(TlsUtilities.EMPTY_BYTES, buf);

            state.selectedCipherSuite = state.server.SelectedCipherSuite;
            if (!TlsProtocol.ArrayContains(state.offeredCipherSuites, state.selectedCipherSuite)
                || state.selectedCipherSuite == CipherSuite.TLS_NULL_WITH_NULL_NULL
                || state.selectedCipherSuite == CipherSuite.TLS_EMPTY_RENEGOTIATION_INFO_SCSV)
            {
                throw new TlsFatalAlert(AlertDescription.internal_error);
            }

            ValidateSelectedCipherSuite(state.selectedCipherSuite, AlertDescription.internal_error);

            state.selectedCompressionMethod = state.server.SelectedCompressionMethod;
            if (!TlsProtocol.ArrayContains(state.offeredCompressionMethods, state.selectedCompressionMethod))
            {
                throw new TlsFatalAlert(AlertDescription.internal_error);
            }

            TlsUtilities.WriteUint16((ushort)state.selectedCipherSuite, buf);
            TlsUtilities.WriteUint8((byte)state.selectedCompressionMethod, buf);

            state.serverExtensions = state.server.GetServerExtensions();

            /*
             * RFC 5746 3.6. Server Behavior: Initial Handshake
             */
            if (state.secure_renegotiation)
            {
                byte[] renegExtData = TlsUtilities.GetExtensionData(state.serverExtensions, TlsProtocol.EXT_RenegotiationInfo);
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
                    if (state.serverExtensions == null)
                    {
                        state.serverExtensions = Platform.CreateHashtable();
                    }

                    /*
                     * If the secure_renegotiation flag is set to TRUE, the server MUST include an empty
                     * "renegotiation_info" extension in the ServerHello message.
                     */
                    state.serverExtensions[TlsProtocol.EXT_RenegotiationInfo] = TlsProtocol.CreateRenegotiationInfo(TlsUtilities.EMPTY_BYTES); 
                }
            }

            if (state.serverExtensions != null)
            {
                state.maxFragmentLength = EvaluateMaxFragmentLengthExtension(state.clientExtensions, state.serverExtensions,
                    AlertDescription.internal_error);

                securityParameters.truncatedHMac = TlsExtensionsUtils.HasTruncatedHMacExtension(state.serverExtensions);

                state.allowCertificateStatus = TlsUtilities.HasExpectedEmptyExtensionData(state.serverExtensions,
                    TlsExtensionsUtils.EXT_status_request, AlertDescription.internal_error);

                state.expectSessionTicket = TlsUtilities.HasExpectedEmptyExtensionData(state.serverExtensions,
                    TlsProtocol.EXT_SessionTicket, AlertDescription.internal_error);

                TlsProtocol.WriteExtensions(buf, state.serverExtensions);
            }

            return buf.ToArray();
        }

        protected void NotifyClientCertificate(ServerHandshakeState state, Certificate clientCertificate)
        {
            if (state.certificateRequest == null)
            {
                throw new InvalidOperationException();
            }

            if (state.clientCertificate != null)
            {
                throw new TlsFatalAlert(AlertDescription.unexpected_message);
            }

            state.clientCertificate = clientCertificate;

            if (clientCertificate.IsEmpty)
            {
                state.keyExchange.SkipClientCredentials();
            }
            else
            {

                /*
                 * TODO RFC 5246 7.4.6. If the certificate_authorities list in the certificate request
                 * message was non-empty, one of the certificates in the certificate chain SHOULD be
                 * issued by one of the listed CAs.
                 */

                state.clientCertificateType = TlsUtilities.GetClientCertificateType(clientCertificate,
                    state.serverCredentials.Certificate);

                state.keyExchange.ProcessClientCertificate(clientCertificate);
            }

            /*
             * RFC 5246 7.4.6. If the client does not send any certificates, the server MAY at its
             * discretion either continue the handshake without client authentication, or respond with a
             * fatal handshake_failure alert. Also, if some aspect of the certificate chain was
             * unacceptable (e.g., it was not signed by a known, trusted CA), the server MAY at its
             * discretion either continue the handshake (considering the client unauthenticated) or send
             * a fatal alert.
             */
            state.server.NotifyClientCertificate(clientCertificate);
        }

        protected void ProcessClientCertificate(ServerHandshakeState state, byte[] body)
        {
            MemoryStream buf = new MemoryStream(body);

            Certificate clientCertificate = Certificate.Parse(buf);

            TlsProtocol.AssertEmpty(buf);

            NotifyClientCertificate(state, clientCertificate);
        }

        protected void ProcessCertificateVerify(ServerHandshakeState state, byte[] body, byte[] certificateVerifyHash)
        {
            MemoryStream buf = new MemoryStream(body);

            DigitallySigned clientCertificateVerify = DigitallySigned.Parse(state.serverContext, buf);

            TlsProtocol.AssertEmpty(buf);

            // Verify the CertificateVerify message contains a correct signature.
            try
            {
                TlsSigner tlsSigner = TlsUtilities.CreateTlsSigner(state.clientCertificateType);
                tlsSigner.Init(state.serverContext);

                var x509Cert = state.clientCertificate.GetCertificateAt(0);
                SubjectPublicKeyInfo keyInfo = x509Cert.SubjectPublicKeyInfo;
                AsymmetricKeyParameter publicKey = PublicKeyFactory.CreateKey(keyInfo);

                tlsSigner.VerifyRawSignature(clientCertificateVerify.Signature, publicKey, certificateVerifyHash);
            }
            catch 
            {
                throw new TlsFatalAlert(AlertDescription.decrypt_error);
            }
        }

        protected void ProcessClientHello(ServerHandshakeState state, byte[] body)
        {
            MemoryStream buf = new MemoryStream(body);

            // TODO Read RFCs for guidance on the expected record layer version number
            ProtocolVersion client_version = TlsUtilities.ReadVersion(buf);
            if (!client_version.IsDTLS)
            {
                throw new TlsFatalAlert(AlertDescription.illegal_parameter);
            }

            /*
             * Read the client random
             */
            byte[] client_random = TlsUtilities.ReadFully(32, buf);

            byte[] sessionID = TlsUtilities.ReadOpaque8(buf);
            if (sessionID.Length > 32)
            {
                throw new TlsFatalAlert(AlertDescription.illegal_parameter);
            }

            // TODO RFC 4347 has the cookie length restricted to 32, but not in RFC 6347
            byte[] cookie = TlsUtilities.ReadOpaque8(buf);

            int cipher_suites_length = TlsUtilities.ReadUint16(buf);
            if (cipher_suites_length < 2 || (cipher_suites_length & 1) != 0)
            {
                throw new TlsFatalAlert(AlertDescription.decode_error);
            }

            /*
             * NOTE: "If the session_id field is not empty (implying a session resumption request) this
             * vector must include at least the cipher_suite from that session."
             */
            state.offeredCipherSuites = TlsUtilities.ReadCipherSuiteArray(cipher_suites_length / 2, buf);

            int compression_methods_length = TlsUtilities.ReadUint8(buf);
            if (compression_methods_length < 1)
            {
                throw new TlsFatalAlert(AlertDescription.illegal_parameter);
            }

            state.offeredCompressionMethods = TlsUtilities.ReadCompressionMethods(compression_methods_length, buf);

            /*
             * TODO RFC 3546 2.3 If [...] the older session is resumed, then the server MUST ignore
             * extensions appearing in the client hello, and send a server hello containing no
             * extensions.
             */
            state.clientExtensions = TlsProtocol.ReadExtensions(buf);

            state.serverContext.ClientVersion = (client_version);

            state.server.NotifyClientVersion(client_version);

            state.serverContext.SecurityParameters.clientRandom = client_random;

            state.server.NotifyOfferedCipherSuites(state.offeredCipherSuites);
            state.server.NotifyOfferedCompressionMethods(state.offeredCompressionMethods);

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
                if (TlsProtocol.ArrayContains(state.offeredCipherSuites, CipherSuite.TLS_EMPTY_RENEGOTIATION_INFO_SCSV))
                {
                    state.secure_renegotiation = true;
                }

                /*
                 * The server MUST check if the "renegotiation_info" extension is included in the
                 * ClientHello.
                 */
                byte[] renegExtData = TlsUtilities.GetExtensionData(state.clientExtensions, TlsProtocol.EXT_RenegotiationInfo);
                if (renegExtData != null)
                {
                    /*
                     * If the extension is present, set secure_renegotiation flag to TRUE. The
                     * server MUST then verify that the length of the "renegotiated_connection"
                     * field is zero, and if it is not, MUST abort the handshake.
                     */
                    state.secure_renegotiation = true;

                    if (!Arrays.ConstantTimeAreEqual(renegExtData, TlsProtocol.CreateRenegotiationInfo(TlsUtilities.EMPTY_BYTES)))
                    {
                        throw new TlsFatalAlert(AlertDescription.handshake_failure);
                    }
                }
            }

            state.server.NotifySecureRenegotiation(state.secure_renegotiation);

            if (state.clientExtensions != null)
            {
                state.server.ProcessClientExtensions(state.clientExtensions);
            }
        }

        protected void ProcessClientKeyExchange(ServerHandshakeState state, byte[] body)
        {
            MemoryStream buf = new MemoryStream(body);

            state.keyExchange.ProcessClientKeyExchange(buf);

            TlsProtocol.AssertEmpty(buf);
        }

        protected void ProcessClientSupplementalData(ServerHandshakeState state, byte[] body)
        {
            MemoryStream buf = new MemoryStream(body);
            IList clientSupplementalData = TlsProtocol.ReadSupplementalDataMessage(buf);
            state.server.ProcessClientSupplementalData(clientSupplementalData);
        }

        protected bool ExpectCertificateVerifyMessage(ServerHandshakeState state)
        {
            return state.clientCertificateType >= 0 && TlsUtilities.HasSigningCapability(state.clientCertificateType);
        }

        protected class ServerHandshakeState
        {
            public TlsServer server = null;
            public TlsServerContextImpl serverContext = null;
            public CipherSuite[] offeredCipherSuites;
            public CompressionMethod[] offeredCompressionMethods;
            public IDictionary clientExtensions;
            public CipherSuite selectedCipherSuite = CipherSuite.UNASSINGED;
            public CompressionMethod selectedCompressionMethod = CompressionMethod.NULL;
            public bool secure_renegotiation = false;
            public short maxFragmentLength = -1;
            public bool allowCertificateStatus = false;
            public bool expectSessionTicket = false;
            public IDictionary serverExtensions = null;
            public TlsKeyExchange keyExchange = null;
            public TlsCredentials serverCredentials = null;
            public CertificateRequest certificateRequest = null;
            public ClientCertificateType clientCertificateType = ClientCertificateType.empty;
            public Certificate clientCertificate = null;
        }
    }
}
