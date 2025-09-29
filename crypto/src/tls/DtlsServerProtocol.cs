using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;

using Org.BouncyCastle.Tls.Crypto;
using Org.BouncyCastle.Utilities;

namespace Org.BouncyCastle.Tls
{
    public class DtlsServerProtocol
        : DtlsProtocol
    {
        protected bool m_verifyRequests = true;

        public DtlsServerProtocol()
            : base()
        {
        }

        public virtual bool VerifyRequests
        {
            get { return m_verifyRequests; }
            set { this.m_verifyRequests = value; }
        }

        /// <exception cref="IOException"/>
        public virtual DtlsTransport Accept(TlsServer server, DatagramTransport transport)
        {
            return Accept(server, transport, null);
        }

        /// <exception cref="IOException"/>
        public virtual DtlsTransport Accept(TlsServer server, DatagramTransport transport, DtlsRequest request)
        {
            if (server == null)
                throw new ArgumentNullException("server");
            if (transport == null)
                throw new ArgumentNullException("transport");

            TlsServerContextImpl serverContext = new TlsServerContextImpl(server.Crypto);

            server.Init(serverContext);
            serverContext.HandshakeBeginning(server);

            SecurityParameters securityParameters = serverContext.SecurityParameters;
            securityParameters.m_extendedPadding = server.ShouldUseExtendedPadding();

            DtlsRecordLayer recordLayer = new DtlsRecordLayer(serverContext, server, transport);
            server.NotifyCloseHandle(recordLayer);

            ServerHandshakeState state = new ServerHandshakeState();
            state.server = server;
            state.serverContext = serverContext;
            state.recordLayer = recordLayer;

            try
            {
                return ServerHandshake(state, request);
            }
            catch (TlsFatalAlertReceived)
            {
                Debug.Assert(recordLayer.IsFailed);
                InvalidateSession(state);
                throw;
            }
            catch (TlsFatalAlert fatalAlert)
            {
                AbortServerHandshake(state, fatalAlert.AlertDescription);
                throw;
            }
            catch (IOException)
            {
                AbortServerHandshake(state, AlertDescription.internal_error);
                throw;
            }
            catch (Exception e)
            {
                AbortServerHandshake(state, AlertDescription.internal_error);
                throw new TlsFatalAlert(AlertDescription.internal_error, e);
            }
            finally
            {
                securityParameters.Clear();
            }
        }

        internal virtual void AbortServerHandshake(ServerHandshakeState state, short alertDescription)
        {
            state.recordLayer.Fail(alertDescription);
            InvalidateSession(state);
        }

        /// <exception cref="IOException"/>
        internal virtual DtlsTransport ServerHandshake(ServerHandshakeState state, DtlsRequest request)
        {
            TlsServer server = state.server;
            TlsServerContextImpl serverContext = state.serverContext;
            DtlsRecordLayer recordLayer = state.recordLayer;
            SecurityParameters securityParameters = serverContext.SecurityParameters;

            DtlsReliableHandshake handshake = new DtlsReliableHandshake(serverContext, recordLayer,
                server.GetHandshakeTimeoutMillis(), TlsUtilities.GetHandshakeResendTimeMillis(server), request);

            DtlsReliableHandshake.Message clientMessage = null;

            if (null == request)
            {
                clientMessage = handshake.ReceiveMessage();

                if (clientMessage.Type == HandshakeType.client_hello)
                {
                    ProcessClientHello(state, clientMessage.Body);
                }
                else
                {
                    throw new TlsFatalAlert(AlertDescription.unexpected_message);
                }

                clientMessage = null;
            }
            else
            {
                ProcessClientHello(state, request.ClientHello);

                request = null;
            }

            {
                byte[] serverHelloBody = GenerateServerHello(state);

                handshake.SendMessage(HandshakeType.server_hello, serverHelloBody);
            }

            handshake.HandshakeHash.NotifyPrfDetermined();

            if (securityParameters.IsResumedSession)
            {
                securityParameters.m_masterSecret = state.sessionMasterSecret;
                recordLayer.InitPendingEpoch(TlsUtilities.InitCipher(serverContext));

                // NOTE: Calculated exclusive of the Finished message itself
                securityParameters.m_localVerifyData = TlsUtilities.CalculateVerifyData(serverContext,
                    handshake.HandshakeHash, true);
                handshake.SendMessage(HandshakeType.finished, securityParameters.LocalVerifyData);

                // NOTE: Calculated exclusive of the actual Finished message from the client
                securityParameters.m_peerVerifyData = TlsUtilities.CalculateVerifyData(serverContext,
                    handshake.HandshakeHash, false);
                ProcessFinished(handshake.ReceiveMessageBody(HandshakeType.finished),
                    securityParameters.PeerVerifyData);

                handshake.Finish();

                if (securityParameters.IsExtendedMasterSecret &&
                    ProtocolVersion.DTLSv12.IsEqualOrLaterVersionOf(securityParameters.NegotiatedVersion))
                {
                    securityParameters.m_tlsUnique = securityParameters.LocalVerifyData;
                }

                securityParameters.m_localCertificate = state.sessionParameters.LocalCertificate;
                securityParameters.m_peerCertificate = state.sessionParameters.PeerCertificate;
                securityParameters.m_pskIdentity = state.sessionParameters.PskIdentity;
                securityParameters.m_srpIdentity = state.sessionParameters.SrpIdentity;

                serverContext.HandshakeComplete(server, state.tlsSession);

                recordLayer.InitHeartbeat(state.heartbeat, HeartbeatMode.peer_allowed_to_send == state.heartbeatPolicy);

                return new DtlsTransport(recordLayer, server.IgnoreCorruptDtlsRecords);
            }

            var serverSupplementalData = server.GetServerSupplementalData();
            if (serverSupplementalData != null)
            {
                byte[] supplementalDataBody = GenerateSupplementalData(serverSupplementalData);
                handshake.SendMessage(HandshakeType.supplemental_data, supplementalDataBody);
            }

            state.keyExchange = TlsUtilities.InitKeyExchangeServer(serverContext, server);

            state.serverCredentials = null;

            if (!KeyExchangeAlgorithm.IsAnonymous(securityParameters.KeyExchangeAlgorithm))
            {
                state.serverCredentials = TlsUtilities.EstablishServerCredentials(server);
            }

            // Server certificate
            {
                Certificate serverCertificate = null;

                MemoryStream endPointHash = new MemoryStream();
                if (state.serverCredentials == null)
                {
                    state.keyExchange.SkipServerCredentials();
                }
                else
                {
                    state.keyExchange.ProcessServerCredentials(state.serverCredentials);

                    serverCertificate = state.serverCredentials.Certificate;

                    SendCertificateMessage(serverContext, handshake, serverCertificate, endPointHash);
                }
                securityParameters.m_tlsServerEndPoint = endPointHash.ToArray();

                // TODO[RFC 3546] Check whether empty certificates is possible, allowed, or excludes CertificateStatus
                if (serverCertificate == null || serverCertificate.IsEmpty)
                {
                    securityParameters.m_statusRequestVersion = 0;
                }
            }

            if (securityParameters.StatusRequestVersion > 0)
            {
                CertificateStatus certificateStatus = server.GetCertificateStatus();
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
                state.certificateRequest = server.GetCertificateRequest();

                if (null == state.certificateRequest)
                {
                    /*
                     * For static agreement key exchanges, CertificateRequest is required since
                     * the client Certificate message is mandatory but can only be sent if the
                     * server requests it.
                     */
                    if (!state.keyExchange.RequiresCertificateVerify)
                        throw new TlsFatalAlert(AlertDescription.internal_error);
                }
                else
                {
                    if (TlsUtilities.IsTlsV12(serverContext)
                        != (state.certificateRequest.SupportedSignatureAlgorithms != null))
                    {
                        throw new TlsFatalAlert(AlertDescription.internal_error);
                    }

                    state.certificateRequest = TlsUtilities.ValidateCertificateRequest(state.certificateRequest, state.keyExchange);

                    TlsUtilities.EstablishServerSigAlgs(securityParameters, state.certificateRequest);

                    if (ProtocolVersion.DTLSv12.Equals(securityParameters.NegotiatedVersion))
                    {
                        TlsUtilities.TrackHashAlgorithms(handshake.HandshakeHash, securityParameters.ServerSigAlgs);

                        if (serverContext.Crypto.HasAnyStreamVerifiers(securityParameters.ServerSigAlgs))
                        {
                            handshake.HandshakeHash.ForceBuffering();
                        }
                    }
                    else
                    {
                        if (serverContext.Crypto.HasAnyStreamVerifiersLegacy(state.certificateRequest.CertificateTypes))
                        {
                            handshake.HandshakeHash.ForceBuffering();
                        }
                    }
                }
            }

            handshake.HandshakeHash.SealHashAlgorithms();

            if (null != state.certificateRequest)
            {
                byte[] certificateRequestBody = GenerateCertificateRequest(state, state.certificateRequest);
                handshake.SendMessage(HandshakeType.certificate_request, certificateRequestBody);
            }

            handshake.SendMessage(HandshakeType.server_hello_done, TlsUtilities.EmptyBytes);

            clientMessage = handshake.ReceiveMessage();

            if (clientMessage.Type == HandshakeType.supplemental_data)
            {
                ProcessClientSupplementalData(state, clientMessage.Body);
                clientMessage = handshake.ReceiveMessage();
            }
            else
            {
                server.ProcessClientSupplementalData(null);
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
                    if (TlsUtilities.IsTlsV12(serverContext))
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

            securityParameters.m_sessionHash = TlsUtilities.GetCurrentPrfHash(handshake.HandshakeHash);

            TlsProtocol.EstablishMasterSecret(serverContext, state.keyExchange);
            state.keyExchange = null;

            recordLayer.InitPendingEpoch(TlsUtilities.InitCipher(serverContext));

            /*
             * RFC 5246 7.4.8 This message is only sent following a client certificate that has signing
             * capability (i.e., all certificates except those containing fixed Diffie-Hellman
             * parameters).
             */
            {
                if (ExpectCertificateVerifyMessage(state))
                {
                    clientMessage = handshake.ReceiveMessageDelayedDigest(HandshakeType.certificate_verify);
                    byte[] certificateVerifyBody = clientMessage.Body;
                    ProcessCertificateVerify(state, certificateVerifyBody, handshake.HandshakeHash);
                    handshake.PrepareToFinish();
                    handshake.UpdateHandshakeMessagesDigest(clientMessage);
                }
                else
                {
                    handshake.PrepareToFinish();
                }
            }

            clientMessage = null;

            // NOTE: Calculated exclusive of the actual Finished message from the client
            securityParameters.m_peerVerifyData = TlsUtilities.CalculateVerifyData(serverContext,
                handshake.HandshakeHash, false);
            ProcessFinished(handshake.ReceiveMessageBody(HandshakeType.finished), securityParameters.PeerVerifyData);

            if (state.expectSessionTicket)
            {
               /*
                * TODO[new_session_ticket] Check the server-side rules regarding the session ID, since the client
                * is going to ignore any session ID it received once it sees the new_session_ticket message.
                */

                NewSessionTicket newSessionTicket = server.GetNewSessionTicket();
                byte[] newSessionTicketBody = GenerateNewSessionTicket(state, newSessionTicket);
                handshake.SendMessage(HandshakeType.new_session_ticket, newSessionTicketBody);
            }

            // NOTE: Calculated exclusive of the Finished message itself
            securityParameters.m_localVerifyData = TlsUtilities.CalculateVerifyData(serverContext,
                handshake.HandshakeHash, true);
            handshake.SendMessage(HandshakeType.finished, securityParameters.LocalVerifyData);

            handshake.Finish();

            state.sessionMasterSecret = securityParameters.MasterSecret;

            state.sessionParameters = new SessionParameters.Builder()
                .SetCipherSuite(securityParameters.CipherSuite)
                .SetExtendedMasterSecret(securityParameters.IsExtendedMasterSecret)
                .SetLocalCertificate(securityParameters.LocalCertificate)
                .SetMasterSecret(serverContext.Crypto.AdoptSecret(state.sessionMasterSecret))
                .SetNegotiatedVersion(securityParameters.NegotiatedVersion)
                .SetPeerCertificate(securityParameters.PeerCertificate)
                .SetPskIdentity(securityParameters.PskIdentity)
                .SetSrpIdentity(securityParameters.SrpIdentity)
                // TODO Consider filtering extensions that aren't relevant to resumed sessions
                .SetServerExtensions(state.serverExtensions)
                .Build();

            state.tlsSession = TlsUtilities.ImportSession(securityParameters.SessionID, state.sessionParameters);

            if (ProtocolVersion.DTLSv12.IsEqualOrLaterVersionOf(securityParameters.NegotiatedVersion))
            {
                securityParameters.m_tlsUnique = securityParameters.PeerVerifyData;
            }

            serverContext.HandshakeComplete(server, state.tlsSession);

            recordLayer.InitHeartbeat(state.heartbeat, HeartbeatMode.peer_allowed_to_send == state.heartbeatPolicy);

            return new DtlsTransport(recordLayer, server.IgnoreCorruptDtlsRecords);
        }

        /// <exception cref="IOException"/>
        protected virtual byte[] GenerateCertificateRequest(ServerHandshakeState state,
            CertificateRequest certificateRequest)
        {
            MemoryStream buf = new MemoryStream();
            certificateRequest.Encode(state.serverContext, buf);
            return buf.ToArray();
        }

        /// <exception cref="IOException"/>
        protected virtual byte[] GenerateCertificateStatus(ServerHandshakeState state,
            CertificateStatus certificateStatus)
        {
            MemoryStream buf = new MemoryStream();
            // TODO[tls13] Ensure this cannot happen for (D)TLS1.3+
            certificateStatus.Encode(buf);
            return buf.ToArray();
        }

        /// <exception cref="IOException"/>
        protected virtual byte[] GenerateNewSessionTicket(ServerHandshakeState state,
            NewSessionTicket newSessionTicket)
        {
            MemoryStream buf = new MemoryStream();
            newSessionTicket.Encode(buf);
            return buf.ToArray();
        }

        /// <exception cref="IOException"/>
        internal virtual byte[] GenerateServerHello(ServerHandshakeState state)
        {
            TlsServer server = state.server;
            TlsServerContextImpl serverContext = state.serverContext;
            SecurityParameters securityParameters = serverContext.SecurityParameters;


            ProtocolVersion serverVersion;

            // NOT renegotiating
            {
                serverVersion = server.GetServerVersion();
                if (!ProtocolVersion.Contains(serverContext.ClientSupportedVersions, serverVersion))
                    throw new TlsFatalAlert(AlertDescription.internal_error);

                // TODO[dtls13] Read draft/RFC for guidance on the legacy_record_version field
                //ProtocolVersion legacy_record_version = server_version.IsLaterVersionOf(ProtocolVersion.DTLSv12)
                //    ? ProtocolVersion.DTLSv12
                //    : server_version;

                //state.recordLayer.SetWriteVersion(legacy_record_version);
                securityParameters.m_negotiatedVersion = serverVersion;
            }

            // TODO[dtls13]
            //if (ProtocolVersion.DTLSv13.IsEqualOrEarlierVersionOf(serverVersion))
            //{
            //    // See RFC 8446 D.4.
            //    state.recordLayer.SetIgnoreChangeCipherSpec(true);

            //    state.recordLayer.ReadVersion = ProtocolVersion.DTLSv12;
            //    state.recordLayer.SetWriteVersion(ProtocolVersion.DTLSv12);

            //    return Generate13ServerHello(clientHello, clientHelloMessage, false);
            //}

            state.recordLayer.ReadVersion = serverVersion;
            state.recordLayer.SetWriteVersion(serverVersion);

            {
                bool useGmtUnixTime = server.ShouldUseGmtUnixTime();

                securityParameters.m_serverRandom = TlsProtocol.CreateRandomBlock(useGmtUnixTime, serverContext);

                if (!serverVersion.Equals(ProtocolVersion.GetLatestDtls(server.GetProtocolVersions())))
                {
                    TlsUtilities.WriteDowngradeMarker(serverVersion, securityParameters.ServerRandom);
                }
            }

            var clientHelloExtensions = state.clientHello.Extensions;

            TlsSession sessionToResume = server.GetSessionToResume(state.clientHello.SessionID);

            bool resumedSession = EstablishSession(state, sessionToResume);

            if (resumedSession && !serverVersion.Equals(state.sessionParameters.NegotiatedVersion))
            {
                resumedSession = false;
            }

            // TODO Check the session cipher suite is selectable by the same rules that GetSelectedCipherSuite uses

            // TODO Check the resumed session has a peer certificate if we NEED client-auth

            // extended_master_secret
            {
                bool negotiateEms = false;

                if (TlsUtilities.IsExtendedMasterSecretOptional(serverVersion) &&
                    server.ShouldUseExtendedMasterSecret())
                {
                    if (TlsExtensionsUtilities.HasExtendedMasterSecretExtension(clientHelloExtensions))
                    {
                        negotiateEms = true;
                    }
                    else if (server.RequiresExtendedMasterSecret())
                    {
                        throw new TlsFatalAlert(AlertDescription.handshake_failure,
                            "Extended Master Secret extension is required");
                    }
                    else if (resumedSession)
                    {
                        if (state.sessionParameters.IsExtendedMasterSecret)
                        {
                            throw new TlsFatalAlert(AlertDescription.handshake_failure,
                                "Extended Master Secret extension is required for EMS session resumption");
                        }

                        if (!server.AllowLegacyResumption())
                        {
                            throw new TlsFatalAlert(AlertDescription.handshake_failure,
                                "Extended Master Secret extension is required for legacy session resumption");
                        }
                    }
                }

                if (resumedSession && negotiateEms != state.sessionParameters.IsExtendedMasterSecret)
                {
                    resumedSession = false;
                }

                securityParameters.m_extendedMasterSecret = negotiateEms;
            }

            if (!resumedSession)
            {
                CancelSession(state);

                byte[] newSessionID = server.GetNewSessionID();
                if (null == newSessionID)
                {
                    newSessionID = TlsUtilities.EmptyBytes;
                }

                state.tlsSession = TlsUtilities.ImportSession(newSessionID, null);
            }

            securityParameters.m_resumedSession = resumedSession;
            securityParameters.m_sessionID = state.tlsSession.SessionID;

            server.NotifySession(state.tlsSession);

            TlsUtilities.NegotiatedVersionDtlsServer(serverContext);

            {
                int cipherSuite = ValidateSelectedCipherSuite(server.GetSelectedCipherSuite(),
                    AlertDescription.internal_error);

                if (!TlsUtilities.IsValidCipherSuiteSelection(state.clientHello.CipherSuites, cipherSuite) ||
                    !TlsUtilities.IsValidVersionForCipherSuite(cipherSuite, securityParameters.NegotiatedVersion))
                {
                    throw new TlsFatalAlert(AlertDescription.internal_error);
                }

                TlsUtilities.NegotiatedCipherSuite(securityParameters, cipherSuite);
            }

            {
                IDictionary<int, byte[]> sessionServerExtensions = resumedSession
                    ?   state.sessionParameters.ReadServerExtensions()
                    :   server.GetServerExtensions();

                state.serverExtensions = TlsExtensionsUtilities.EnsureExtensionsInitialised(sessionServerExtensions);
            }

            server.GetServerExtensionsForConnection(state.serverExtensions);

            // NOT renegotiating
            {
                /*
                 * RFC 5746 3.6. Server Behavior: Initial Handshake (both full and session-resumption)
                 */
                if (securityParameters.IsSecureRenegotiation)
                {
                    byte[] serverRenegExtData = TlsUtilities.GetExtensionData(state.serverExtensions,
                        ExtensionType.renegotiation_info);
                    bool noRenegExt = (null == serverRenegExtData);

                    if (noRenegExt)
                    {
                        /*
                         * Note that sending a "renegotiation_info" extension in response to a ClientHello
                         * containing only the SCSV is an explicit exception to the prohibition in RFC 5246,
                         * Section 7.4.1.4, on the server sending unsolicited extensions and is only allowed
                         * because the client is signaling its willingness to receive the extension via the
                         * TLS_EMPTY_RENEGOTIATION_INFO_SCSV SCSV.
                         */

                        /*
                         * If the secure_renegotiation flag is set to TRUE, the server MUST include an empty
                         * "renegotiation_info" extension in the ServerHello message.
                         */
                        state.serverExtensions[ExtensionType.renegotiation_info] = TlsProtocol.CreateRenegotiationInfo(
                            TlsUtilities.EmptyBytes);
                    }
                }
            }

            if (securityParameters.IsExtendedMasterSecret)
            {
                TlsExtensionsUtilities.AddExtendedMasterSecretExtension(state.serverExtensions);
            }
            else
            {
                state.serverExtensions.Remove(ExtensionType.extended_master_secret);
            }

            // Heartbeats
            if (null != state.heartbeat || HeartbeatMode.peer_allowed_to_send == state.heartbeatPolicy)
            {
                TlsExtensionsUtilities.AddHeartbeatExtension(state.serverExtensions,
                    new HeartbeatExtension(state.heartbeatPolicy));
            }

            securityParameters.m_applicationProtocol = TlsExtensionsUtilities.GetAlpnExtensionServer(
                state.serverExtensions);
            securityParameters.m_applicationProtocolSet = true;

            // Connection ID
            if (ProtocolVersion.DTLSv12.Equals(securityParameters.NegotiatedVersion))
            {
                /*
                 * RFC 9146 3. When a DTLS session is resumed or renegotiated, the "connection_id" extension is
                 * negotiated afresh.
                 */
                var serverConnectionID = TlsExtensionsUtilities.GetConnectionIDExtension(state.serverExtensions);
                if (serverConnectionID != null)
                {
                    var clientConnectionID = TlsExtensionsUtilities.GetConnectionIDExtension(clientHelloExtensions)
                        ?? throw new TlsFatalAlert(AlertDescription.internal_error);

                    securityParameters.m_connectionIDLocal = clientConnectionID;
                    securityParameters.m_connectionIDPeer = serverConnectionID;
                }
            }

            if (state.serverExtensions.Count > 0)
            {
                securityParameters.m_encryptThenMac = TlsExtensionsUtilities.HasEncryptThenMacExtension(
                    state.serverExtensions);

                securityParameters.m_maxFragmentLength = TlsUtilities.ProcessMaxFragmentLengthExtension(
                    resumedSession ? null : clientHelloExtensions, state.serverExtensions,
                    AlertDescription.internal_error);

                securityParameters.m_truncatedHmac = TlsExtensionsUtilities.HasTruncatedHmacExtension(
                    state.serverExtensions);

                if (!resumedSession)
                {
                    // TODO[tls13] See RFC 8446 4.4.2.1
                    if (TlsUtilities.HasExpectedEmptyExtensionData(state.serverExtensions,
                        ExtensionType.status_request_v2, AlertDescription.internal_error))
                    {
                        securityParameters.m_statusRequestVersion = 2;
                    }
                    else if (TlsUtilities.HasExpectedEmptyExtensionData(state.serverExtensions,
                        ExtensionType.status_request, AlertDescription.internal_error))
                    {
                        securityParameters.m_statusRequestVersion = 1;
                    }

                    securityParameters.m_clientCertificateType = TlsUtilities.ProcessClientCertificateTypeExtension(
                        clientHelloExtensions, state.serverExtensions, AlertDescription.internal_error);
                    securityParameters.m_serverCertificateType = TlsUtilities.ProcessServerCertificateTypeExtension(
                        clientHelloExtensions, state.serverExtensions, AlertDescription.internal_error);

                    state.expectSessionTicket = TlsUtilities.HasExpectedEmptyExtensionData(state.serverExtensions,
                        ExtensionType.session_ticket, AlertDescription.internal_error);
                }
            }

            ServerHello serverHello = new ServerHello(serverVersion, securityParameters.ServerRandom,
                securityParameters.SessionID, securityParameters.CipherSuite, state.serverExtensions);

            state.clientHello = null;

            ApplyMaxFragmentLengthExtension(state.recordLayer, securityParameters.MaxFragmentLength);

            MemoryStream buf = new MemoryStream();
            serverHello.Encode(serverContext, buf);
            return buf.ToArray();
        }

        protected virtual void CancelSession(ServerHandshakeState state)
        {
            if (state.sessionMasterSecret != null)
            {
                state.sessionMasterSecret.Destroy();
                state.sessionMasterSecret = null;
            }

            if (state.sessionParameters != null)
            {
                state.sessionParameters.Clear();
                state.sessionParameters = null;
            }

            state.tlsSession = null;
        }

        protected virtual bool EstablishSession(ServerHandshakeState state, TlsSession sessionToResume)
        {
            state.tlsSession = null;
            state.sessionParameters = null;
            state.sessionMasterSecret = null;

            if (null == sessionToResume || !sessionToResume.IsResumable)
                return false;

            SessionParameters sessionParameters = sessionToResume.ExportSessionParameters();
            if (null == sessionParameters)
                return false;

            ProtocolVersion sessionVersion = sessionParameters.NegotiatedVersion;
            if (null == sessionVersion || !sessionVersion.IsDtls)
                return false;

            if (!sessionParameters.IsExtendedMasterSecret &&
                !TlsUtilities.IsExtendedMasterSecretOptional(sessionVersion))
            {
                return false;
            }

            TlsCrypto crypto = state.serverContext.Crypto;
            TlsSecret sessionMasterSecret = TlsUtilities.GetSessionMasterSecret(crypto, sessionParameters.MasterSecret);
            if (null == sessionMasterSecret)
                return false;

            state.tlsSession = sessionToResume;
            state.sessionParameters = sessionParameters;
            state.sessionMasterSecret = sessionMasterSecret;

            return true;
        }

        protected virtual void InvalidateSession(ServerHandshakeState state)
        {
            if (state.tlsSession != null)
            {
                state.tlsSession.Invalidate();
            }

            CancelSession(state);
        }

        /// <exception cref="IOException"/>
        protected virtual void NotifyClientCertificate(ServerHandshakeState state, Certificate clientCertificate)
        {
            if (null == state.certificateRequest)
                throw new TlsFatalAlert(AlertDescription.internal_error);

            TlsUtilities.ProcessClientCertificate(state.serverContext, clientCertificate, state.keyExchange,
                state.server);
        }

        /// <exception cref="IOException"/>
        protected virtual void ProcessClientCertificate(ServerHandshakeState state, byte[] body)
        {
            MemoryStream buf = new MemoryStream(body, false);

            Certificate.ParseOptions options = new Certificate.ParseOptions()
            {
                CertificateType = state.serverContext.SecurityParameters.ClientCertificateType,
                MaxChainLength = state.server.GetMaxCertificateChainLength(),
            };

            Certificate clientCertificate = Certificate.Parse(options, state.serverContext, buf, null);

            TlsProtocol.AssertEmpty(buf);

            NotifyClientCertificate(state, clientCertificate);
        }

        /// <exception cref="IOException"/>
        protected virtual void ProcessCertificateVerify(ServerHandshakeState state, byte[] body,
            TlsHandshakeHash handshakeHash)
        {
            if (state.certificateRequest == null)
                throw new InvalidOperationException();

            MemoryStream buf = new MemoryStream(body, false);

            TlsServerContextImpl serverContext = state.serverContext;
            DigitallySigned certificateVerify = DigitallySigned.Parse(serverContext, buf);

            TlsProtocol.AssertEmpty(buf);

            TlsUtilities.VerifyCertificateVerifyClient(serverContext, state.certificateRequest, certificateVerify,
                handshakeHash);
        }

        /// <exception cref="IOException"/>
        protected virtual void ProcessClientHello(ServerHandshakeState state, byte[] body)
        {
            MemoryStream buf = new MemoryStream(body, false);
            ClientHello clientHello = ClientHello.Parse(buf, Stream.Null);
            ProcessClientHello(state, clientHello);
        }

        /// <exception cref="IOException"/>
        protected virtual void ProcessClientHello(ServerHandshakeState state, ClientHello clientHello)
        {
            state.recordLayer.SetWriteVersion(ProtocolVersion.DTLSv10);

            state.clientHello = clientHello;

            // TODO Read RFCs for guidance on the expected record layer version number
            ProtocolVersion legacy_version = clientHello.Version;
            int[] offeredCipherSuites = clientHello.CipherSuites;
            var clientHelloExtensions = clientHello.Extensions;



            TlsServer server = state.server;
            TlsServerContextImpl serverContext = state.serverContext;
            SecurityParameters securityParameters = serverContext.SecurityParameters;

            if (!legacy_version.IsDtls)
                throw new TlsFatalAlert(AlertDescription.illegal_parameter);

            serverContext.SetRsaPreMasterSecretVersion(legacy_version);

            serverContext.SetClientSupportedVersions(
                TlsExtensionsUtilities.GetSupportedVersionsExtensionClient(clientHelloExtensions));

            ProtocolVersion client_version = legacy_version;
            if (null == serverContext.ClientSupportedVersions)
            {
                if (client_version.IsLaterVersionOf(ProtocolVersion.DTLSv12))
                {
                    client_version = ProtocolVersion.DTLSv12;
                }

                serverContext.SetClientSupportedVersions(client_version.DownTo(ProtocolVersion.DTLSv10));
            }
            else
            {
                client_version = ProtocolVersion.GetLatestDtls(serverContext.ClientSupportedVersions);
            }

            if (!ProtocolVersion.SERVER_EARLIEST_SUPPORTED_DTLS.IsEqualOrEarlierVersionOf(client_version))
                throw new TlsFatalAlert(AlertDescription.protocol_version);

            serverContext.SetClientVersion(client_version);

            server.NotifyClientVersion(serverContext.ClientVersion);

            securityParameters.m_clientRandom = clientHello.Random;

            server.NotifyFallback(Arrays.Contains(offeredCipherSuites, CipherSuite.TLS_FALLBACK_SCSV));

            server.NotifyOfferedCipherSuites(offeredCipherSuites);

            /*
             * TODO[resumption] Check RFC 7627 5.4. for required behaviour 
             */

            byte[] clientRenegExtData = TlsUtilities.GetExtensionData(clientHelloExtensions,
                ExtensionType.renegotiation_info);

            // NOT renegotiatiing
            {
                /*
                 * RFC 5746 3.6. Server Behavior: Initial Handshake (both full and session-resumption)
                 */

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
                if (Arrays.Contains(offeredCipherSuites, CipherSuite.TLS_EMPTY_RENEGOTIATION_INFO_SCSV))
                {
                    securityParameters.m_secureRenegotiation = true;
                }

                if (clientRenegExtData != null)
                {
                    /*
                     * If the extension is present, set secure_renegotiation flag to TRUE. The
                     * server MUST then verify that the length of the "renegotiated_connection"
                     * field is zero, and if it is not, MUST abort the handshake.
                     */
                    securityParameters.m_secureRenegotiation = true;

                    if (!Arrays.FixedTimeEquals(clientRenegExtData,
                        TlsProtocol.CreateRenegotiationInfo(TlsUtilities.EmptyBytes)))
                    {
                        throw new TlsFatalAlert(AlertDescription.handshake_failure);
                    }
                }
            }

            server.NotifySecureRenegotiation(securityParameters.IsSecureRenegotiation);

            if (clientHelloExtensions != null)
            {
                // NOTE: Validates the padding extension data, if present
                TlsExtensionsUtilities.GetPaddingExtension(clientHelloExtensions);

                securityParameters.m_clientServerNames = TlsExtensionsUtilities.GetServerNameExtensionClient(
                    clientHelloExtensions);

                /*
                 * RFC 5246 7.4.1.4.1. Note: this extension is not meaningful for TLS versions prior
                 * to 1.2. Clients MUST NOT offer it if they are offering prior versions.
                 */
                if (TlsUtilities.IsSignatureAlgorithmsExtensionAllowed(client_version))
                {
                    TlsUtilities.EstablishClientSigAlgs(securityParameters, clientHelloExtensions);
                }

                securityParameters.m_clientSupportedGroups = TlsExtensionsUtilities.GetSupportedGroupsExtension(
                    clientHelloExtensions);

                // Heartbeats
                {
                    HeartbeatExtension heartbeatExtension = TlsExtensionsUtilities.GetHeartbeatExtension(
                        clientHelloExtensions);
                    if (null != heartbeatExtension)
                    {
                        if (HeartbeatMode.peer_allowed_to_send == heartbeatExtension.Mode)
                        {
                            state.heartbeat = server.GetHeartbeat();
                        }

                        state.heartbeatPolicy = server.GetHeartbeatPolicy();
                    }
                }

                server.ProcessClientExtensions(clientHelloExtensions);
            }
        }

        /// <exception cref="IOException"/>
        protected virtual void ProcessClientKeyExchange(ServerHandshakeState state, byte[] body)
        {
            MemoryStream buf = new MemoryStream(body, false);
            state.keyExchange.ProcessClientKeyExchange(buf);
            TlsProtocol.AssertEmpty(buf);
        }

        /// <exception cref="IOException"/>
        protected virtual void ProcessClientSupplementalData(ServerHandshakeState state, byte[] body)
        {
            MemoryStream buf = new MemoryStream(body, false);
            var clientSupplementalData = TlsProtocol.ReadSupplementalDataMessage(buf);
            state.server.ProcessClientSupplementalData(clientSupplementalData);
        }

        protected virtual bool ExpectCertificateVerifyMessage(ServerHandshakeState state)
        {
            if (null == state.certificateRequest)
                return false;

            Certificate clientCertificate = state.serverContext.SecurityParameters.PeerCertificate;

            return null != clientCertificate && !clientCertificate.IsEmpty
                && (null == state.keyExchange || state.keyExchange.RequiresCertificateVerify);
        }

        protected internal class ServerHandshakeState
        {
            internal TlsServer server = null;
            internal TlsServerContextImpl serverContext = null;
            internal DtlsRecordLayer recordLayer = null;
            internal TlsSession tlsSession = null;
            internal SessionParameters sessionParameters = null;
            internal TlsSecret sessionMasterSecret = null;
            internal SessionParameters.Builder sessionParametersBuilder = null;
            internal ClientHello clientHello = null;
            internal IDictionary<int, byte[]> serverExtensions = null;
            internal bool expectSessionTicket = false;
            internal TlsKeyExchange keyExchange = null;
            internal TlsCredentials serverCredentials = null;
            internal CertificateRequest certificateRequest = null;
            internal TlsHeartbeat heartbeat = null;
            internal short heartbeatPolicy = HeartbeatMode.peer_not_allowed_to_send;
        }
    }
}
