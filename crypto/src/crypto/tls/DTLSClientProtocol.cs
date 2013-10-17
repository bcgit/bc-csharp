using System.Collections;
using System;
using Org.BouncyCastle.Security;
using System.IO;
using Org.BouncyCastle.Utilities;


namespace Org.BouncyCastle.Crypto.Tls
{

    public class DTLSClientProtocol : DTLSProtocol
    {
        public DTLSClientProtocol(SecureRandom secureRandom)
            : base(secureRandom)
        {

        }

        public DTLSTransport Connect(TlsClient client, DatagramTransport transport)
        {
            if (client == null)
            {
                throw new ArgumentException("'client' cannot be null");
            }
            if (transport == null)
            {
                throw new ArgumentException("'transport' cannot be null");
            }

            SecurityParameters securityParameters = new SecurityParameters();
            securityParameters.entity = ConnectionEnd.client;
            securityParameters.clientRandom = TlsProtocol.CreateRandomBlock(secureRandom);

            ClientHandshakeState state = new ClientHandshakeState();
            state.client = client;
            state.clientContext = new TlsClientContextImpl(secureRandom, securityParameters);
            client.Init(state.clientContext);

            DTLSRecordLayer recordLayer = new DTLSRecordLayer(transport, state.clientContext, client, ContentType.handshake);

            TlsSession sessionToResume = state.client.SessionToResume;
            if (sessionToResume != null)
            {
                SessionParameters sessionParameters = sessionToResume.ExportSessionParameters();
                if (sessionParameters != null)
                {
                    state.tlsSession = sessionToResume;
                    state.sessionParameters = sessionParameters;
                }
            }

            try
            {
                return ClientHandshake(state, recordLayer);
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

        private DTLSTransport ClientHandshake(ClientHandshakeState state, DTLSRecordLayer recordLayer)
        {
            SecurityParameters securityParameters = state.clientContext.SecurityParameters;
            DTLSReliableHandshake handshake = new DTLSReliableHandshake(state.clientContext, recordLayer);

            byte[] clientHelloBody = GenerateClientHello(state, state.client);
            handshake.SendMessage(HandshakeType.client_hello, clientHelloBody);

            DTLSReliableHandshake.Message serverMessage = handshake.ReceiveMessage();

            {
                // NOTE: After receiving a record from the server, we discover the record layer version
                ProtocolVersion server_version = recordLayer.DiscoveredPeerVersion;
                ProtocolVersion client_version = state.clientContext.ClientVersion;

                if (!server_version.IsEqualOrEarlierVersionOf(client_version))
                {
                    throw new TlsFatalAlert(AlertDescription.illegal_parameter);
                }

                state.clientContext.ServerVersion = server_version;
                state.client.NotifyServerVersion(server_version);
            }

            while (serverMessage.Type == HandshakeType.hello_verify_request)
            {
                byte[] cookie = ParseHelloVerifyRequest(state.clientContext, serverMessage.Body);
                byte[] patched = PatchClientHelloWithCookie(clientHelloBody, cookie);

                handshake.ResetHandshakeMessagesDigest();
                handshake.SendMessage(HandshakeType.client_hello, patched);

                serverMessage = handshake.ReceiveMessage();
            }

            if (serverMessage.Type == HandshakeType.server_hello)
            {
                ProcessServerHello(state, serverMessage.Body);
            }
            else
            {
                throw new TlsFatalAlert(AlertDescription.unexpected_message);
            }

            if (state.maxFragmentLength >= 0)
            {
                int plainTextLimit = 1 << (8 + state.maxFragmentLength);
                recordLayer.SetPlaintextLimit(plainTextLimit);
            }

            securityParameters.cipherSuite = state.selectedCipherSuite;
            securityParameters.compressionAlgorithm = state.selectedCompressionMethod;
            securityParameters.prfAlgorithm = TlsProtocol.GetPRFAlgorithm(state.clientContext, state.selectedCipherSuite);

            /*
             * RFC 5264 7.4.9. Any cipher suite which does not explicitly specify verify_data_length has
             * a verify_data_length equal to 12. This includes all existing cipher suites.
             */
            securityParameters.verifyDataLength = 12;

            handshake.NotifyHelloComplete();

            bool resumedSession = state.selectedSessionID.Length > 0 && state.tlsSession != null
                && Arrays.AreEqual(state.selectedSessionID, state.tlsSession.GetSessionID());

            byte[] clientVerifyData;
            byte[] expectedServerVerifyData;

            if (resumedSession)
            {
                if (securityParameters.CipherSuite != state.sessionParameters.CipherSuite
                    || securityParameters.CompressionAlgorithm != state.sessionParameters.CompressionAlgorithm)
                {
                    throw new TlsFatalAlert(AlertDescription.illegal_parameter);
                }

                securityParameters.masterSecret = Arrays.Clone(state.sessionParameters.MasterSecret);
                recordLayer.InitPendingEpoch(state.client.GetCipher());

                // NOTE: Calculated exclusive of the actual Finished message from the server
                expectedServerVerifyData = TlsUtilities.CalculateVerifyData(state.clientContext, "server finished",
                    handshake.GetCurrentHash());
                ProcessFinished(handshake.ReceiveMessageBody(HandshakeType.finished), expectedServerVerifyData);

                // NOTE: Calculated exclusive of the Finished message itself
                clientVerifyData = TlsUtilities.CalculateVerifyData(state.clientContext, "client finished",
                    handshake.GetCurrentHash());
                handshake.SendMessage(HandshakeType.finished, clientVerifyData);

                handshake.Finish();

                state.clientContext.ResumableSession = state.tlsSession;

                state.client.NotifyHandshakeComplete();

                return new DTLSTransport(recordLayer);
            }

            InvalidateSession(state);

            if (state.selectedSessionID.Length > 0)
            {
                state.tlsSession = new TlsSessionImpl(state.selectedSessionID, null);
            }

            serverMessage = handshake.ReceiveMessage();

            if (serverMessage.Type == HandshakeType.supplemental_data)
            {
                ProcessServerSupplementalData(state, serverMessage.Body);
                serverMessage = handshake.ReceiveMessage();
            }
            else
            {
                state.client.ProcessServerSupplementalData(null);
            }

            state.keyExchange = state.client.GetKeyExchange();
            state.keyExchange.Init(state.clientContext);

            Certificate serverCertificate = null;

            if (serverMessage.Type == HandshakeType.certificate)
            {
                serverCertificate = ProcessServerCertificate(state, serverMessage.Body);
                serverMessage = handshake.ReceiveMessage();
            }
            else
            {
                // Okay, Certificate is optional
                state.keyExchange.SkipServerCredentials();
            }

            // TODO[RFC 3546] Check whether empty certificates is possible, allowed, or excludes CertificateStatus
            if (serverCertificate == null || serverCertificate.IsEmpty)
            {
                state.allowCertificateStatus = false;
            }

            if (serverMessage.Type == HandshakeType.certificate_status)
            {
                ProcessCertificateStatus(state, serverMessage.Body);
                serverMessage = handshake.ReceiveMessage();
            }
            else
            {
                // Okay, CertificateStatus is optional
            }

            if (serverMessage.Type == HandshakeType.server_key_exchange)
            {
                processServerKeyExchange(state, serverMessage.Body);
                serverMessage = handshake.ReceiveMessage();
            }
            else
            {
                // Okay, ServerKeyExchange is optional
                state.keyExchange.SkipServerKeyExchange();
            }

            if (serverMessage.Type == HandshakeType.certificate_request)
            {
                ProcessCertificateRequest(state, serverMessage.Body);
                serverMessage = handshake.ReceiveMessage();
            }
            else
            {
                // Okay, CertificateRequest is optional
            }

            if (serverMessage.Type == HandshakeType.server_hello_done)
            {
                if (serverMessage.Body.Length != 0)
                {
                    throw new TlsFatalAlert(AlertDescription.decode_error);
                }
            }
            else
            {
                throw new TlsFatalAlert(AlertDescription.unexpected_message);
            }

            var clientSupplementalData = state.client.GetClientSupplementalData();
            if (clientSupplementalData != null)
            {
                byte[] supplementalDataBody = GenerateSupplementalData(clientSupplementalData);
                handshake.SendMessage(HandshakeType.supplemental_data, supplementalDataBody);
            }

            if (state.certificateRequest != null)
            {
                state.clientCredentials = state.authentication.GetClientCredentials(state.certificateRequest);

                /*
                 * RFC 5246 If no suitable certificate is available, the client MUST send a certificate
                 * message containing no certificates.
                 * 
                 * NOTE: In previous RFCs, this was SHOULD instead of MUST.
                 */
                Certificate clientCertificate = null;
                if (state.clientCredentials != null)
                {
                    clientCertificate = state.clientCredentials.Certificate;
                }
                if (clientCertificate == null)
                {
                    clientCertificate = Certificate.EmptyChain;
                }

                byte[] certificateBody = GenerateCertificate(clientCertificate);
                handshake.SendMessage(HandshakeType.certificate, certificateBody);
            }

            if (state.clientCredentials != null)
            {
                state.keyExchange.ProcessClientCredentials(state.clientCredentials);
            }
            else
            {
                state.keyExchange.SkipClientCredentials();
            }

            byte[] clientKeyExchangeBody = GenerateClientKeyExchange(state);
            handshake.SendMessage(HandshakeType.client_key_exchange, clientKeyExchangeBody);

            TlsProtocol.EstablishMasterSecret(state.clientContext, state.keyExchange);
            recordLayer.InitPendingEpoch(state.client.GetCipher());

            if (state.clientCredentials != null && state.clientCredentials is TlsSignerCredentials)
            {
                TlsSignerCredentials signerCredentials = (TlsSignerCredentials)state.clientCredentials;
                byte[] md5andsha1 = handshake.GetCurrentHash();
                byte[] signature = signerCredentials.GenerateCertificateSignature(md5andsha1);
                /*
                 * TODO RFC 5246 4.7. digitally-signed element needs SignatureAndHashAlgorithm from TLS 1.2
                 */
                DigitallySigned certificateVerify = new DigitallySigned(null, signature);
                byte[] certificateVerifyBody = GenerateCertificateVerify(state, certificateVerify);
                handshake.SendMessage(HandshakeType.certificate_verify, certificateVerifyBody);
            }

            // NOTE: Calculated exclusive of the Finished message itself
            clientVerifyData = TlsUtilities.CalculateVerifyData(state.clientContext, "client finished",
                handshake.GetCurrentHash());

            handshake.SendMessage(HandshakeType.finished, clientVerifyData);

            if (state.expectSessionTicket)
            {
                serverMessage = handshake.ReceiveMessage();
                if (serverMessage.Type == HandshakeType.session_ticket)
                {
                    ProcessNewSessionTicket(state, serverMessage.Body);
                }
                else
                {
                    throw new TlsFatalAlert(AlertDescription.unexpected_message);
                }
            }

            // NOTE: Calculated exclusive of the actual Finished message from the server
            expectedServerVerifyData = TlsUtilities.CalculateVerifyData(state.clientContext, "server finished",
                handshake.GetCurrentHash());
            ProcessFinished(handshake.ReceiveMessageBody(HandshakeType.finished), expectedServerVerifyData);

            handshake.Finish();

            if (state.tlsSession != null)
            {
                state.sessionParameters = new SessionParameters.Builder()
                    .SetCipherSuite(securityParameters.cipherSuite)
                    .SetCompressionAlgorithm(securityParameters.compressionAlgorithm)
                    .SetMasterSecret(securityParameters.masterSecret)
                    .SetPeerCertificate(serverCertificate)
                    .Build();

                state.tlsSession = TlsUtilities.ImportSession(state.tlsSession.GetSessionID(), state.sessionParameters);

                state.clientContext.ResumableSession = state.tlsSession;
            }

            state.client.NotifyHandshakeComplete();

            return new DTLSTransport(recordLayer);
        }

        protected byte[] GenerateCertificateVerify(ClientHandshakeState state, DigitallySigned certificateVerify)
        {
            MemoryStream buf = new MemoryStream();
            certificateVerify.Encode(buf);
            return buf.ToArray();
        }

        protected byte[] GenerateClientHello(ClientHandshakeState state, TlsClient client)
        {
            MemoryStream buf = new MemoryStream();

            ProtocolVersion client_version = client.ClientVersion;
            if (!client_version.IsDTLS)
            {
                throw new TlsFatalAlert(AlertDescription.internal_error);
            }

            state.clientContext.ClientVersion = client_version;
            TlsUtilities.WriteVersion(client_version, buf);

            var clientRandom = state.clientContext.SecurityParameters.ClientRandom;
            buf.Write(clientRandom, 0, clientRandom.Length);

            // Session ID
            byte[] session_id = TlsUtilities.EMPTY_BYTES;
            if (state.tlsSession != null)
            {
                session_id = state.tlsSession.GetSessionID();
                if (session_id == null || session_id.Length > 32)
                {
                    session_id = TlsUtilities.EMPTY_BYTES;
                }
            }
            TlsUtilities.WriteOpaque8(session_id, buf);

            // Cookie
            TlsUtilities.WriteOpaque8(TlsUtilities.EMPTY_BYTES, buf);

            /*
             * Cipher suites
             */
            state.offeredCipherSuites = client.GetCipherSuites();

            // Integer -> byte[]
            state.clientExtensions = client.GetClientExtensions();

            // Cipher Suites (and SCSV)
            {
                /*
                 * RFC 5746 3.4. The client MUST include either an empty "renegotiation_info" extension,
                 * or the TLS_EMPTY_RENEGOTIATION_INFO_SCSV signaling cipher suite value in the
                 * ClientHello. Including both is NOT RECOMMENDED.
                 */
                byte[] renegExtData = TlsUtilities.GetExtensionData(state.clientExtensions, TlsProtocol.EXT_RenegotiationInfo);
                bool noRenegExt = (null == renegExtData);

                int count = state.offeredCipherSuites.Length;
                if (noRenegExt)
                {
                    // Note: 1 extra slot for TLS_EMPTY_RENEGOTIATION_INFO_SCSV
                    ++count;
                }

                int length = 2 * count;
                TlsUtilities.CheckUint16(length);
                TlsUtilities.WriteUint16(length, buf);
                TlsUtilities.WriteUint16Array(state.offeredCipherSuites, buf);

                if (noRenegExt)
                {
                    TlsUtilities.WriteUint16((short)CipherSuite.TLS_EMPTY_RENEGOTIATION_INFO_SCSV, buf);
                }
            }

            // TODO Add support for compression
            // Compression methods
            // state.offeredCompressionMethods = client.getCompressionMethods();
            state.offeredCompressionMethods = new CompressionMethod[] { CompressionMethod.NULL };

            TlsUtilities.CheckUint8(state.offeredCompressionMethods.Length);
            TlsUtilities.WriteUint8(state.offeredCompressionMethods.Length, buf);
            TlsUtilities.WriteUint8Array(state.offeredCompressionMethods, buf);

            // Extensions
            if (state.clientExtensions != null)
            {
                TlsProtocol.WriteExtensions(buf, state.clientExtensions);
            }

            return buf.ToArray();
        }

        protected byte[] GenerateClientKeyExchange(ClientHandshakeState state)
        {
            MemoryStream buf = new MemoryStream();
            state.keyExchange.GenerateClientKeyExchange(buf);
            return buf.ToArray();
        }

        protected void InvalidateSession(ClientHandshakeState state)
        {
            if (state.sessionParameters != null)
            {
                state.sessionParameters.Clear();
                state.sessionParameters = null;
            }

            if (state.tlsSession != null)
            {
                state.tlsSession.Invalidate();
                state.tlsSession = null;
            }
        }

        protected void ProcessCertificateRequest(ClientHandshakeState state, byte[] body)
        {
            if (state.authentication == null)
            {
                /*
                 * RFC 2246 7.4.4. It is a fatal handshake_failure alert for an anonymous server to
                 * request client identification.
                 */
                throw new TlsFatalAlert(AlertDescription.handshake_failure);
            }

            MemoryStream buf = new MemoryStream(body);

            state.certificateRequest = CertificateRequest.Parse(state.clientContext, buf);

            TlsProtocol.AssertEmpty(buf);

            state.keyExchange.ValidateCertificateRequest(state.certificateRequest);
        }

        protected void ProcessCertificateStatus(ClientHandshakeState state, byte[] body)
        {
            if (!state.allowCertificateStatus)
            {
                /*
                 * RFC 3546 3.6. If a server returns a "CertificateStatus" message, then the
                 * server MUST have included an extension of type "status_request" with empty
                 * "extension_data" in the extended server hello..
                 */
                throw new TlsFatalAlert(AlertDescription.unexpected_message);
            }

            MemoryStream buf = new MemoryStream(body);

            state.certificateStatus = CertificateStatus.parse(buf);

            TlsProtocol.AssertEmpty(buf);

            // TODO[RFC 3546] Figure out how to provide this to the client/authentication.
        }

        protected void ProcessNewSessionTicket(ClientHandshakeState state, byte[] body)
        {
            MemoryStream buf = new MemoryStream(body);

            NewSessionTicket newSessionTicket = NewSessionTicket.Parse(buf);

            TlsProtocol.AssertEmpty(buf);

            state.client.NotifyNewSessionTicket(newSessionTicket);
        }

        protected Certificate ProcessServerCertificate(ClientHandshakeState state, byte[] body)
        {
            MemoryStream buf = new MemoryStream(body);

            Certificate serverCertificate = Certificate.Parse(buf);

            TlsProtocol.AssertEmpty(buf);

            state.keyExchange.ProcessServerCertificate(serverCertificate);
            state.authentication = state.client.GetAuthentication();
            state.authentication.NotifyServerCertificate(serverCertificate);

            return serverCertificate;
        }

        protected void ProcessServerHello(ClientHandshakeState state, byte[] body)
        {
            SecurityParameters securityParameters = state.clientContext.SecurityParameters;

            MemoryStream buf = new MemoryStream(body);

            // TODO Read RFCs for guidance on the expected record layer version number
            ProtocolVersion server_version = TlsUtilities.ReadVersion(buf);
            if (!server_version.Equals(state.clientContext.ServerVersion))
            {
                throw new TlsFatalAlert(AlertDescription.illegal_parameter);
            }

            securityParameters.serverRandom = TlsUtilities.ReadFully(32, buf);

            state.selectedSessionID = TlsUtilities.ReadOpaque8(buf);
            if (state.selectedSessionID.Length > 32)
            {
                throw new TlsFatalAlert(AlertDescription.illegal_parameter);
            }
            state.client.NotifySessionID(state.selectedSessionID);

            state.selectedCipherSuite = (CipherSuite)TlsUtilities.ReadUint16(buf);
            if (!TlsProtocol.ArrayContains(state.offeredCipherSuites, state.selectedCipherSuite)
                || state.selectedCipherSuite == CipherSuite.TLS_NULL_WITH_NULL_NULL
                || state.selectedCipherSuite == CipherSuite.TLS_EMPTY_RENEGOTIATION_INFO_SCSV)
            {
                throw new TlsFatalAlert(AlertDescription.illegal_parameter);
            }

            ValidateSelectedCipherSuite(state.selectedCipherSuite, AlertDescription.illegal_parameter);

            state.client.NotifySelectedCipherSuite(state.selectedCipherSuite);

            state.selectedCompressionMethod = (CompressionMethod)TlsUtilities.ReadUint8(buf);
            if (!TlsProtocol.ArrayContains(state.offeredCompressionMethods, state.selectedCompressionMethod))
            {
                throw new TlsFatalAlert(AlertDescription.illegal_parameter);
            }
            state.client.NotifySelectedCompressionMethod(state.selectedCompressionMethod);

            /*
             * RFC3546 2.2 The extended server hello message format MAY be sent in place of the server
             * hello message when the client has requested extended functionality via the extended
             * client hello message specified in Section 2.1. ... Note that the extended server hello
             * message is only sent in response to an extended client hello message. This prevents the
             * possibility that the extended server hello message could "break" existing TLS 1.0
             * clients.
             */

            /*
             * TODO RFC 3546 2.3 If [...] the older session is resumed, then the server MUST ignore
             * extensions appearing in the client hello, and send a server hello containing no
             * extensions.
             */

            // Integer -> byte[]
            IDictionary serverExtensions = TlsProtocol.ReadExtensions(buf);

            /*
             * RFC 3546 2.2 Note that the extended server hello message is only sent in response to an
             * extended client hello message. However, see RFC 5746 exception below. We always include
             * the SCSV, so an Extended Server Hello is always allowed.
             */
            if (serverExtensions != null)
            {
                foreach(var e in serverExtensions.Keys)
                {
                    ExtensionType extType = (ExtensionType)e;

                    /*
                     * RFC 5746 Note that sending a "renegotiation_info" extension in response to a
                     * ClientHello containing only the SCSV is an explicit exception to the prohibition
                     * in RFC 5246, Section 7.4.1.4, on the server sending unsolicited extensions and is
                     * only allowed because the client is signaling its willingness to receive the
                     * extension via the TLS_EMPTY_RENEGOTIATION_INFO_SCSV SCSV. TLS implementations
                     * MUST continue to comply with Section 7.4.1.4 for all other extensions.
                     */
                    if (!extType.Equals(TlsProtocol.EXT_RenegotiationInfo)
                        && null == TlsUtilities.GetExtensionData(state.clientExtensions, extType))
                    {
                        /*
                         * RFC 3546 2.3 Note that for all extension types (including those defined in
                         * future), the extension type MUST NOT appear in the extended server hello
                         * unless the same extension type appeared in the corresponding client hello.
                         * Thus clients MUST abort the handshake if they receive an extension type in
                         * the extended server hello that they did not request in the associated
                         * (extended) client hello.
                         */
                        throw new TlsFatalAlert(AlertDescription.unsupported_extension);
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
                    byte[] renegExtData = (byte[])serverExtensions[TlsProtocol.EXT_RenegotiationInfo];
                    if (renegExtData != null)
                    {
                        /*
                         * If the extension is present, set the secure_renegotiation flag to TRUE. The
                         * client MUST then verify that the length of the "renegotiated_connection"
                         * field is zero, and if it is not, MUST abort the handshake (by sending a fatal
                         * handshake_failure alert).
                         */
                        state.secure_renegotiation = true;

                        if (!Arrays.ConstantTimeAreEqual(renegExtData,
                            TlsProtocol.CreateRenegotiationInfo(TlsUtilities.EMPTY_BYTES)))
                        {
                            throw new TlsFatalAlert(AlertDescription.handshake_failure);
                        }
                    }
                }

                state.maxFragmentLength = EvaluateMaxFragmentLengthExtension(state.clientExtensions, serverExtensions,
                    AlertDescription.illegal_parameter);

                securityParameters.truncatedHMac = TlsExtensionsUtils.HasTruncatedHMacExtension(serverExtensions);

                state.allowCertificateStatus = TlsUtilities.HasExpectedEmptyExtensionData(serverExtensions,
                    TlsExtensionsUtils.EXT_status_request, AlertDescription.illegal_parameter);

                state.expectSessionTicket = TlsUtilities.HasExpectedEmptyExtensionData(serverExtensions,
                    TlsProtocol.EXT_SessionTicket, AlertDescription.illegal_parameter);
            }

            state.client.NotifySecureRenegotiation(state.secure_renegotiation);

            if (state.clientExtensions != null)
            {
                state.client.ProcessServerExtensions(serverExtensions);
            }
        }

        protected void processServerKeyExchange(ClientHandshakeState state, byte[] body)
        {
            MemoryStream buf = new MemoryStream(body);

            state.keyExchange.ProcessServerKeyExchange(buf);

            TlsProtocol.AssertEmpty(buf);
        }

        protected void ProcessServerSupplementalData(ClientHandshakeState state, byte[] body)
        {
            MemoryStream buf = new MemoryStream(body);
            IList serverSupplementalData = TlsProtocol.ReadSupplementalDataMessage(buf);
            state.client.ProcessServerSupplementalData(serverSupplementalData);
        }

        protected static byte[] ParseHelloVerifyRequest(TlsContext context, byte[] body)
        {
            MemoryStream buf = new MemoryStream(body);

            ProtocolVersion server_version = TlsUtilities.ReadVersion(buf);
            if (!server_version.Equals(context.ServerVersion))
            {
                throw new TlsFatalAlert(AlertDescription.illegal_parameter);
            }

            byte[] cookie = TlsUtilities.ReadOpaque8(buf);

            // TODO RFC 4347 has the cookie length restricted to 32, but not in RFC 6347

            TlsProtocol.AssertEmpty(buf);

            return cookie;
        }

        protected static byte[] PatchClientHelloWithCookie(byte[] clientHelloBody, byte[] cookie)
        {
            int sessionIDPos = 34;
            int sessionIDLength = TlsUtilities.ReadUint8(clientHelloBody, sessionIDPos);

            int cookieLengthPos = sessionIDPos + 1 + sessionIDLength;
            int cookiePos = cookieLengthPos + 1;

            byte[] patched = new byte[clientHelloBody.Length + cookie.Length];
            Array.Copy(clientHelloBody, 0, patched, 0, cookieLengthPos);
            TlsUtilities.CheckUint8(cookie.Length);
            TlsUtilities.WriteUint8(cookie.Length, patched, cookieLengthPos);
            Array.Copy(cookie, 0, patched, cookiePos, cookie.Length);
            Array.Copy(clientHelloBody, cookiePos, patched, cookiePos + cookie.Length, clientHelloBody.Length
                - cookiePos);

            return patched;
        }

        protected internal class ClientHandshakeState
        {
            public TlsClient client = null;
            public TlsClientContextImpl clientContext = null;
            public TlsSession tlsSession = null;
            public SessionParameters sessionParameters = null;
            public SessionParameters.Builder sessionParametersBuilder = null;
            public CipherSuite[] offeredCipherSuites = null;
            public CompressionMethod[] offeredCompressionMethods = null;
            public IDictionary clientExtensions = null;
            public byte[] selectedSessionID = null;
            public CipherSuite selectedCipherSuite = CipherSuite.UNASSINGED;
            public CompressionMethod selectedCompressionMethod = CompressionMethod.NULL;
            public bool secure_renegotiation = false;
            public short maxFragmentLength = -1;
            public bool allowCertificateStatus = false;
            public bool expectSessionTicket = false;
            public TlsKeyExchange keyExchange = null;
            public TlsAuthentication authentication = null;
            public CertificateStatus certificateStatus = null;
            public CertificateRequest certificateRequest = null;
            public TlsCredentials clientCredentials = null;
        }
    }
}