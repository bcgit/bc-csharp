using System.IO;
using Org.BouncyCastle.Utilities;
using Org.BouncyCastle.Crypto.Tls;
using System;
using Org.BouncyCastle.Security;
using System.Collections;
using System.Collections.Generic;

namespace Org.BouncyCastle.Crypto.Tls
{

    /**
     * An implementation of all high level protocols in TLS 1.0/1.1.
     */
    public abstract class TlsProtocol
    {
        protected internal static readonly ExtensionType EXT_RenegotiationInfo = ExtensionType.renegotiation_info;
        protected internal static readonly ExtensionType EXT_SessionTicket = ExtensionType.session_ticket;

        private const string TLS_ERROR_MESSAGE = "Internal TLS error, this could be an attack";

        /*
         * Our Connection states
         */
        protected const short CS_START = 0;
        protected const short CS_CLIENT_HELLO = 1;
        protected const short CS_SERVER_HELLO = 2;
        protected const short CS_SERVER_SUPPLEMENTAL_DATA = 3;
        protected const short CS_SERVER_CERTIFICATE = 4;
        protected const short CS_CERTIFICATE_STATUS = 5;
        protected const short CS_SERVER_KEY_EXCHANGE = 6;
        protected const short CS_CERTIFICATE_REQUEST = 7;
        protected const short CS_SERVER_HELLO_DONE = 8;
        protected const short CS_CLIENT_SUPPLEMENTAL_DATA = 9;
        protected const short CS_CLIENT_CERTIFICATE = 10;
        protected const short CS_CLIENT_KEY_EXCHANGE = 11;
        protected const short CS_CERTIFICATE_VERIFY = 12;
        protected const short CS_CLIENT_FINISHED = 13;
        protected const short CS_SERVER_SESSION_TICKET = 14;
        protected const short CS_SERVER_FINISHED = 15;
        protected const short CS_END = 16;

        /*
         * Queues for data from some protocols.
         */
        private ByteQueue applicationDataQueue = new ByteQueue();
        private ByteQueue alertQueue = new ByteQueue(2);
        private ByteQueue handshakeQueue = new ByteQueue();

        /*
         * The Record Stream we use
         */
        internal RecordStream recordStream;
        protected SecureRandom secureRandom;

        private TlsStream tlsStream = null;

        private volatile bool closed = false;
        private volatile bool failedWithError = false;
        private volatile bool appDataReady = false;
        private volatile bool writeExtraEmptyRecords = true;
        private byte[] expected_verify_data = null;

        protected TlsSession tlsSession = null;
        protected SessionParameters sessionParameters = null;
        protected SecurityParameters securityParameters = null;
        protected Certificate peerCertificate = null;

        protected CipherSuite[] offeredCipherSuites = null;
        protected CompressionMethod[] offeredCompressionMethods = null;
        protected IDictionary clientExtensions = null;
        protected IDictionary serverExtensions = null;

        protected short connection_state = CS_START;
        protected bool resumedSession = false;
        protected bool receivedChangeCipherSpec = false;
        protected bool secure_renegotiation = false;
        protected bool allowCertificateStatus = false;
        protected bool expectSessionTicket = false;

        public TlsProtocol(Stream input, Stream output, SecureRandom secureRandom)
        {
            this.recordStream = new RecordStream(this, input, output);
            this.secureRandom = secureRandom;
        }

        protected abstract AbstractTlsContext Context { get; }

        protected abstract TlsPeer Peer
        {
            get;
        }

        protected virtual void HandleChangeCipherSpecMessage()
        {
        }

        protected abstract void HandleHandshakeMessage(HandshakeType type, byte[] buf);

        protected virtual void HandleWarningMessage(AlertDescription description)
        {

        }

        protected virtual void CleanupHandshake()
        {
            if (this.expected_verify_data != null)
            {
                Arrays.Fill(this.expected_verify_data, (byte)0);
                this.expected_verify_data = null;
            }

            this.securityParameters.Clear();
            this.peerCertificate = null;

            this.offeredCipherSuites = null;
            this.offeredCompressionMethods = null;
            this.clientExtensions = null;
            this.serverExtensions = null;

            this.resumedSession = false;
            this.receivedChangeCipherSpec = false;
            this.secure_renegotiation = false;
            this.allowCertificateStatus = false;
            this.expectSessionTicket = false;
        }

        protected void CompleteHandshake()
        {
            try
            {
                /*
                 * We will now read data, until we have completed the handshake.
                 */
                while (this.connection_state != CS_END)
                {
                    if (this.closed)
                    {
                        // TODO What kind of exception/alert?
                    }

                    SafeReadRecord();
                }

                this.recordStream.FinaliseHandshake();

                this.writeExtraEmptyRecords = !TlsUtilities.IsTLSv11(Context);

                /*
                 * If this was an initial handshake, we are now ready to send and receive application data.
                 */
                if (!appDataReady)
                {
                    this.appDataReady = true;

                    this.tlsStream = new TlsStream(this);
                }

                if (this.tlsSession != null)
                {
                    if (this.sessionParameters == null)
                    {
                        this.sessionParameters = new SessionParameters.Builder()
                            .SetCipherSuite(this.securityParameters.cipherSuite)
                            .SetCompressionAlgorithm(this.securityParameters.compressionAlgorithm)
                            .SetMasterSecret(this.securityParameters.masterSecret)
                            .SetPeerCertificate(this.peerCertificate)
                            // TODO Consider filtering extensions that aren't relevant to resumed sessions
                            .SetServerExtensions(this.serverExtensions)
                            .Build();

                        this.tlsSession = new TlsSessionImpl(this.tlsSession.GetSessionID(), this.sessionParameters);
                    }

                    Context.ResumableSession = this.tlsSession;
                }

                Peer.NotifyHandshakeComplete();
            }
            finally
            {
                CleanupHandshake();
            }
        }

        protected internal void ProcessRecord(ContentType protocol, byte[] buf, int offset, int len)
        {
            /*
             * Have a look at the protocol type, and add it to the correct queue.
             */
            switch (protocol)
            {
                case ContentType.alert:
                    {
                        alertQueue.AddData(buf, offset, len);
                        processAlert();
                        break;
                    }
                case ContentType.application_data:
                    {
                        if (!appDataReady)
                        {
                            throw new TlsFatalAlert(AlertDescription.unexpected_message);
                        }
                        applicationDataQueue.AddData(buf, offset, len);
                        ProcessApplicationData();
                        break;
                    }
                case ContentType.change_cipher_spec:
                    {
                        ProcessChangeCipherSpec(buf, offset, len);
                        break;
                    }
                case ContentType.handshake:
                    {
                        handshakeQueue.AddData(buf, offset, len);
                        ProcessHandshake();
                        break;
                    }
                case ContentType.heartbeat:
                    {
                        // TODO[RFC 6520]
                        break;
                    }
                default:
                    /*
                     * Uh, we don't know this protocol.
                     * 
                     * RFC2246 defines on page 13, that we should ignore this.
                     */
                    break;
            }
        }

        private void ProcessHandshake()
        {
            bool read;
            do
            {
                read = false;
                /*
                 * We need the first 4 bytes, they contain type and length of the message.
                 */
                if (handshakeQueue.Available >= 4)
                {
                    byte[] beginning = new byte[4];
                    handshakeQueue.Read(beginning, 0, 4, 0);
                    MemoryStream bis = new MemoryStream(beginning);
                    HandshakeType type = (HandshakeType) TlsUtilities.ReadUint8(bis);
                    int len = TlsUtilities.ReadUint24(bis);

                    /*
                     * Check if we have enough bytes in the buffer to read the full message.
                     */
                    if (handshakeQueue.Available >= (len + 4))
                    {
                        /*
                         * Read the message.
                         */
                        byte[] buf = handshakeQueue.RemoveData(len, 4);

                        /*
                         * RFC 2246 7.4.9. The value handshake_messages includes all handshake messages
                         * starting at client hello up to, but not including, this finished message.
                         * [..] Note: [Also,] Hello Request messages are omitted from handshake hashes.
                         */
                        switch (type)
                        {
                            case HandshakeType.hello_request:
                                break;
                            case HandshakeType.finished:
                                {
                                    if (this.expected_verify_data == null)
                                    {
                                        this.expected_verify_data = CreateVerifyData(!Context.IsServer);
                                    }

                                    // NB: Fall through to next case label
                                    goto default;
                                }
                            default:
                                recordStream.UpdateHandshakeData(beginning, 0, 4);
                                recordStream.UpdateHandshakeData(buf, 0, len);
                                break;
                        }

                        /*
                         * Now, parse the message.
                         */
                        HandleHandshakeMessage(type, buf);
                        read = true;
                    }
                }
            }
            while (read);
        }

        private void ProcessApplicationData()
        {
            /*
             * There is nothing we need to do here.
             * 
             * This function could be used for callbacks when application data arrives in the future.
             */
        }

        private void processAlert()
        {
            while (alertQueue.Available >= 2)
            {
                /*
                 * An alert is always 2 bytes. Read the alert.
                 */
                byte[] tmp = alertQueue.RemoveData(2, 0);
                AlertLevel level = (AlertLevel)tmp[0];
                AlertDescription description = (AlertDescription)tmp[1];

                Peer.NotifyAlertReceived(level, description);

                if (level == AlertLevel.fatal)
                {
                    /*
                     * RFC 2246 7.2.1. The session becomes unresumable if any connection is terminated
                     * without proper close_notify messages with level equal to warning.
                     */
                    InvalidateSession();

                    this.failedWithError = true;
                    this.closed = true;

                    recordStream.SafeClose();

                    throw new IOException(TLS_ERROR_MESSAGE);
                }
                else
                {

                    /*
                     * RFC 5246 7.2.1. The other party MUST respond with a close_notify alert of its own
                     * and close down the connection immediately, discarding any pending writes.
                     */
                    // TODO Can close_notify be a fatal alert?
                    if (description == AlertDescription.close_notify)
                    {
                        HandleClose(false);
                    }

                    /*
                     * If it is just a warning, we continue.
                     */
                    HandleWarningMessage(description);
                }
            }
        }

        /**
         * This method is called, when a change cipher spec message is received.
         *
         * @throws IOException If the message has an invalid content or the handshake is not in the correct
         * state.
         */
        private void ProcessChangeCipherSpec(byte[] buf, int off, int len)
        {
            for (int i = 0; i < len; ++i)
            {
                short message = TlsUtilities.ReadUint8(buf, off + i);

                if (message != ChangeCipherSpec.change_cipher_spec)
                {
                    throw new TlsFatalAlert(AlertDescription.decode_error);
                }

                if (this.receivedChangeCipherSpec)
                {
                    throw new TlsFatalAlert(AlertDescription.unexpected_message);
                }

                this.receivedChangeCipherSpec = true;

                recordStream.ReceivedReadCipherSpec();

                HandleChangeCipherSpecMessage();
            }
        }

        /**
         * Read data from the network. The method will return immediately, if there is still some data
         * left in the buffer, or block until some application data has been read from the network.
         *
         * @param buf    The buffer where the data will be copied to.
         * @param offset The position where the data will be placed in the buffer.
         * @param len    The maximum number of bytes to read.
         * @return The number of bytes read.
         * @throws IOException If something goes wrong during reading data.
         */
        protected internal int ReadApplicationData(byte[] buf, int offset, int len)
        {
            if (len < 1)
            {
                return 0;
            }

            while (applicationDataQueue.Available == 0)
            {
                /*
                 * We need to read some data.
                 */
                if (this.closed)
                {
                    if (this.failedWithError)
                    {
                        /*
                         * Something went terribly wrong, we should throw an IOException
                         */
                        throw new IOException(TLS_ERROR_MESSAGE);
                    }

                    /*
                     * Connection has been closed, there is no more data to read.
                     */
                    return -1;
                }

                SafeReadRecord();
            }

            len = System.Math.Min(len, applicationDataQueue.Available);
            applicationDataQueue.RemoveData(buf, offset, len, 0);
            return len;
        }

        protected void SafeReadRecord()
        {
            try
            {
                if (!recordStream.ReadRecord())
                {
                    // TODO It would be nicer to allow graceful connection close if between records
                    //                this.failWithError(AlertLevel.warning, AlertDescription.close_notify);
                    throw new EndOfStreamException();
                }
            }
            catch (TlsFatalAlert e)
            {
                if (!this.closed)
                {
                    this.FailWithError(AlertLevel.fatal, e.AlertDescription);
                }
                throw e;
            }
            catch (IOException e)
            {
                if (!this.closed)
                {
                    this.FailWithError(AlertLevel.fatal, AlertDescription.internal_error);
                }
                throw e;
            }
            catch (Exception e)
            {
                if (!this.closed)
                {
                    this.FailWithError(AlertLevel.fatal, AlertDescription.internal_error);
                }
                throw e;
            }
        }

        protected void SafeWriteRecord(ContentType type, byte[] buf, int offset, int len)
        {
            try
            {
                recordStream.WriteRecord(type, buf, offset, len);
            }
            catch (TlsFatalAlert e)
            {
                if (!this.closed)
                {
                    this.FailWithError(AlertLevel.fatal, e.AlertDescription);
                }
                throw e;
            }
            catch (IOException e)
            {
                if (!closed)
                {
                    this.FailWithError(AlertLevel.fatal, AlertDescription.internal_error);
                }
                throw e;
            }
            catch (Exception e)
            {
                if (!closed)
                {
                    this.FailWithError(AlertLevel.fatal, AlertDescription.internal_error);
                }
                throw e;
            }
        }

        /**
         * Send some application data to the remote system.
         * <p/>
         * The method will handle fragmentation internally.
         *
         * @param buf    The buffer with the data.
         * @param offset The position in the buffer where the data is placed.
         * @param len    The length of the data.
         * @throws IOException If something goes wrong during sending.
         */
        protected internal void WriteData(byte[] buf, int offset, int len)
        {
            if (this.closed)
            {
                if (this.failedWithError)
                {
                    throw new IOException(TLS_ERROR_MESSAGE);
                }

                throw new IOException("Sorry, connection has been closed, you cannot write more data");
            }

            while (len > 0)
            {
                /*
                 * RFC 5246 6.2.1. Zero-length fragments of Application data MAY be sent as they are
                 * potentially useful as a traffic analysis countermeasure.
                 */
                if (this.writeExtraEmptyRecords)
                {
                    /*
                     * Protect against known IV attack!
                     * 
                     * DO NOT REMOVE THIS LINE, EXCEPT YOU KNOW EXACTLY WHAT YOU ARE DOING HERE.
                     */
                    SafeWriteRecord(ContentType.application_data, TlsUtilities.EMPTY_BYTES, 0, 0);
                }

                // Fragment data according to the current fragment limit.
                int toWrite = System.Math.Min(len, recordStream.PlaintextLimit);
                SafeWriteRecord(ContentType.application_data, buf, offset, toWrite);
                offset += toWrite;
                len -= toWrite;
            }
        }

        protected void WriteHandshakeMessage(byte[] buf, int off, int len)
        {
            while (len > 0)
            {
                // Fragment data according to the current fragment limit.
                int toWrite = System.Math.Min(len, recordStream.PlaintextLimit);
                SafeWriteRecord(ContentType.handshake, buf, off, toWrite);
                off += toWrite;
                len -= toWrite;
            }
        }

        /**
         * @return An OutputStream which can be used to send data.
         */
        public Stream Stream
        {
            get
            {
                return this.tlsStream;
            }
        }

        public bool IsClosed
        {
            get { return IsClosed; }
        }

        /**
         * Terminate this connection with an alert. Can be used for normal closure too.
         * 
         * @param alertLevel
         *            See {@link AlertLevel} for values.
         * @param alertDescription
         *            See {@link AlertDescription} for values.
         * @throws IOException
         *             If alert was fatal.
         */
        protected void FailWithError(AlertLevel alertLevel, AlertDescription alertDescription)
        {
            /*
             * Check if the connection is still open.
             */
            if (!closed)
            {
                /*
                 * Prepare the message
                 */
                this.closed = true;

                if (alertLevel == AlertLevel.fatal)
                {
                    /*
                     * RFC 2246 7.2.1. The session becomes unresumable if any connection is terminated
                     * without proper close_notify messages with level equal to warning.
                     */
                    // TODO This isn't quite in the right place. Also, as of TLS 1.1 the above is obsolete.
                    InvalidateSession();

                    this.failedWithError = true;
                }
                RaiseAlert(alertLevel, alertDescription, null, null);
                recordStream.SafeClose();
                if (alertLevel != AlertLevel.fatal)
                {
                    return;
                }
            }

            throw new IOException(TLS_ERROR_MESSAGE);
        }

        protected void InvalidateSession()
        {
            if (this.sessionParameters != null)
            {
                this.sessionParameters.Clear();
                this.sessionParameters = null;
            }

            if (this.tlsSession != null)
            {
                this.tlsSession.Invalidate();
                this.tlsSession = null;
            }
        }

        protected void ProcessFinishedMessage(MemoryStream buf)
        {
            byte[] verify_data = TlsUtilities.ReadFully(expected_verify_data.Length, buf);

            AssertEmpty(buf);

            /*
             * Compare both checksums.
             */
            if (!Arrays.ConstantTimeAreEqual(expected_verify_data, verify_data))
            {
                /*
                 * Wrong checksum in the finished message.
                 */
                throw new TlsFatalAlert(AlertDescription.decrypt_error);
            }
        }

        protected void RaiseAlert(AlertLevel alertLevel, AlertDescription alertDescription, String message, Exception cause)
        {
            Peer.NotifyAlertRaised(alertLevel, alertDescription, message, cause);

            byte[] error = new byte[2];
            error[0] = (byte)alertLevel;
            error[1] = (byte)alertDescription;

            SafeWriteRecord(ContentType.alert, error, 0, 2);
        }

        protected void RaiseWarning(AlertDescription alertDescription, String message)
        {
            RaiseAlert(AlertLevel.warning, alertDescription, message, null);
        }

        protected void SendCertificateMessage(Certificate certificate)
        {
            if (certificate == null)
            {
                certificate = Certificate.EmptyChain;
            }

            if (certificate.Length == 0)
            {
                TlsContext context = this.Context;
                if (!context.IsServer)
                {
                    ProtocolVersion serverVersion = Context.ServerVersion;
                    if (serverVersion.IsSSL)
                    {
                        string message = serverVersion.ToString() + " client didn't provide credentials";
                        RaiseWarning(AlertDescription.no_certificate, message);
                        return;
                    }
                }
            }

            HandshakeMessage handshakeMessage = new HandshakeMessage(this, HandshakeType.certificate);

            certificate.Encode(handshakeMessage);

            handshakeMessage.WriteToRecordStream();
        }

        protected void SendChangeCipherSpecMessage()
        {
            byte[] message = new byte[] { 1 };
            SafeWriteRecord(ContentType.change_cipher_spec, message, 0, message.Length);
            recordStream.SentWriteCipherSpec();
        }

        protected void SendFinishedMessage()
        {
            byte[] verify_data = CreateVerifyData(Context.IsServer);

            HandshakeMessage message = new HandshakeMessage(this, HandshakeType.finished, verify_data.Length);

            message.Write(verify_data, 0, verify_data.Length);

            message.WriteToRecordStream();
        }

        protected void SendSupplementalDataMessage(IEnumerable supplementalData)
        {
            HandshakeMessage message = new HandshakeMessage(this, HandshakeType.supplemental_data);

            WriteSupplementalData(message, supplementalData);

            message.WriteToRecordStream();
        }

        protected byte[] CreateVerifyData(bool isServer)
        {
            TlsContext context = Context;

            if (isServer)
            {
                return TlsUtilities.CalculateVerifyData(context, "server finished",
                    recordStream.GetCurrentHash(TlsUtilities.SSL_SERVER));
            }

            return TlsUtilities.CalculateVerifyData(context, "client finished",
                recordStream.GetCurrentHash(TlsUtilities.SSL_CLIENT));
        }

        /**
         * Closes this connection.
         *
         * @throws IOException If something goes wrong during closing.
         */
        public virtual void Close()
        {
            HandleClose(true);
        }

        protected void HandleClose(bool user_canceled)
        {
            if (!closed)
            {
                if (user_canceled && !appDataReady)
                {
                    RaiseWarning(AlertDescription.user_canceled, "User canceled handshake");
                }
                this.FailWithError(AlertLevel.warning, AlertDescription.close_notify);
            }
        }

        protected internal void Flush()
        {
            recordStream.Flush();
        }

        protected short ProcessMaxFragmentLengthExtension(IDictionary clientExtensions, IDictionary serverExtensions, AlertDescription alertDescription)
        {
            short maxFragmentLength = TlsExtensionsUtils.GetMaxFragmentLengthExtension(serverExtensions);
            if (maxFragmentLength >= 0 && !this.resumedSession)
            {
                if (maxFragmentLength != TlsExtensionsUtils.GetMaxFragmentLengthExtension(clientExtensions))
                {
                    throw new TlsFatalAlert(alertDescription);
                }
            }
            return maxFragmentLength;
        }

        //protected internal static bool ArrayContains(short[] a, short n)
        //{
        //    for (int i = 0; i < a.Length; ++i)
        //    {
        //        if (a[i] == n)
        //        {
        //            return true;
        //        }
        //    }
        //    return false;
        //}

        protected internal static bool ArrayContains(ECPointFormat[] a, ECPointFormat n)
        {
            for (int i = 0; i < a.Length; ++i)
            {
                if (a[i] == n)
                {
                    return true;
                }
            }
            return false;
        }

        protected internal static bool ArrayContains(CipherSuite[] a, CipherSuite n)
        {
            for (int i = 0; i < a.Length; ++i)
            {
                if (a[i] == n)
                {
                    return true;
                }
            }
            return false;
        }

        protected internal static bool ArrayContains<T>(T[] a, T n) 
        {
            for (int i = 0; i < a.Length; ++i)
            {
                if (a[i].Equals(n))
                {
                    return true;
                }
            }
            return false;
        }

        protected internal static bool ArrayContains(NamedCurve[] a, short n)
        {
            for (int i = 0; i < a.Length; ++i)
            {
                if ((short)a[i] == n)
                {
                    return true;
                }
            }
            return false;
        }

        protected internal static bool ArrayContains(NamedCurve[] a, NamedCurve n)
        {
            for (int i = 0; i < a.Length; ++i)
            {
                if (a[i] == n)
                {
                    return true;
                }
            }
            return false;
        }


        //protected static bool ArrayContains(int[] a, int n)
        //{
        //    for (int i = 0; i < a.Length; ++i)
        //    {
        //        if (a[i] == n)
        //        {
        //            return true;
        //        }
        //    }
        //    return false;
        //}

        /**
         * Make sure the InputStream 'buf' now empty. Fail otherwise.
         *
         * @param buf The InputStream to check.
         * @throws IOException If 'buf' is not empty.
         */
        protected internal static void AssertEmpty(MemoryStream buf)
        {
            if (buf.Length - buf.Position > 0)
            {
                throw new TlsFatalAlert(AlertDescription.decode_error);
            }
        }

        protected internal static byte[] CreateRandomBlock(SecureRandom random)
        {
            byte[] result = new byte[32];
            random.NextBytes(result);
            TlsUtilities.WriteGMTUnixTime(result, 0);
            return result;
        }

        protected internal static byte[] CreateRenegotiationInfo(byte[] renegotiated_connection)
        {
            MemoryStream buf = new MemoryStream();
            TlsUtilities.WriteOpaque8(renegotiated_connection, buf);
            return buf.ToArray();
        }

        protected internal static void EstablishMasterSecret(TlsContext context, TlsKeyExchange keyExchange)
        {
            byte[] pre_master_secret = keyExchange.GeneratePremasterSecret();

            try
            {
                context.SecurityParameters.masterSecret  = TlsUtilities.CalculateMasterSecret(context, pre_master_secret);
            }
            finally
            {
                // TODO Is there a way to ensure the data is really overwritten?
                /*
                 * RFC 2246 8.1. The pre_master_secret should be deleted from memory once the
                 * master_secret has been computed.
                 */
                if (pre_master_secret != null)
                {
                    Arrays.Fill(pre_master_secret, (byte)0);
                }
            }
        }

        protected internal static IDictionary ReadExtensions(MemoryStream input)
        {
            if (input.Length - input.Position  < 1)
            {
                return null;
            }

            byte[] extBytes = TlsUtilities.ReadOpaque16(input);

            AssertEmpty(input);

            MemoryStream buf = new MemoryStream(extBytes);

            // Integer -> byte[]
            IDictionary extensions = Platform.CreateHashtable();

            while (buf.Length - buf.Position > 0)
            {
                ExtensionType  extension_type = (ExtensionType )TlsUtilities.ReadUint16(buf);
                byte[] extension_data = TlsUtilities.ReadOpaque16(buf);

                /*
                 * RFC 3546 2.3 There MUST NOT be more than one extension of the same type.
                 */
                if (extensions.Contains(extension_type))
                {
                    extensions[extension_type] = extension_data;
                    throw new TlsFatalAlert(AlertDescription.illegal_parameter);
                }

                extensions[extension_type] = extension_data;
            }

            return extensions;
        }

        protected internal static IList ReadSupplementalDataMessage(MemoryStream input)
        {
            byte[] supp_data = TlsUtilities.ReadOpaque24(input);

            AssertEmpty(input);

            MemoryStream buf = new MemoryStream(supp_data);

            var supplementalData = Platform.CreateArrayList();

            while (buf.Length - buf.Position > 0)
            {
                int supp_data_type = TlsUtilities.ReadUint16(buf);
                byte[] data = TlsUtilities.ReadOpaque16(buf);

                supplementalData.Add(new SupplementalDataEntry(supp_data_type, data));
            }

            return supplementalData;
        }

        protected internal static void WriteExtensions(Stream output, IDictionary extensions)
        {
            MemoryStream buf = new MemoryStream();

            var keys = extensions.Keys;
            foreach (var key in keys)
            {
                int extension_type = (int)key;
                byte[] extension_data = (byte[])extensions[key];

                TlsUtilities.CheckUint16(extension_type);
                TlsUtilities.WriteUint16(extension_type, buf);
                TlsUtilities.WriteOpaque16(extension_data, buf);
            }

            byte[] extBytes = buf.ToArray();

            TlsUtilities.WriteOpaque16(extBytes, output);
        }

        protected internal static void WriteSupplementalData(Stream output, IEnumerable supplementalData)
        {
            MemoryStream buf = new MemoryStream();

            foreach (var obj in supplementalData)
            {
                SupplementalDataEntry entry = (SupplementalDataEntry)obj;

                int supp_data_type = entry.getDataType();
                TlsUtilities.CheckUint16(supp_data_type);
                TlsUtilities.WriteUint16(supp_data_type, buf);
                TlsUtilities.WriteOpaque16(entry.getData(), buf);
            }

            byte[] supp_data = buf.ToArray();

            TlsUtilities.WriteOpaque24(supp_data, output);
        }

        protected internal static int GetPRFAlgorithm(TlsContext context, CipherSuite ciphersuite)
        {
            bool isTLSv12 = TlsUtilities.IsTLSv12(context);

            switch (ciphersuite)
            {
                case CipherSuite.TLS_DH_DSS_WITH_AES_128_CBC_SHA256:
                case CipherSuite.TLS_DH_DSS_WITH_AES_128_GCM_SHA256:
                case CipherSuite.TLS_DH_DSS_WITH_AES_256_CBC_SHA256:
                case CipherSuite.TLS_DH_RSA_WITH_AES_128_CBC_SHA256:
                case CipherSuite.TLS_DH_RSA_WITH_AES_128_GCM_SHA256:
                case CipherSuite.TLS_DH_RSA_WITH_AES_256_CBC_SHA256:
                case CipherSuite.TLS_DHE_DSS_WITH_AES_128_CBC_SHA256:
                case CipherSuite.TLS_DHE_DSS_WITH_AES_128_GCM_SHA256:
                case CipherSuite.TLS_DHE_DSS_WITH_AES_256_CBC_SHA256:
                case CipherSuite.TLS_DHE_PSK_WITH_AES_128_CCM:
                case CipherSuite.TLS_DHE_PSK_WITH_AES_128_GCM_SHA256:
                case CipherSuite.TLS_DHE_PSK_WITH_AES_256_CCM:
                case CipherSuite.TLS_DHE_RSA_WITH_AES_128_CBC_SHA256:
                case CipherSuite.TLS_DHE_RSA_WITH_AES_128_CCM:
                case CipherSuite.TLS_DHE_RSA_WITH_AES_128_CCM_8:
                case CipherSuite.TLS_DHE_RSA_WITH_AES_128_GCM_SHA256:
                case CipherSuite.TLS_DHE_RSA_WITH_AES_256_CBC_SHA256:
                case CipherSuite.TLS_DHE_RSA_WITH_AES_256_CCM:
                case CipherSuite.TLS_DHE_RSA_WITH_AES_256_CCM_8:
                case CipherSuite.TLS_ECDH_ECDSA_WITH_AES_128_CBC_SHA256:
                case CipherSuite.TLS_ECDH_ECDSA_WITH_AES_128_GCM_SHA256:
                case CipherSuite.TLS_ECDH_RSA_WITH_AES_128_CBC_SHA256:
                case CipherSuite.TLS_ECDH_RSA_WITH_AES_128_GCM_SHA256:
                case CipherSuite.TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA256:
                case CipherSuite.TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256:
                case CipherSuite.TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA256:
                case CipherSuite.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256:
                case CipherSuite.TLS_PSK_DHE_WITH_AES_128_CCM_8:
                case CipherSuite.TLS_PSK_DHE_WITH_AES_256_CCM_8:
                case CipherSuite.TLS_PSK_WITH_AES_128_CCM:
                case CipherSuite.TLS_PSK_WITH_AES_128_CCM_8:
                case CipherSuite.TLS_PSK_WITH_AES_128_GCM_SHA256:
                case CipherSuite.TLS_PSK_WITH_AES_256_CCM:
                case CipherSuite.TLS_PSK_WITH_AES_256_CCM_8:
                case CipherSuite.TLS_RSA_PSK_WITH_AES_128_GCM_SHA256:
                case CipherSuite.TLS_RSA_WITH_AES_128_CBC_SHA256:
                case CipherSuite.TLS_RSA_WITH_AES_128_CCM:
                case CipherSuite.TLS_RSA_WITH_AES_128_CCM_8:
                case CipherSuite.TLS_RSA_WITH_AES_128_GCM_SHA256:
                case CipherSuite.TLS_RSA_WITH_AES_256_CBC_SHA256:
                case CipherSuite.TLS_RSA_WITH_AES_256_CCM:
                case CipherSuite.TLS_RSA_WITH_AES_256_CCM_8:
                case CipherSuite.TLS_RSA_WITH_NULL_SHA256:
                    {
                        if (isTLSv12)
                        {
                            return PRFAlgorithm.tls_prf_sha256;
                        }
                        throw new TlsFatalAlert(AlertDescription.illegal_parameter);
                    }

                case CipherSuite.TLS_DH_DSS_WITH_AES_256_GCM_SHA384:
                case CipherSuite.TLS_DH_RSA_WITH_AES_256_GCM_SHA384:
                case CipherSuite.TLS_DHE_DSS_WITH_AES_256_GCM_SHA384:
                case CipherSuite.TLS_DHE_PSK_WITH_AES_256_GCM_SHA384:
                case CipherSuite.TLS_DHE_RSA_WITH_AES_256_GCM_SHA384:
                case CipherSuite.TLS_ECDH_ECDSA_WITH_AES_256_CBC_SHA384:
                case CipherSuite.TLS_ECDH_ECDSA_WITH_AES_256_GCM_SHA384:
                case CipherSuite.TLS_ECDH_RSA_WITH_AES_256_CBC_SHA384:
                case CipherSuite.TLS_ECDH_RSA_WITH_AES_256_GCM_SHA384:
                case CipherSuite.TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA384:
                case CipherSuite.TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384:
                case CipherSuite.TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA384:
                case CipherSuite.TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384:
                case CipherSuite.TLS_PSK_WITH_AES_256_GCM_SHA384:
                case CipherSuite.TLS_RSA_PSK_WITH_AES_256_GCM_SHA384:
                case CipherSuite.TLS_RSA_WITH_AES_256_GCM_SHA384:
                    {
                        if (isTLSv12)
                        {
                            return PRFAlgorithm.tls_prf_sha384;
                        }
                        throw new TlsFatalAlert(AlertDescription.illegal_parameter);
                    }

                case CipherSuite.TLS_DHE_PSK_WITH_AES_256_CBC_SHA384:
                case CipherSuite.TLS_DHE_PSK_WITH_NULL_SHA384:
                case CipherSuite.TLS_ECDHE_PSK_WITH_AES_256_CBC_SHA384:
                case CipherSuite.TLS_ECDHE_PSK_WITH_NULL_SHA384:
                case CipherSuite.TLS_PSK_WITH_AES_256_CBC_SHA384:
                case CipherSuite.TLS_PSK_WITH_NULL_SHA384:
                case CipherSuite.TLS_RSA_PSK_WITH_AES_256_CBC_SHA384:
                case CipherSuite.TLS_RSA_PSK_WITH_NULL_SHA384:
                    {
                        if (isTLSv12)
                        {
                            return PRFAlgorithm.tls_prf_sha384;
                        }
                        return PRFAlgorithm.tls_prf_legacy;
                    }

                default:
                    {
                        if (isTLSv12)
                        {
                            return PRFAlgorithm.tls_prf_sha256;
                        }
                        return PRFAlgorithm.tls_prf_legacy;
                    }
            }
        }

        protected class HandshakeMessage : MemoryStream
        {
            private readonly TlsProtocol outer;

            public HandshakeMessage(TlsProtocol outer, HandshakeType handshakeType)
                : this(outer, handshakeType, 60)
            {
                
            }

            public HandshakeMessage(TlsProtocol outer, HandshakeType handshakeType, int length)
                : base(length + 4)
            {
                this.outer = outer;

                TlsUtilities.WriteUint8((byte)handshakeType, this);
                // Reserve space for length
                Position += 3;
            }

            public void WriteToRecordStream()
            {
                // Patch actual length back in
                int length = (int)Position - 4;
                TlsUtilities.CheckUint24(length);
                var buffer = GetBuffer();
                TlsUtilities.WriteUint24(length, buffer, 1);
                outer.WriteHandshakeMessage(buffer, 0, (int)this.Length);
            }
        }
    }
}