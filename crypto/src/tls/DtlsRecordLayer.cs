using System;
using System.IO;
using System.Net.Sockets;

using Org.BouncyCastle.Tls.Crypto;
using Org.BouncyCastle.Utilities;
using Org.BouncyCastle.Utilities.Date;

namespace Org.BouncyCastle.Tls
{
    internal class DtlsRecordLayer
        : DatagramTransport
    {
        private const int RECORD_HEADER_LENGTH = 13;
        private const int MAX_FRAGMENT_LENGTH = 1 << 14;
        private const long TCP_MSL = 1000L * 60 * 2;
        private const long RETRANSMIT_TIMEOUT = TCP_MSL * 2;

        /// <exception cref="IOException"/>
        internal static byte[] ReceiveClientHelloRecord(byte[] data, int dataOff, int dataLen)
        {
            if (dataLen < RECORD_HEADER_LENGTH)
            {
                return null;
            }

            short contentType = TlsUtilities.ReadUint8(data, dataOff + 0);
            if (ContentType.handshake != contentType)
                return null;

            ProtocolVersion version = TlsUtilities.ReadVersion(data, dataOff + 1);
            if (!ProtocolVersion.DTLSv10.IsEqualOrEarlierVersionOf(version))
                return null;

            int epoch = TlsUtilities.ReadUint16(data, dataOff + 3);
            if (0 != epoch)
                return null;

            //long sequenceNumber = TlsUtilities.ReadUint48(data, dataOff + 5);

            int length = TlsUtilities.ReadUint16(data, dataOff + 11);
            if (dataLen < RECORD_HEADER_LENGTH + length)
                return null;

            if (length > MAX_FRAGMENT_LENGTH)
                return null;

            // NOTE: We ignore/drop any data after the first record
            return TlsUtilities.CopyOfRangeExact(data, dataOff + RECORD_HEADER_LENGTH,
                dataOff + RECORD_HEADER_LENGTH + length);
        }

        /// <exception cref="IOException"/>
        internal static void SendHelloVerifyRequestRecord(DatagramSender sender, long recordSeq, byte[] message)
        {
            TlsUtilities.CheckUint16(message.Length);

            byte[] record = new byte[RECORD_HEADER_LENGTH + message.Length];
            TlsUtilities.WriteUint8(ContentType.handshake, record, 0);
            TlsUtilities.WriteVersion(ProtocolVersion.DTLSv10, record, 1);
            TlsUtilities.WriteUint16(0, record, 3);
            TlsUtilities.WriteUint48(recordSeq, record, 5);
            TlsUtilities.WriteUint16(message.Length, record, 11);

            Array.Copy(message, 0, record, RECORD_HEADER_LENGTH, message.Length);

            SendDatagram(sender, record, 0, record.Length);
        }

        /// <exception cref="IOException"/>
        private static void SendDatagram(DatagramSender sender, byte[] buf, int off, int len)
        {
            // TODO[tls-port] Can we support interrupted IO on .NET?
            //try
            //{
            //    sender.Send(buf, off, len);
            //}
            //catch (InterruptedIOException e)
            //{
            //    e.bytesTransferred = 0;
            //    throw e;
            //}

            sender.Send(buf, off, len);
        }

        private readonly TlsContext m_context;
        private readonly TlsPeer m_peer;
        private readonly DatagramTransport m_transport;

        private readonly ByteQueue m_recordQueue = new ByteQueue();
        private readonly object m_writeLock = new object();

        private volatile bool m_closed = false;
        private volatile bool m_failed = false;
        // TODO[dtls13] Review the draft/RFC (legacy_record_version) to see if readVersion can be removed
        private volatile ProtocolVersion m_readVersion = null, m_writeVersion = null;
        private volatile bool m_inConnection;
        private volatile bool m_inHandshake;
        private volatile int m_plaintextLimit;
        private DtlsEpoch m_currentEpoch, m_pendingEpoch;
        private DtlsEpoch m_readEpoch, m_writeEpoch;

        private DtlsHandshakeRetransmit m_retransmit = null;
        private DtlsEpoch m_retransmitEpoch = null;
        private Timeout m_retransmitTimeout = null;

        private TlsHeartbeat m_heartbeat = null;                // If non-null, controls the sending of heartbeat requests
        private bool m_heartBeatResponder = false;              // Whether we should send heartbeat responses

        private HeartbeatMessage m_heartbeatInFlight = null;    // The current in-flight heartbeat request, if any
        private Timeout m_heartbeatTimeout = null;              // Idle timeout (if none in-flight), else expiry timeout for response

        private int m_heartbeatResendMillis = -1;               // Delay before retransmit of current in-flight heartbeat request
        private Timeout m_heartbeatResendTimeout = null;        // Timeout for next retransmit of the in-flight heartbeat request

        internal DtlsRecordLayer(TlsContext context, TlsPeer peer, DatagramTransport transport)
        {
            this.m_context = context;
            this.m_peer = peer;
            this.m_transport = transport;

            this.m_inHandshake = true;

            this.m_currentEpoch = new DtlsEpoch(0, TlsNullNullCipher.Instance);
            this.m_pendingEpoch = null;
            this.m_readEpoch = m_currentEpoch;
            this.m_writeEpoch = m_currentEpoch;

            SetPlaintextLimit(MAX_FRAGMENT_LENGTH);
        }

        internal virtual bool IsClosed
        {
            get { return m_closed; }
        }

        internal virtual void ResetAfterHelloVerifyRequestServer(long recordSeq)
        {
            this.m_inConnection = true;

            m_currentEpoch.SequenceNumber = recordSeq;
            m_currentEpoch.ReplayWindow.Reset(recordSeq);
        }

        internal virtual void SetPlaintextLimit(int plaintextLimit)
        {
            this.m_plaintextLimit = plaintextLimit;
        }

        internal virtual int ReadEpoch
        {
            get { return m_readEpoch.Epoch; }
        }

        internal virtual ProtocolVersion ReadVersion
        {
            get { return m_readVersion; }
            set { this.m_readVersion = value; }
        }

        internal virtual void SetWriteVersion(ProtocolVersion writeVersion)
        {
            this.m_writeVersion = writeVersion;
        }

        internal virtual void InitPendingEpoch(TlsCipher pendingCipher)
        {
            if (m_pendingEpoch != null)
                throw new InvalidOperationException();

            /*
             * TODO "In order to ensure that any given sequence/epoch pair is unique, implementations
             * MUST NOT allow the same epoch value to be reused within two times the TCP maximum segment
             * lifetime."
             */

            // TODO Check for overflow
            this.m_pendingEpoch = new DtlsEpoch(m_writeEpoch.Epoch + 1, pendingCipher);
        }

        internal virtual void HandshakeSuccessful(DtlsHandshakeRetransmit retransmit)
        {
            if (m_readEpoch == m_currentEpoch || m_writeEpoch == m_currentEpoch)
            {
                // TODO
                throw new InvalidOperationException();
            }

            if (null != retransmit)
            {
                this.m_retransmit = retransmit;
                this.m_retransmitEpoch = m_currentEpoch;
                this.m_retransmitTimeout = new Timeout(RETRANSMIT_TIMEOUT);
            }

            this.m_inHandshake = false;
            this.m_currentEpoch = m_pendingEpoch;
            this.m_pendingEpoch = null;
        }

        internal virtual void InitHeartbeat(TlsHeartbeat heartbeat, bool heartbeatResponder)
        {
            if (m_inHandshake)
                throw new InvalidOperationException();

            this.m_heartbeat = heartbeat;
            this.m_heartBeatResponder = heartbeatResponder;

            if (null != heartbeat)
            {
                ResetHeartbeat();
            }
        }

        internal virtual void ResetWriteEpoch()
        {
            if (null != m_retransmitEpoch)
            {
                this.m_writeEpoch = m_retransmitEpoch;
            }
            else
            {
                this.m_writeEpoch = m_currentEpoch;
            }
        }

        /// <exception cref="IOException"/>
        public virtual int GetReceiveLimit()
        {
            return System.Math.Min(m_plaintextLimit,
                m_readEpoch.Cipher.GetPlaintextDecodeLimit(m_transport.GetReceiveLimit() - RECORD_HEADER_LENGTH));
        }

        /// <exception cref="IOException"/>
        public virtual int GetSendLimit()
        {
            return System.Math.Min(m_plaintextLimit,
                m_writeEpoch.Cipher.GetPlaintextEncodeLimit(m_transport.GetSendLimit() - RECORD_HEADER_LENGTH));
        }

        /// <exception cref="IOException"/>
        public virtual int Receive(byte[] buf, int off, int len, int waitMillis)
        {
#if NETCOREAPP2_1_OR_GREATER || NETSTANDARD2_1_OR_GREATER
            return Receive(buf.AsSpan(off, len), waitMillis);
#else
            long currentTimeMillis = DateTimeUtilities.CurrentUnixMs();

            Timeout timeout = Timeout.ForWaitMillis(waitMillis, currentTimeMillis);
            byte[] record = null;

            while (waitMillis >= 0)
            {
                if (null != m_retransmitTimeout && m_retransmitTimeout.RemainingMillis(currentTimeMillis) < 1)
                {
                    m_retransmit = null;
                    m_retransmitEpoch = null;
                    m_retransmitTimeout = null;
                }

                if (Timeout.HasExpired(m_heartbeatTimeout, currentTimeMillis))
                {
                    if (null != m_heartbeatInFlight)
                        throw new TlsTimeoutException("Heartbeat timed out");

                    this.m_heartbeatInFlight = HeartbeatMessage.Create(m_context,
                        HeartbeatMessageType.heartbeat_request, m_heartbeat.GeneratePayload());
                    this.m_heartbeatTimeout = new Timeout(m_heartbeat.TimeoutMillis, currentTimeMillis);

                    this.m_heartbeatResendMillis = DtlsReliableHandshake.INITIAL_RESEND_MILLIS;
                    this.m_heartbeatResendTimeout = new Timeout(m_heartbeatResendMillis, currentTimeMillis);

                    SendHeartbeatMessage(m_heartbeatInFlight);
                }
                else if (Timeout.HasExpired(m_heartbeatResendTimeout, currentTimeMillis))
                {
                    this.m_heartbeatResendMillis = DtlsReliableHandshake.BackOff(m_heartbeatResendMillis);
                    this.m_heartbeatResendTimeout = new Timeout(m_heartbeatResendMillis, currentTimeMillis);

                    SendHeartbeatMessage(m_heartbeatInFlight);
                }

                waitMillis = Timeout.ConstrainWaitMillis(waitMillis, m_heartbeatTimeout, currentTimeMillis);
                waitMillis = Timeout.ConstrainWaitMillis(waitMillis, m_heartbeatResendTimeout, currentTimeMillis);

                // NOTE: Guard against bad logic giving a negative value
                if (waitMillis < 0)
                {
                    waitMillis = 1;
                }

                int receiveLimit = System.Math.Min(len, GetReceiveLimit()) + RECORD_HEADER_LENGTH;
                if (null == record || record.Length < receiveLimit)
                {
                    record = new byte[receiveLimit];
                }

                int received = ReceiveRecord(record, 0, receiveLimit, waitMillis);
                int processed = ProcessRecord(received, record, buf, off);
                if (processed >= 0)
                {
                    return processed;
                }

                currentTimeMillis = DateTimeUtilities.CurrentUnixMs();
                waitMillis = Timeout.GetWaitMillis(timeout, currentTimeMillis);
            }

            return -1;
#endif
        }

#if NETCOREAPP2_1_OR_GREATER || NETSTANDARD2_1_OR_GREATER
        /// <exception cref="IOException"/>
        public virtual int Receive(Span<byte> buffer, int waitMillis)
        {
            long currentTimeMillis = DateTimeUtilities.CurrentUnixMs();

            Timeout timeout = Timeout.ForWaitMillis(waitMillis, currentTimeMillis);
            byte[] record = null;

            while (waitMillis >= 0)
            {
                if (null != m_retransmitTimeout && m_retransmitTimeout.RemainingMillis(currentTimeMillis) < 1)
                {
                    m_retransmit = null;
                    m_retransmitEpoch = null;
                    m_retransmitTimeout = null;
                }

                if (Timeout.HasExpired(m_heartbeatTimeout, currentTimeMillis))
                {
                    if (null != m_heartbeatInFlight)
                        throw new TlsTimeoutException("Heartbeat timed out");

                    this.m_heartbeatInFlight = HeartbeatMessage.Create(m_context,
                        HeartbeatMessageType.heartbeat_request, m_heartbeat.GeneratePayload());
                    this.m_heartbeatTimeout = new Timeout(m_heartbeat.TimeoutMillis, currentTimeMillis);

                    this.m_heartbeatResendMillis = DtlsReliableHandshake.INITIAL_RESEND_MILLIS;
                    this.m_heartbeatResendTimeout = new Timeout(m_heartbeatResendMillis, currentTimeMillis);

                    SendHeartbeatMessage(m_heartbeatInFlight);
                }
                else if (Timeout.HasExpired(m_heartbeatResendTimeout, currentTimeMillis))
                {
                    this.m_heartbeatResendMillis = DtlsReliableHandshake.BackOff(m_heartbeatResendMillis);
                    this.m_heartbeatResendTimeout = new Timeout(m_heartbeatResendMillis, currentTimeMillis);

                    SendHeartbeatMessage(m_heartbeatInFlight);
                }

                waitMillis = Timeout.ConstrainWaitMillis(waitMillis, m_heartbeatTimeout, currentTimeMillis);
                waitMillis = Timeout.ConstrainWaitMillis(waitMillis, m_heartbeatResendTimeout, currentTimeMillis);

                // NOTE: Guard against bad logic giving a negative value
                if (waitMillis < 0)
                {
                    waitMillis = 1;
                }

                int receiveLimit = System.Math.Min(buffer.Length, GetReceiveLimit()) + RECORD_HEADER_LENGTH;
                if (null == record || record.Length < receiveLimit)
                {
                    record = new byte[receiveLimit];
                }

                int received = ReceiveRecord(record, 0, receiveLimit, waitMillis);
                int processed = ProcessRecord(received, record, buffer);
                if (processed >= 0)
                {
                    return processed;
                }

                currentTimeMillis = DateTimeUtilities.CurrentUnixMs();
                waitMillis = Timeout.GetWaitMillis(timeout, currentTimeMillis);
            }

            return -1;
        }
#endif

        /// <exception cref="IOException"/>
        public virtual void Send(byte[] buf, int off, int len)
        {
#if NETCOREAPP2_1_OR_GREATER || NETSTANDARD2_1_OR_GREATER
            Send(buf.AsSpan(off, len));
#else
            short contentType = ContentType.application_data;

            if (m_inHandshake || m_writeEpoch == m_retransmitEpoch)
            {
                contentType = ContentType.handshake;

                short handshakeType = TlsUtilities.ReadUint8(buf, off);
                if (handshakeType == HandshakeType.finished)
                {
                    DtlsEpoch nextEpoch = null;
                    if (m_inHandshake)
                    {
                        nextEpoch = m_pendingEpoch;
                    }
                    else if (m_writeEpoch == m_retransmitEpoch)
                    {
                        nextEpoch = m_currentEpoch;
                    }

                    if (nextEpoch == null)
                    {
                        // TODO
                        throw new InvalidOperationException();
                    }

                    // Implicitly send change_cipher_spec and change to pending cipher state

                    // TODO Send change_cipher_spec and finished records in single datagram?
                    byte[] data = new byte[1]{ 1 };
                    SendRecord(ContentType.change_cipher_spec, data, 0, data.Length);

                    this.m_writeEpoch = nextEpoch;
                }
            }

            SendRecord(contentType, buf, off, len);
#endif
        }

#if NETCOREAPP2_1_OR_GREATER || NETSTANDARD2_1_OR_GREATER
        /// <exception cref="IOException"/>
        public virtual void Send(ReadOnlySpan<byte> buffer)
        {
            short contentType = ContentType.application_data;

            if (m_inHandshake || m_writeEpoch == m_retransmitEpoch)
            {
                contentType = ContentType.handshake;

                short handshakeType = TlsUtilities.ReadUint8(buffer);
                if (handshakeType == HandshakeType.finished)
                {
                    DtlsEpoch nextEpoch = null;
                    if (m_inHandshake)
                    {
                        nextEpoch = m_pendingEpoch;
                    }
                    else if (m_writeEpoch == m_retransmitEpoch)
                    {
                        nextEpoch = m_currentEpoch;
                    }

                    if (nextEpoch == null)
                    {
                        // TODO
                        throw new InvalidOperationException();
                    }

                    // Implicitly send change_cipher_spec and change to pending cipher state

                    // TODO Send change_cipher_spec and finished records in single datagram?
                    ReadOnlySpan<byte> data = stackalloc byte[1]{ 1 };
                    SendRecord(ContentType.change_cipher_spec, data);

                    this.m_writeEpoch = nextEpoch;
                }
            }

            SendRecord(contentType, buffer);
        }
#endif

        /// <exception cref="IOException"/>
        public virtual void Close()
        {
            if (!m_closed)
            {
                if (m_inHandshake && m_inConnection)
                {
                    Warn(AlertDescription.user_canceled, "User canceled handshake");
                }
                CloseTransport();
            }
        }

        internal virtual void Fail(short alertDescription)
        {
            if (!m_closed)
            {
                if (m_inConnection)
                {
                    try
                    {
                        RaiseAlert(AlertLevel.fatal, alertDescription, null, null);
                    }
                    catch (Exception)
                    {
                        // Ignore
                    }
                }

                this.m_failed = true;

                CloseTransport();
            }
        }

        internal virtual void Failed()
        {
            if (!m_closed)
            {
                this.m_failed = true;

                CloseTransport();
            }
        }

        /// <exception cref="IOException"/>
        internal virtual void Warn(short alertDescription, string message)
        {
            RaiseAlert(AlertLevel.warning, alertDescription, message, null);
        }

        private void CloseTransport()
        {
            if (!m_closed)
            {
                /*
                 * RFC 5246 7.2.1. Unless some other fatal alert has been transmitted, each party is
                 * required to send a close_notify alert before closing the write side of the
                 * connection. The other party MUST respond with a close_notify alert of its own and
                 * close down the connection immediately, discarding any pending writes.
                 */

                try
                {
                    if (!m_failed)
                    {
                        Warn(AlertDescription.close_notify, null);
                    }
                    m_transport.Close();
                }
                catch (Exception)
                {
                    // Ignore
                }

                this.m_closed = true;
            }
        }

        /// <exception cref="IOException"/>
        private void RaiseAlert(short alertLevel, short alertDescription, string message, Exception cause)
        {
            m_peer.NotifyAlertRaised(alertLevel, alertDescription, message, cause);

#if NETCOREAPP2_1_OR_GREATER || NETSTANDARD2_1_OR_GREATER
            ReadOnlySpan<byte> error = stackalloc byte[2]{ (byte)alertLevel, (byte)alertDescription };
            SendRecord(ContentType.alert, error);
#else
            byte[] error = new byte[2]{ (byte)alertLevel, (byte)alertDescription };
            SendRecord(ContentType.alert, error, 0, 2);
#endif
        }

        /// <exception cref="IOException"/>
        private int ReceiveDatagram(byte[] buf, int off, int len, int waitMillis)
        {
            try
            {
                return m_transport.Receive(buf, off, len, waitMillis);
            }
            catch (TlsTimeoutException)
            {
                return -1;
            }
            catch (SocketException e)
            {
                if (TlsUtilities.IsTimeout(e))
                    return -1;

                throw e;
            }
            // TODO[tls-port] Can we support interrupted IO on .NET?
            //catch (InterruptedIOException e)
            //{
            //    e.bytesTransferred = 0;
            //    throw e;
            //}
        }

        // TODO Include 'currentTimeMillis' as an argument, use with Timeout, resetHeartbeat
        /// <exception cref="IOException"/>
#if NETCOREAPP2_1_OR_GREATER || NETSTANDARD2_1_OR_GREATER
        private int ProcessRecord(int received, byte[] record, Span<byte> buffer)
#else
        private int ProcessRecord(int received, byte[] record, byte[] buf, int off)
#endif
        {
            if (received < 1)
                return -1;

            var cidLength = m_context.SecurityParameters.ConnectionIdPeer?.Length ?? 0;

            if (!TryGetRecordLength(record, 0, received, cidLength, out int headerLength, out int dataLength))
                return -1;

            if (received != (headerLength + dataLength))
                return -1;

            // TODO[dtls13] Deal with opaque record type for 1.3 AEAD ciphers
            short recordType = TlsUtilities.ReadUint8(record, 0);

            switch (recordType)
            {
            case ContentType.alert:
            case ContentType.application_data:
            case ContentType.change_cipher_spec:
            case ContentType.handshake:
            case ContentType.heartbeat:
            case ContentType.tls12_cid:
                break;
            default:
                return -1;
            }

            int epoch = TlsUtilities.ReadUint16(record, 3);

            DtlsEpoch recordEpoch = null;
            if (epoch == m_readEpoch.Epoch)
            {
                recordEpoch = m_readEpoch;
            }
            else if (recordType == ContentType.handshake && null != m_retransmitEpoch
                && epoch == m_retransmitEpoch.Epoch)
            {
                recordEpoch = m_retransmitEpoch;
            }

            if (null == recordEpoch)
                return -1;

            long seq = TlsUtilities.ReadUint48(record, 5);
            if (recordEpoch.ReplayWindow.ShouldDiscard(seq))
                return -1;

            ProtocolVersion recordVersion = TlsUtilities.ReadVersion(record, 1);
            if (!recordVersion.IsDtls)
                return -1;

            if (null != m_readVersion && !m_readVersion.Equals(recordVersion))
            {
                /*
                 * Special-case handling for retransmitted ClientHello records.
                 *
                 * TODO Revisit how 'readVersion' works, since this is quite awkward.
                 */
                bool isClientHelloFragment =
                        ReadEpoch == 0
                    && dataLength > 0
                    && ContentType.handshake == recordType
                    && HandshakeType.client_hello == TlsUtilities.ReadUint8(record, headerLength);

                if (!isClientHelloFragment)
                    return -1;
            }

            long macSeqNo = GetMacSequenceNumber(recordEpoch.Epoch, seq);

            TlsDecodeResult decoded;
            try
            {
                decoded = recordEpoch.Cipher.DecodeCiphertext(macSeqNo, recordType, recordVersion, record, headerLength, dataLength);

                recordEpoch.ReplayWindow.ReportAuthenticated(seq);

                // TODO[cid] somehow notify server of valid packet for peer address update
            }
            catch (TlsFatalAlert fatalAlert) when (fatalAlert.AlertDescription == AlertDescription.bad_record_mac)
            {
                /*
                 * RFC 9146 6.
                 * DTLS implementations MUST silently discard records with bad MACs or that are otherwise invalid.
                 */
                return -1;
            }


            if (decoded.len > m_plaintextLimit)
                return -1;

            if (decoded.len < 1 && decoded.contentType != ContentType.application_data)
                return -1;

            if (null == m_readVersion)
            {
                bool isHelloVerifyRequest =
                        ReadEpoch == 0
                    && dataLength > 0
                    && ContentType.handshake == recordType
                    && HandshakeType.hello_verify_request == TlsUtilities.ReadUint8(record, headerLength);

                if (isHelloVerifyRequest)
                {
                    /*
                     * RFC 6347 4.2.1 DTLS 1.2 server implementations SHOULD use DTLS version 1.0
                     * regardless of the version of TLS that is expected to be negotiated. DTLS 1.2 and
                     * 1.0 clients MUST use the version solely to indicate packet formatting (which is
                     * the same in both DTLS 1.2 and 1.0) and not as part of version negotiation.
                     */
                    if (!ProtocolVersion.DTLSv12.IsEqualOrLaterVersionOf(recordVersion))
                        return -1;
                }
                else
                {
                    this.m_readVersion = recordVersion;
                }
            }

            switch (decoded.contentType)
            {
            case ContentType.alert:
            {
                if (decoded.len == 2)
                {
                    short alertLevel = TlsUtilities.ReadUint8(decoded.buf, decoded.off);
                    short alertDescription = TlsUtilities.ReadUint8(decoded.buf, decoded.off + 1);

                    m_peer.NotifyAlertReceived(alertLevel, alertDescription);

                    if (alertLevel == AlertLevel.fatal)
                    {
                        Failed();
                        throw new TlsFatalAlert(alertDescription);
                    }

                    // TODO Can close_notify be a fatal alert?
                    if (alertDescription == AlertDescription.close_notify)
                    {
                        CloseTransport();
                    }
                }

                return -1;
            }
            case ContentType.application_data:
            {
                if (m_inHandshake)
                {
                    // TODO Consider buffering application data for new epoch that arrives
                    // out-of-order with the Finished message
                    return -1;
                }
                break;
            }
            case ContentType.change_cipher_spec:
            {
                // Implicitly receive change_cipher_spec and change to pending cipher state

                for (int i = 0; i < decoded.len; ++i)
                {
                    short message = TlsUtilities.ReadUint8(decoded.buf, decoded.off + i);
                    if (message != ChangeCipherSpec.change_cipher_spec)
                        continue;

                    if (m_pendingEpoch != null)
                    {
                        m_readEpoch = m_pendingEpoch;
                    }
                }

                return -1;
            }
            case ContentType.handshake:
            {
                if (!m_inHandshake)
                {
                    if (null != m_retransmit)
                    {
                        m_retransmit.ReceivedHandshakeRecord(epoch, decoded.buf, decoded.off, decoded.len);
                    }

                    // TODO Consider support for HelloRequest
                    return -1;
                }
                break;
            }
            case ContentType.heartbeat:
            {
                if (null != m_heartbeatInFlight || m_heartBeatResponder)
                {
                    try
                    {
                        MemoryStream input = new MemoryStream(decoded.buf, decoded.off, decoded.len, false);
                        HeartbeatMessage heartbeatMessage = HeartbeatMessage.Parse(input);

                        if (null != heartbeatMessage)
                        {
                            switch (heartbeatMessage.Type)
                            {
                            case HeartbeatMessageType.heartbeat_request:
                            {
                                if (m_heartBeatResponder)
                                {
                                    HeartbeatMessage response = HeartbeatMessage.Create(m_context,
                                        HeartbeatMessageType.heartbeat_response, heartbeatMessage.Payload);

                                    SendHeartbeatMessage(response);
                                }
                                break;
                            }
                            case HeartbeatMessageType.heartbeat_response:
                            {
                                if (null != m_heartbeatInFlight
                                    && Arrays.AreEqual(heartbeatMessage.Payload, m_heartbeatInFlight.Payload))
                                {
                                    ResetHeartbeat();
                                }
                                break;
                            }
                            default:
                                break;
                            }
                        }
                    }
                    catch (Exception)
                    {
                        // Ignore
                    }
                }

                return -1;
            }
            default:
                return -1;
            }

            /*
             * NOTE: If we receive any non-handshake data in the new epoch implies the peer has
             * received our final flight.
             */
            if (!m_inHandshake && null != m_retransmit)
            {
                this.m_retransmit = null;
                this.m_retransmitEpoch = null;
                this.m_retransmitTimeout = null;
            }

#if NETCOREAPP2_1_OR_GREATER || NETSTANDARD2_1_OR_GREATER
            decoded.buf.AsSpan(decoded.off, decoded.len).CopyTo(buffer);
#else
            Array.Copy(decoded.buf, decoded.off, buf, off, decoded.len);
#endif
            return decoded.len;
        }

        /// <exception cref="IOException"/>
        private int ReceiveRecord(byte[] buf, int off, int len, int waitMillis)
        {
            int cidLength = m_context.SecurityParameters.ConnectionIdPeer?.Length ?? 0;

            if (m_recordQueue.Available > 0)
            {
                var maxHeaderLength = System.Math.Min(RECORD_HEADER_LENGTH + cidLength, m_recordQueue.Available);
                byte[] header = new byte[maxHeaderLength];
                m_recordQueue.Read(header, 0, maxHeaderLength, 0);

                int recordLength;
                if (TryGetRecordLength(header, 0, maxHeaderLength, cidLength, out int headerLength, out int dataLength))
                {
                    recordLength = System.Math.Min(m_recordQueue.Available, headerLength + dataLength);
                }
                else
                {
                    // if we can't determine a length, just return the rest of the buffer - if it's invalid, ProcessRecord will discard it
                    // under normal circumstances, there should never be incomplete/invalid records in the queue
                    recordLength = m_recordQueue.Available;
                }
                m_recordQueue.RemoveData(buf, off, recordLength, 0);
                return recordLength;
            }

            {
                int received = ReceiveDatagram(buf, off, len, waitMillis);
                if (TryGetRecordLength(buf, off, received, cidLength, out int headerLength, out int dataLength))
                {
                    this.m_inConnection = true;
                    var recordLength = headerLength + dataLength;

                    if (received > recordLength)
                    {
                        // if we have more than one record in this datagram, add all but the first to the queue
                        m_recordQueue.AddData(buf, off + recordLength, received - recordLength);
                        received = recordLength;
                    }
                }

                return received;
            }
        }

        private static bool TryGetRecordLength(byte[] buf, int off, int len, int cidLength, out int headerLength, out int dataLength)
        {
            if (len < RECORD_HEADER_LENGTH)
            {
                headerLength = 0;
                dataLength = 0;
                return false;
            }
            short contentType = buf[off];

            if (contentType == ContentType.tls12_cid)
            {
                if (len < RECORD_HEADER_LENGTH + cidLength)
                {
                    headerLength = 0;
                    dataLength = 0;
                    return false;
                }

                headerLength = RECORD_HEADER_LENGTH + cidLength;
                dataLength = TlsUtilities.ReadUint16(buf, off + 11 + cidLength);
                return true;
            }
            else
            {
                headerLength = RECORD_HEADER_LENGTH;
                dataLength = TlsUtilities.ReadUint16(buf, off + 11);
                return true;
            }
        }

        private void ResetHeartbeat()
        {
            this.m_heartbeatInFlight = null;
            this.m_heartbeatResendMillis = -1;
            this.m_heartbeatResendTimeout = null;
            this.m_heartbeatTimeout = new Timeout(m_heartbeat.IdleMillis);
        }

        /// <exception cref="IOException"/>
        private void SendHeartbeatMessage(HeartbeatMessage heartbeatMessage)
        {
            MemoryStream output = new MemoryStream();
            heartbeatMessage.Encode(output);

#if NETCOREAPP2_1_OR_GREATER || NETSTANDARD2_1_OR_GREATER
            if (!output.TryGetBuffer(out var buffer))
                throw new InvalidOperationException();

            SendRecord(ContentType.heartbeat, buffer);
#else
            byte[] buf = output.ToArray();
            SendRecord(ContentType.heartbeat, buf, 0, buf.Length);
#endif
        }

        /*
         * Currently uses synchronization to ensure heartbeat sends and application data sends don't
         * interfere with each other. It may be overly cautious; the sequence number allocation is
         * atomic, and if we synchronize only on the datagram send instead, then the only effect should
         * be possible reordering of records (which might surprise a reliable transport implementation).
         */
        /// <exception cref="IOException"/>
#if NETCOREAPP2_1_OR_GREATER || NETSTANDARD2_1_OR_GREATER
        private void SendRecord(short contentType, ReadOnlySpan<byte> buffer)
#else
        private void SendRecord(short contentType, byte[] buf, int off, int len)
#endif
        {
            // Never send anything until a valid ClientHello has been received
            if (m_writeVersion == null)
                return;

#if NETCOREAPP2_1_OR_GREATER || NETSTANDARD2_1_OR_GREATER
            int len = buffer.Length;
#endif

            if (len > m_plaintextLimit)
                throw new TlsFatalAlert(AlertDescription.internal_error);

            /*
             * RFC 5246 6.2.1 Implementations MUST NOT send zero-length fragments of Handshake, Alert,
             * or ChangeCipherSpec content types.
             */
            if (len < 1 && contentType != ContentType.application_data)
                throw new TlsFatalAlert(AlertDescription.internal_error);

            lock (m_writeLock)
            {
                int recordEpoch = m_writeEpoch.Epoch;
                long recordSequenceNumber = m_writeEpoch.AllocateSequenceNumber();
                long macSequenceNumber = GetMacSequenceNumber(recordEpoch, recordSequenceNumber);
                ProtocolVersion recordVersion = m_writeVersion;

                int headerLength = RECORD_HEADER_LENGTH;
                byte[] connectionIdLocal = m_context.SecurityParameters.ConnectionIdLocal;

                // TODO[cid] find a better way to implement "once encryption is enabled"
                // https://www.rfc-editor.org/rfc/rfc9146.html#section-3-10
                bool useConnectionId = connectionIdLocal != null && recordEpoch != 0;
                if (useConnectionId)
                {
                    headerLength = RECORD_HEADER_LENGTH + connectionIdLocal.Length;
                }

#if NETCOREAPP2_1_OR_GREATER || NETSTANDARD2_1_OR_GREATER
                TlsEncodeResult encoded = m_writeEpoch.Cipher.EncodePlaintext(macSequenceNumber, contentType,
                    recordVersion, headerLength, buffer);
#else
                TlsEncodeResult encoded = m_writeEpoch.Cipher.EncodePlaintext(macSequenceNumber, contentType,
                    recordVersion, headerLength, buf, off, len);
#endif
                int ciphertextLength = encoded.len - headerLength;
                TlsUtilities.CheckUint16(ciphertextLength);

                TlsUtilities.WriteUint8(encoded.recordType, encoded.buf, encoded.off + 0);
                TlsUtilities.WriteVersion(recordVersion, encoded.buf, encoded.off + 1);
                TlsUtilities.WriteUint16(recordEpoch, encoded.buf, encoded.off + 3);
                TlsUtilities.WriteUint48(recordSequenceNumber, encoded.buf, encoded.off + 5);
                if (useConnectionId)
                {
                    Array.Copy(connectionIdLocal, 0, encoded.buf, encoded.off + 11, connectionIdLocal.Length);
                }
                TlsUtilities.WriteUint16(ciphertextLength, encoded.buf, encoded.off + 11 + (useConnectionId ? connectionIdLocal.Length : 0));

                SendDatagram(m_transport, encoded.buf, encoded.off, encoded.len);
            }
        }

        private static long GetMacSequenceNumber(int epoch, long sequence_number)
        {
            return ((epoch & 0xFFFFFFFFL) << 48) | sequence_number;
        }
    }
}
