namespace Org.BouncyCastle.Crypto.Tls 
{
    using System;
    using Org.BouncyCastle.Utilities.Date;
    using System.IO;

    class DTLSRecordLayer : DatagramTransport
    {
        private const int RECORD_HEADER_LENGTH = 13;
        private const int MAX_FRAGMENT_LENGTH = 1 << 14;
        private const long TCP_MSL = 1000L * 60 * 2;
        private const long RETRANSMIT_TIMEOUT = TCP_MSL * 2;

        private readonly DatagramTransport transport;
        private readonly TlsContext context;
        private readonly TlsPeer peer;

        private readonly ByteQueue recordQueue = new ByteQueue();

        private volatile bool closed = false;
        private volatile bool failed = false;
        private volatile ProtocolVersion discoveredPeerVersion = null;
        private volatile bool inHandshake;
        private volatile int plaintextLimit;
        private DTLSEpoch currentEpoch, pendingEpoch;
        private DTLSEpoch readEpoch, writeEpoch;

        private DTLSHandshakeRetransmit retransmit = null;
        private DTLSEpoch retransmitEpoch = null;
        private long retransmitExpiry = 0;

        internal DTLSRecordLayer(DatagramTransport transport, TlsContext context, TlsPeer peer, ContentType contentType)
        {
            this.transport = transport;
            this.context = context;
            this.peer = peer;

            this.inHandshake = true;

            this.currentEpoch = new DTLSEpoch(0, new TlsNullCipher(context));
            this.pendingEpoch = null;
            this.readEpoch = currentEpoch;
            this.writeEpoch = currentEpoch;

            SetPlaintextLimit(MAX_FRAGMENT_LENGTH);
        }

        internal void SetPlaintextLimit(int plaintextLimit)
        {
            this.plaintextLimit = plaintextLimit;
        }

        public ProtocolVersion DiscoveredPeerVersion
        {
            get
            {
                return discoveredPeerVersion;
            }
        }

        public ProtocolVersion ResetDiscoveredPeerVersion()
        {
            ProtocolVersion result = discoveredPeerVersion; 
            discoveredPeerVersion = null;
            return result;
        }

        internal void InitPendingEpoch(TlsCipher pendingCipher)
        {
            if (pendingEpoch != null)
            {
                throw new InvalidOperationException();
            }

            /*
             * TODO "In order to ensure that any given sequence/epoch pair is unique, implementations
             * MUST NOT allow the same epoch value to be reused within two times the TCP maximum segment
             * lifetime."
             */

            // TODO Check for overflow
            this.pendingEpoch = new DTLSEpoch(writeEpoch.Epoch + 1, pendingCipher);
        }

        internal void HandshakeSuccessful(DTLSHandshakeRetransmit retransmit)
        {
            if (readEpoch == currentEpoch || writeEpoch == currentEpoch)
            {
                // TODO
                throw new InvalidOperationException();
            }

            if (retransmit != null)
            {
                this.retransmit = retransmit;
                this.retransmitEpoch = currentEpoch;
                this.retransmitExpiry = DateTimeUtilities.CurrentUnixMs() + RETRANSMIT_TIMEOUT;
            }

            this.inHandshake = false;
            this.currentEpoch = pendingEpoch;
            this.pendingEpoch = null;
        }

        internal void ResetWriteEpoch()
        {
            if (retransmitEpoch != null)
            {
                this.writeEpoch = retransmitEpoch;
            }
            else
            {
                this.writeEpoch = currentEpoch;
            }
        }

        public int ReceiveLimit
        {
            get
            {
                return Math.Min(this.plaintextLimit,
                    readEpoch.Cipher.GetPlaintextLimit(transport.ReceiveLimit - RECORD_HEADER_LENGTH));
            }
        }

        public int SendLimit
        {
            get
            {
                return Math.Min(this.plaintextLimit,
                    writeEpoch.Cipher.GetPlaintextLimit(transport.SendLimit - RECORD_HEADER_LENGTH));
            }
        }

        public int Receive(byte[] buf, int off, int len, int waitMillis)
        {
            byte[] record = null;

            for (;;)
            {
                int receiveLimit = Math.Min(len, ReceiveLimit) + RECORD_HEADER_LENGTH;
                if (record == null || record.Length < receiveLimit)
                {
                    record = new byte[receiveLimit];
                }

                try
                {
                    if (retransmit != null && DateTimeUtilities.CurrentUnixMs() > retransmitExpiry)
                    {
                        retransmit = null;
                        retransmitEpoch = null;
                    }

                    int received = ReceiveRecord(record, 0, receiveLimit, waitMillis);
                    if (received < 0)
                    {
                        return received;
                    }
                    if (received < RECORD_HEADER_LENGTH)
                    {
                        continue;
                    }
                    int length = TlsUtilities.ReadUint16(record, 11);
                    if (received != (length + RECORD_HEADER_LENGTH))
                    {
                        continue;
                    }

                    ContentType type = (ContentType)TlsUtilities.ReadUint8(record, 0);

                    // TODO Support user-specified custom protocols?
                    switch (type)
                    {
                    case ContentType.alert:
                    case ContentType.application_data:
                    case ContentType.change_cipher_spec:
                    case ContentType.handshake:
                    case ContentType.heartbeat:
                        break;
                    default:
                        // TODO Exception?
                        continue;
                    }

                    int epoch = TlsUtilities.ReadUint16(record, 3);

                    DTLSEpoch recordEpoch = null;
                    if (epoch == readEpoch.Epoch)
                    {
                        recordEpoch = readEpoch;
                    }
                    else if (type == ContentType.handshake && retransmitEpoch != null
                        && epoch == retransmitEpoch.Epoch)
                    {
                        recordEpoch = retransmitEpoch;
                    }

                    if (recordEpoch == null)
                    {
                        continue;
                    }

                    long seq = TlsUtilities.ReadUint48(record, 5);
                    if (recordEpoch.ReplayWindow.ShouldDiscard(seq))
                    {
                        continue;
                    }

                    ProtocolVersion version = TlsUtilities.ReadVersion(record, 1);
                    if (discoveredPeerVersion != null && !discoveredPeerVersion.Equals(version))
                    {
                        continue;
                    }

                    byte[] plaintext = recordEpoch.Cipher.DecodeCiphertext(
                        GetMacSequenceNumber(recordEpoch.Epoch, seq), type, record, RECORD_HEADER_LENGTH,
                        received - RECORD_HEADER_LENGTH);

                    recordEpoch.ReplayWindow.ReportAuthenticated(seq);

                    if (plaintext.Length > this.plaintextLimit)
                    {
                        continue;
                    }

                    if (discoveredPeerVersion == null)
                    {
                        discoveredPeerVersion = version;
                    }

                    switch (type)
                    {
                        case ContentType.alert:
                            {
                                if (plaintext.Length == 2)
                                {
                                    AlertLevel alertLevel = (AlertLevel)plaintext[0];
                                    AlertDescription alertDescription = (AlertDescription)plaintext[1];

                                    peer.NotifyAlertReceived(alertLevel, alertDescription);

                                    if (alertLevel == AlertLevel.fatal)
                                    {
                                        Fail(alertDescription);
                                        throw new TlsFatalAlert(alertDescription);
                                    }

                                    // TODO Can close_notify be a fatal alert?
                                    if (alertDescription == AlertDescription.close_notify)
                                    {
                                        CloseTransport();
                                    }
                                }
                                else
                                {
                                    // TODO What exception?
                                }

                                continue;
                            }
                        case ContentType.application_data:
                            {
                                if (inHandshake)
                                {
                                    // TODO Consider buffering application data for new epoch that arrives
                                    // out-of-order with the Finished message
                                    continue;
                                }
                                break;
                            }
                        case ContentType.change_cipher_spec:
                            {
                                // Implicitly receive change_cipher_spec and change to pending cipher state

                                for (int i = 0; i < plaintext.Length; ++i)
                                {
                                    short message = TlsUtilities.ReadUint8(plaintext, i);
                                    if (message != ChangeCipherSpec.change_cipher_spec)
                                    {
                                        continue;
                                    }

                                    if (pendingEpoch != null)
                                    {
                                        readEpoch = pendingEpoch;
                                    }
                                }
                                continue;
                            }
                        case ContentType.handshake:
                            {
                                if (!inHandshake)
                                {
                                    if (retransmit != null)
                                    {
                                        retransmit.ReceivedHandshakeRecord(epoch, plaintext, 0, plaintext.Length);
                                    }

                                    // TODO Consider support for HelloRequest
                                    continue;
                                }
                                break;
                            }
                        case ContentType.heartbeat:
                            {
                                // TODO[RFC 6520]
                                continue;
                            }
                    }

                    /*
                     * NOTE: If we receive any non-handshake data in the new epoch implies the peer has
                     * received our final flight.
                     */
                    if (!inHandshake && retransmit != null)
                    {
                        this.retransmit = null;
                        this.retransmitEpoch = null;
                    }

                    Array.Copy(plaintext, 0, buf, off, plaintext.Length);
                    return plaintext.Length;
                }
                catch (IOException e)
                {
                    // NOTE: Assume this is a timeout for the moment
                    throw e;
                }
            }
        }

        public void Send(byte[] buf, int off, int len)
        {
            ContentType contentType = ContentType.application_data;

            if (this.inHandshake || this.writeEpoch == this.retransmitEpoch)
            {
                contentType = ContentType.handshake;

                HandshakeType handshakeType = (HandshakeType)TlsUtilities.ReadUint8(buf, off);
                if (handshakeType == HandshakeType.finished)
                {
                    DTLSEpoch nextEpoch = null;
                    if (this.inHandshake)
                    {
                        nextEpoch = pendingEpoch;
                    }
                    else if (this.writeEpoch == this.retransmitEpoch)
                    {
                        nextEpoch = currentEpoch;
                    }

                    if (nextEpoch == null)
                    {
                        // TODO
                        throw new InvalidOperationException();
                    }

                    // Implicitly send change_cipher_spec and change to pending cipher state

                    // TODO Send change_cipher_spec and finished records in single datagram?
                    byte[] data = new byte[]{ 1 };
                    SendRecord(ContentType.change_cipher_spec, data, 0, data.Length);

                    writeEpoch = nextEpoch;
                }
            }

            SendRecord(contentType, buf, off, len);
        }

        public void Close()
        {
            if (!closed)
            {
                if (inHandshake)
                {
                    Warn(AlertDescription.user_canceled, "User canceled handshake");
                }
                CloseTransport();
            }
        }

        internal void Fail(AlertDescription alertDescription)
        {
            if (!closed)
            {
                try
                {
                    RaiseAlert(AlertLevel.fatal, alertDescription, null, null);
                }
                catch
                {
                    // Ignore
                }

                failed = true;

                CloseTransport();
            }
        }

        internal void Warn(AlertDescription alertDescription, String message)
        {
            RaiseAlert(AlertLevel.warning, alertDescription, message, null);
        }

        private void CloseTransport()
        {
            if (!closed)
            {
                /*
                 * RFC 5246 7.2.1. Unless some other fatal alert has been transmitted, each party is
                 * required to send a close_notify alert before closing the write side of the
                 * connection. The other party MUST respond with a close_notify alert of its own and
                 * close down the connection immediately, discarding any pending writes.
                 */

                try
                {
                    if (!failed)
                    {
                        Warn(AlertDescription.close_notify, null);
                    }
                    transport.Close();
                }
                catch 
                {
                    // Ignore
                }

                closed = true;
            }
        }

        private void RaiseAlert(AlertLevel alertLevel, AlertDescription alertDescription, String message, Exception cause)
        {
            peer.NotifyAlertRaised(alertLevel, alertDescription, message, cause);

            byte[] error = new byte[2];
            error[0] = (byte)alertLevel;
            error[1] = (byte)alertDescription;

            SendRecord(ContentType.alert, error, 0, 2);
        }

        private int ReceiveRecord(byte[] buf, int off, int len, int waitMillis)
        {
            int received;
            if (recordQueue.Available > 0)
            {
                int length = 0;
                if (recordQueue.Available >= RECORD_HEADER_LENGTH)
                {
                    byte[] lengthBytes = new byte[2];
                    recordQueue.Read(lengthBytes, 0, 2, 11);
                    length = TlsUtilities.ReadUint16(lengthBytes, 0);
                }

                received = Math.Min(recordQueue.Available, RECORD_HEADER_LENGTH + length);
                recordQueue.RemoveData(buf, off, received, 0);
                return received;
            }

            received = transport.Receive(buf, off, len, waitMillis);

            if (received >= RECORD_HEADER_LENGTH)
            {
                int fragmentLength = TlsUtilities.ReadUint16(buf, off + 11);
                int recordLength = RECORD_HEADER_LENGTH + fragmentLength;
                if (received > recordLength)
                {
                    recordQueue.AddData(buf, off + recordLength, received - recordLength);
                    received = recordLength;
                }
            }

            return received;
        }

        private void SendRecord(ContentType contentType, byte[] buf, int off, int len)
        {
            if (len > this.plaintextLimit)
            {
                throw new TlsFatalAlert(AlertDescription.internal_error);
            }

            /*
             * RFC 5264 6.2.1 Implementations MUST NOT send zero-length fragments of Handshake, Alert,
             * or ChangeCipherSpec content types.
             */
            if (len < 1 && contentType != ContentType.application_data)
            {
                throw new TlsFatalAlert(AlertDescription.internal_error);
            }

            int recordEpoch = writeEpoch.Epoch;
            long recordSequenceNumber = writeEpoch.AllocateSequenceNumber();

            byte[] ciphertext = writeEpoch.Cipher.EncodePlaintext(
                GetMacSequenceNumber(recordEpoch, recordSequenceNumber), contentType, buf, off, len, RECORD_HEADER_LENGTH);

            // TODO Check the ciphertext length?

            byte[] record = ciphertext;
            TlsUtilities.WriteUint8((byte)contentType, record, 0);
            ProtocolVersion version = discoveredPeerVersion != null ? discoveredPeerVersion : context.ClientVersion;
            TlsUtilities.WriteVersion(version, record, 1);
            TlsUtilities.WriteUint16(recordEpoch, record, 3);
            TlsUtilities.WriteUint48(recordSequenceNumber, record, 5);
            TlsUtilities.WriteUint16(record.Length - RECORD_HEADER_LENGTH, record, 11);
            //Array.Copy(ciphertext, 0, record, RECORD_HEADER_LENGTH, ciphertext.Length);

            transport.Send(record, 0, record.Length);
        }

        private static long GetMacSequenceNumber(int epoch, long sequence_number)
        {
            return ((long)epoch << 48) | sequence_number;
        }

        void IDisposable.Dispose()
        {
            this.Close();
        }
    }

}