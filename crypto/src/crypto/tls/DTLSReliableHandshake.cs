using System.Collections;
using System.IO;
using Org.BouncyCastle.Utilities;

namespace Org.BouncyCastle.Crypto.Tls
{
    class DTLSReliableHandshake
    {
        private const int MAX_RECEIVE_AHEAD = 10;
        private readonly DTLSRecordLayer recordLayer;

        private TlsHandshakeHash hash = new DeferredHash();

        private IDictionary currentInboundFlight =  Platform.CreateHashtable(); 
        private IDictionary previousInboundFlight = null;
        private IList outboundFlight = Platform.CreateArrayList();
        private bool sending = true;

        private int message_seq = 0, next_receive_seq = 0;

        public DTLSReliableHandshake(TlsContext context, DTLSRecordLayer transport)
        {
            this.recordLayer = transport;
            this.hash.Init(context);
        }

        internal void NotifyHelloComplete()
        {
            this.hash = this.hash.Commit();
        }

        internal byte[] GetCurrentHash()
        {
            TlsHandshakeHash copyOfHash = hash.Fork();
            byte[] result = new byte[copyOfHash.GetDigestSize()];
            copyOfHash.DoFinal(result, 0);
            return result;
        }

        internal void SendMessage(HandshakeType msg_type, byte[] body)
        {
            TlsUtilities.CheckUint24(body.Length);

            if (!sending)
            {
                CheckInboundFlight();
                sending = true;
                outboundFlight.Clear();
            }

            Message message = new Message(message_seq++, msg_type, body);

            outboundFlight.Add(message);

            WriteMessage(message);
            UpdateHandshakeMessagesDigest(message);
        }

        internal byte[] ReceiveMessageBody(HandshakeType msg_type)
        {
            Message message = ReceiveMessage();
            if (message.Type != msg_type)
            {
                throw new TlsFatalAlert(AlertDescription.unexpected_message);
            }

            return message.Body;
        }

        internal Message ReceiveMessage()
        {
            if (sending)
            {
                sending = false;
                PrepareInboundFlight();
            }

            // Check if we already have the next message waiting
            {
                DTLSReassembler next = (DTLSReassembler)currentInboundFlight[next_receive_seq];
                if (next != null)
                {
                    byte[] body = next.GetBodyIfComplete();
                    if (body != null)
                    {
                        previousInboundFlight = null;
                        return UpdateHandshakeMessagesDigest(new Message(next_receive_seq++, next.MessageType, body));
                    }
                }
            }

            byte[] buf = null;

            // TODO Check the conditions under which we should reset this
            int readTimeoutMillis = 1000;

            for (; ; )
            {
                int receiveLimit = recordLayer.ReceiveLimit;
                if (buf == null || buf.Length < receiveLimit)
                {
                    buf = new byte[receiveLimit];
                }

                // TODO Handle records containing multiple handshake messages

                try
                {
                    for (; ; )
                    {
                        int received = recordLayer.Receive(buf, 0, receiveLimit, readTimeoutMillis);
                        if (received < 0)
                        {
                            break;
                        }
                        if (received < 12)
                        {
                            continue;
                        }
                        int fragment_length = TlsUtilities.ReadUint24(buf, 9);
                        if (received != (fragment_length + 12))
                        {
                            continue;
                        }
                        int seq = TlsUtilities.ReadUint16(buf, 4);
                        if (seq > (next_receive_seq + MAX_RECEIVE_AHEAD))
                        {
                            continue;
                        }
                        HandshakeType msg_type = (HandshakeType)TlsUtilities.ReadUint8(buf, 0);
                        int length = TlsUtilities.ReadUint24(buf, 1);
                        int fragment_offset = TlsUtilities.ReadUint24(buf, 6);
                        if (fragment_offset + fragment_length > length)
                        {
                            continue;
                        }

                        if (seq < next_receive_seq)
                        {
                            /*
                             * NOTE: If we receive the previous flight of incoming messages in full
                             * again, retransmit our last flight
                             */
                            if (previousInboundFlight != null)
                            {
                                DTLSReassembler reassembler = (DTLSReassembler)previousInboundFlight[seq];
                                if (reassembler != null)
                                {

                                    reassembler.ContributeFragment(msg_type, length, buf, 12, fragment_offset,
                                        fragment_length);

                                    if (CheckAll(previousInboundFlight))
                                    {

                                        ResendOutboundFlight();

                                        /*
                                         * TODO[DTLS] implementations SHOULD back off handshake packet
                                         * size during the retransmit backoff.
                                         */
                                        readTimeoutMillis = System.Math.Min(readTimeoutMillis * 2, 60000);

                                        ResetAll(previousInboundFlight);
                                    }
                                }
                            }
                        }
                        else
                        {

                            DTLSReassembler reassembler = (DTLSReassembler)currentInboundFlight[seq];
                            if (reassembler == null)
                            {
                                reassembler = new DTLSReassembler(msg_type, length);
                                currentInboundFlight[seq] = reassembler;
                            }

                            reassembler.ContributeFragment(msg_type, length, buf, 12, fragment_offset, fragment_length);

                            if (seq == next_receive_seq)
                            {
                                byte[] body = reassembler.GetBodyIfComplete();
                                if (body != null)
                                {
                                    previousInboundFlight = null;
                                    return UpdateHandshakeMessagesDigest(new Message(next_receive_seq++,
                                        reassembler.MessageType, body));
                                }
                            }
                        }
                    }
                }
                catch 
                {
                    // NOTE: Assume this is a timeout for the moment
                }

                ResendOutboundFlight();

                /*
                 * TODO[DTLS] implementations SHOULD back off handshake packet size during the
                 * retransmit backoff.
                 */
                readTimeoutMillis = System.Math.Min(readTimeoutMillis * 2, 60000);
            }
        }


        internal void Finish()
        {
            DTLSHandshakeRetransmit retransmit = null;
            if (!sending)
            {
                CheckInboundFlight();
            }
            else if (currentInboundFlight != null)
            {
                /*
                 * RFC 6347 4.2.4. In addition, for at least twice the default MSL defined for [TCP],
                 * when in the FINISHED state, the node that transmits the last flight (the server in an
                 * ordinary handshake or the client in a resumed handshake) MUST respond to a retransmit
                 * of the peer's last flight with a retransmit of the last flight.
                 */
                retransmit = new DTLSHandshakeRetransmitImpl(this);
            }

            recordLayer.HandshakeSuccessful(retransmit);
        }

        private class DTLSHandshakeRetransmitImpl : DTLSHandshakeRetransmit
        {
            private DTLSReliableHandshake outer;

            public DTLSHandshakeRetransmitImpl(DTLSReliableHandshake outer)
            {
                this.outer = outer;
            }

            public void ReceivedHandshakeRecord(int epoch, byte[] buf, int off, int len)
            {
                /*
                 * TODO Need to handle the case where the previous inbound flight contains
                 * messages from two epochs.
                 */
                if (len < 12)
                {
                    return;
                }
                int fragment_length = TlsUtilities.ReadUint24(buf, off + 9);
                if (len != (fragment_length + 12))
                {
                    return;
                }
                int seq = TlsUtilities.ReadUint16(buf, off + 4);
                if (seq >= outer.next_receive_seq)
                {
                    return;
                }

                HandshakeType msg_type = (HandshakeType)TlsUtilities.ReadUint8(buf, off);

                // TODO This is a hack that only works until we try to support renegotiation
                int expectedEpoch = msg_type == HandshakeType.finished ? 1 : 0;
                if (epoch != expectedEpoch)
                {
                    return;
                }

                int length = TlsUtilities.ReadUint24(buf, off + 1);
                int fragment_offset = TlsUtilities.ReadUint24(buf, off + 6);
                if (fragment_offset + fragment_length > length)
                {
                    return;
                }

                DTLSReassembler reassembler = (DTLSReassembler)outer.currentInboundFlight[seq];
                if (reassembler != null)
                {
                    reassembler.ContributeFragment(msg_type, length, buf, off + 12, fragment_offset,
                        fragment_length);
                    if (CheckAll(outer.currentInboundFlight))
                    {
                        outer.ResendOutboundFlight();
                        ResetAll(outer.currentInboundFlight);
                    }
                }
            }
        }

        internal void ResetHandshakeMessagesDigest()
        {
            hash.Reset();
        }

        /**
         * Check that there are no "extra" messages left in the current inbound flight
         */
        private void CheckInboundFlight()
        {
            foreach(var obj in currentInboundFlight.Keys)
            {
                int key = (int)obj;
                if (key >= next_receive_seq)
                {
                    // TODO Should this be considered an error?
                }
            }
        }

        private void PrepareInboundFlight()
        {
            ResetAll(currentInboundFlight);
            previousInboundFlight = currentInboundFlight;
            currentInboundFlight = Platform.CreateHashtable();
        }

        private void ResendOutboundFlight()
        {
            recordLayer.ResetWriteEpoch();
            for (int i = 0; i < outboundFlight.Count; ++i)
            {
                WriteMessage((Message)outboundFlight[i]);
            }
        }

        private Message UpdateHandshakeMessagesDigest(Message message)
        {
            if (message.Type != HandshakeType.hello_request)
            {
                byte[] body = message.Body;
                byte[] buf = new byte[12];
                TlsUtilities.WriteUint8((byte)message.Type, buf, 0);
                TlsUtilities.WriteUint24(body.Length, buf, 1);
                TlsUtilities.WriteUint16(message.Seq, buf, 4);
                TlsUtilities.WriteUint24(0, buf, 6);
                TlsUtilities.WriteUint24(body.Length, buf, 9);
                hash.BlockUpdate(buf, 0, buf.Length);
                hash.BlockUpdate(body, 0, body.Length);
            }
            return message;
        }

        private void WriteMessage(Message message)
        {
            int sendLimit = recordLayer.SendLimit;
            int fragmentLimit = sendLimit - 12;

            // TODO Support a higher minimum fragment size?
            if (fragmentLimit < 1)
            {
                // TODO Should we be throwing an exception here?
                throw new TlsFatalAlert(AlertDescription.internal_error);
            }

            int length = message.Body.Length;

            // NOTE: Must still send a fragment if body is empty
            int fragment_offset = 0;
            do
            {
                int fragment_length = System.Math.Min(length - fragment_offset, fragmentLimit);
                WriteHandshakeFragment(message, fragment_offset, fragment_length);
                fragment_offset += fragment_length;
            }
            while (fragment_offset < length);
        }

        private void WriteHandshakeFragment(Message message, int fragment_offset, int fragment_length)
        {
            RecordLayerBuffer fragment = new RecordLayerBuffer(12 + fragment_length);
            TlsUtilities.WriteUint8((ushort)message.Type, fragment);
            TlsUtilities.WriteUint24(message.Body.Length, fragment);
            TlsUtilities.WriteUint16(message.Seq, fragment);
            TlsUtilities.WriteUint24(fragment_offset, fragment);
            TlsUtilities.WriteUint24(fragment_length, fragment);
            fragment.Write(message.Body, fragment_offset, fragment_length);

            fragment.SendToRecordLayer(recordLayer);
        }

        private static bool CheckAll(IDictionary inboundFlight)
        {
            foreach(var value in inboundFlight.Values) 
            {
                if (((DTLSReassembler)value).GetBodyIfComplete() == null)
                {
                    return false;
                }
            }
            return true;
        }

        private static void ResetAll(IDictionary inboundFlight)
        {
            foreach (var value in inboundFlight.Values)
            {
                ((DTLSReassembler)value).Reset();
            }
        }

        internal class Message
        {
            private readonly int message_seq;
            private readonly HandshakeType msg_type;
            private readonly byte[] body;

            public Message(int message_seq, HandshakeType msg_type, byte[] body)
            {
                this.message_seq = message_seq;
                this.msg_type = msg_type;
                this.body = body;
            }

            public int Seq
            {
                get
                {
                    return message_seq;
                }
            }

            public HandshakeType Type
            {
                get
                {
                    return msg_type;
                }
            }

            public byte[] Body
            {
                get
                {
                    return body;
                }
            }
        }

        sealed class RecordLayerBuffer : MemoryStream
        {
            public RecordLayerBuffer(int size)
                : base(size)
            {

            }

            public void SendToRecordLayer(DTLSRecordLayer recordLayer)
            {
                recordLayer.Send(GetBuffer(), 0, (int)this.Length);
                SetLength(0);
            }
        }

    }
}