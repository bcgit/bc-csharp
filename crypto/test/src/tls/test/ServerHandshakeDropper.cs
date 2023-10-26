using System;

namespace Org.BouncyCastle.Tls.Tests
{
    /** This is a [Transport] wrapper which causes the first retransmission of the second flight of a server
     * handshake to be dropped. */
    public class ServerHandshakeDropper
        : FilteredDatagramTransport
    {
        private static FilterPredicate Choose(bool condition, FilterPredicate left, FilterPredicate right)
        {
            if (condition) { return left; } else { return right; }
        }

        public ServerHandshakeDropper(DatagramTransport transport, bool dropOnReceive)
            : base(transport,
                Choose(dropOnReceive, new DropFirstServerFinalFlight().AllowPacket, AlwaysAllow),
                Choose(dropOnReceive, AlwaysAllow, new DropFirstServerFinalFlight().AllowPacket))
        {
        }

        /** This drops the first instance of DTLS packets that either begin with a ChangeCipherSpec, or handshake in
         * epoch 1.  This is the server's final flight of the handshake.  It will test whether the client properly
         * retransmits its second flight, and the server properly retransmits the dropped flight.
         */
        private class DropFirstServerFinalFlight
        {
            private bool m_sawChangeCipherSpec = false;
            private bool m_sawEpoch1Handshake = false;

            private bool IsChangeCipherSpec(byte[] buf, int off, int len)
            {
                short contentType = TlsUtilities.ReadUint8(buf, off);
                return ContentType.change_cipher_spec == contentType;
            }

            private bool IsEpoch1Handshake(byte[] buf, int off, int len)
            {
                short contentType = TlsUtilities.ReadUint8(buf, off);
                if (ContentType.handshake != contentType)
                    return false;

                int epoch = TlsUtilities.ReadUint16(buf, off + 3);
                return 1 == epoch;
            }

            public bool AllowPacket(byte[] buf, int off, int len)
            {
                if (!m_sawChangeCipherSpec && IsChangeCipherSpec(buf, off, len))
                {
                    m_sawChangeCipherSpec = true;
                    return false;
                }
                if (!m_sawEpoch1Handshake && IsEpoch1Handshake(buf, off, len))
                {
                    m_sawEpoch1Handshake = true;
                    return false;
                }
                return true;
            }
        }
    }
}
