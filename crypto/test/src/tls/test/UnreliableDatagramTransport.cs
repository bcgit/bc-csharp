using System;

using Org.BouncyCastle.Utilities.Date;

namespace Org.BouncyCastle.Tls.Tests
{
    public class UnreliableDatagramTransport
        : DatagramTransport
    {
        private readonly DatagramTransport m_transport;
        private readonly Random m_random;
        private readonly int m_maxDroppedReceiving, m_maxDroppedSending;
        private volatile int m_percentPacketLossReceiving, m_percentPacketLossSending;
        private int m_droppedReceiving = 0, m_droppedSending = 0;

        /// <summary>Lose the given percentages of datagrams, with no limit on how many are lost.</summary>
        public UnreliableDatagramTransport(DatagramTransport transport, Random random,
            int percentPacketLossReceiving, int percentPacketLossSending)
            : this(transport, random, percentPacketLossReceiving, percentPacketLossSending, int.MaxValue,
                int.MaxValue)
        {
        }

        /// <summary>
        /// Lose the given percentages of datagrams, but no more than the given number in each direction, after which
        /// the transport is reliable in that direction. The limit bounds how long a run can take: each lost datagram
        /// costs at most one resend cycle, and the resend interval doubles with each cycle.
        /// </summary>
        public UnreliableDatagramTransport(DatagramTransport transport, Random random,
            int percentPacketLossReceiving, int percentPacketLossSending, int maxDroppedReceiving,
            int maxDroppedSending)
        {
            if (maxDroppedReceiving < 0)
                throw new ArgumentException("cannot be negative", "maxDroppedReceiving");
            if (maxDroppedSending < 0)
                throw new ArgumentException("cannot be negative", "maxDroppedSending");

            this.m_transport = transport;
            this.m_random = random;
            this.m_maxDroppedReceiving = maxDroppedReceiving;
            this.m_maxDroppedSending = maxDroppedSending;

            SetPacketLoss(percentPacketLossReceiving, percentPacketLossSending);
        }

        /// <summary>Change the loss rates, e.g. to make the transport reliable once a handshake has completed.
        /// </summary>
        public virtual void SetPacketLoss(int percentPacketLossReceiving, int percentPacketLossSending)
        {
            if (percentPacketLossReceiving < 0 || percentPacketLossReceiving > 100)
                throw new ArgumentException("out of range", "percentPacketLossReceiving");
            if (percentPacketLossSending < 0 || percentPacketLossSending > 100)
                throw new ArgumentException("out of range", "percentPacketLossSending");

            this.m_percentPacketLossReceiving = percentPacketLossReceiving;
            this.m_percentPacketLossSending = percentPacketLossSending;
        }

        public virtual int GetReceiveLimit() => m_transport.GetReceiveLimit();

        public virtual int GetSendLimit() => m_transport.GetSendLimit();

        public virtual int Receive(byte[] buf, int off, int len, int waitMillis)
        {
//#if NETCOREAPP2_1_OR_GREATER || NETSTANDARD2_1_OR_GREATER
#if NET6_0_OR_GREATER
            return Receive(buf.AsSpan(off, len), waitMillis);
#else
            long endMillis = DateTimeUtilities.CurrentUnixMs() + waitMillis;
            for (;;)
            {
                int length = m_transport.Receive(buf, off, len, waitMillis);
                if (length < 0 || !LostPacketReceiving())
                    return length;

                TlsTestUtilities.Log("PACKET LOSS ({0} byte packet not received)", length);

                long now = DateTimeUtilities.CurrentUnixMs();
                if (now >= endMillis)
                    return -1;

                waitMillis = (int)(endMillis - now);
            }
#endif
        }

//#if NETCOREAPP2_1_OR_GREATER || NETSTANDARD2_1_OR_GREATER
#if NET6_0_OR_GREATER
        public virtual int Receive(Span<byte> buffer, int waitMillis)
        {
            long endMillis = DateTimeUtilities.CurrentUnixMs() + waitMillis;
            for (;;)
            {
                int length = m_transport.Receive(buffer, waitMillis);
                if (length < 0 || !LostPacketReceiving())
                    return length;

                TlsTestUtilities.Log("PACKET LOSS ({0} byte packet not received)", length);

                long now = DateTimeUtilities.CurrentUnixMs();
                if (now >= endMillis)
                    return -1;

                waitMillis = (int)(endMillis - now);
            }
        }
#endif

        public virtual void Send(byte[] buf, int off, int len)
        {
//#if NETCOREAPP2_1_OR_GREATER || NETSTANDARD2_1_OR_GREATER
#if NET6_0_OR_GREATER
            Send(buf.AsSpan(off, len));
#else
            if (LostPacketSending())
            {
                TlsTestUtilities.Log("PACKET LOSS ({0} byte packet not sent)", len);
            }
            else
            {
                m_transport.Send(buf, off, len);
            }
#endif
        }

//#if NETCOREAPP2_1_OR_GREATER || NETSTANDARD2_1_OR_GREATER
#if NET6_0_OR_GREATER
        public virtual void Send(ReadOnlySpan<byte> buffer)
        {
            if (LostPacketSending())
            {
                TlsTestUtilities.Log("PACKET LOSS ({0} byte packet not sent)", buffer.Length);
            }
            else
            {
                m_transport.Send(buffer);
            }
        }
#endif

        public virtual void Close() => m_transport.Close();

        private bool LostPacketReceiving()
        {
            lock (this)
            {
                if (m_droppedReceiving >= m_maxDroppedReceiving || !LostPacket(m_percentPacketLossReceiving))
                    return false;

                if (++m_droppedReceiving == m_maxDroppedReceiving)
                {
                    TlsTestUtilities.Log("PACKET LOSS LIMIT REACHED ({0} packets not received)", m_maxDroppedReceiving);
                }
                return true;
            }
        }

        private bool LostPacketSending()
        {
            lock (this)
            {
                if (m_droppedSending >= m_maxDroppedSending || !LostPacket(m_percentPacketLossSending))
                    return false;

                if (++m_droppedSending == m_maxDroppedSending)
                {
                    TlsTestUtilities.Log("PACKET LOSS LIMIT REACHED ({0} packets not sent)", m_maxDroppedSending);
                }
                return true;
            }
        }

        private bool LostPacket(int percentPacketLoss)
        {
            return percentPacketLoss > 0 && m_random.Next(100) < percentPacketLoss;
        }
    }
}
