using System;

using Org.BouncyCastle.Utilities.Date;

namespace Org.BouncyCastle.Tls.Tests
{
    public class UnreliableDatagramTransport
        : DatagramTransport
    {
        private readonly DatagramTransport m_transport;
        private readonly Random m_random;
        private readonly int m_percentPacketLossReceiving, m_percentPacketLossSending;

        public UnreliableDatagramTransport(DatagramTransport transport, Random random,
            int percentPacketLossReceiving, int percentPacketLossSending)
        {
            if (percentPacketLossReceiving < 0 || percentPacketLossReceiving > 100)
                throw new ArgumentException("out of range", "percentPacketLossReceiving");
            if (percentPacketLossSending < 0 || percentPacketLossSending > 100)
                throw new ArgumentException("out of range", "percentPacketLossSending");

            this.m_transport = transport;
            this.m_random = random;
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
                if (length < 0 || !LostPacket(m_percentPacketLossReceiving))
                    return length;

                Console.WriteLine("PACKET LOSS ({0} byte packet not received)", length);

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
                if (length < 0 || !LostPacket(m_percentPacketLossReceiving))
                    return length;

                Console.WriteLine("PACKET LOSS ({0} byte packet not received)", length);

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
            if (LostPacket(m_percentPacketLossSending))
            {
                Console.WriteLine("PACKET LOSS ({0} byte packet not sent)", len);
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
            if (LostPacket(m_percentPacketLossSending))
            {
                Console.WriteLine("PACKET LOSS ({0} byte packet not sent)", buffer.Length);
            }
            else
            {
                m_transport.Send(buffer);
            }
        }
#endif

        public virtual void Close() => m_transport.Close();

        private bool LostPacket(int percentPacketLoss)
        {
            return percentPacketLoss > 0 && m_random.Next(100) < percentPacketLoss;
        }
    }
}
