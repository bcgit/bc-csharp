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

        public virtual int GetReceiveLimit()
        {
            return m_transport.GetReceiveLimit();
        }

        public virtual int GetSendLimit()
        {
            return m_transport.GetSendLimit();
        }

        public virtual int Receive(byte[] buf, int off, int len, int waitMillis)
        {
            long endMillis = DateTimeUtilities.CurrentUnixMs() + waitMillis;
            for (;;)
            {
                int length = m_transport.Receive(buf, off, len, waitMillis);
                if (length < 0 || !LostPacket(m_percentPacketLossReceiving))
                    return length;

                Console.WriteLine("PACKET LOSS (" + length + " byte packet not received)");

                long now = DateTimeUtilities.CurrentUnixMs();
                if (now >= endMillis)
                    return -1;

                waitMillis = (int)(endMillis - now);
            }
        }

        public virtual void Send(byte[] buf, int off, int len)
        {
            if (LostPacket(m_percentPacketLossSending))
            {
                Console.WriteLine("PACKET LOSS (" + len + " byte packet not sent)");
            }
            else
            {
                m_transport.Send(buf, off, len);
            }
        }

        public virtual void Close()
        {
            m_transport.Close();
        }

        private bool LostPacket(int percentPacketLoss)
        {
            return percentPacketLoss > 0 && m_random.Next(100) < percentPacketLoss;
        }
    }
}
