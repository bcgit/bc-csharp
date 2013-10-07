using System;
using Org.BouncyCastle.Utilities.Date;

namespace Org.BouncyCastle.Crypto.Tls.Test
{

    public class UnreliableDatagramTransport : DatagramTransport
    {
        private readonly DatagramTransport transport;
        private readonly Random random;
        private readonly int percentPacketLossReceiving, percentPacketLossSending;

        public UnreliableDatagramTransport(DatagramTransport transport, Random random,
                                           int percentPacketLossReceiving, int percentPacketLossSending)
        {
            if (percentPacketLossReceiving < 0 || percentPacketLossReceiving > 100)
            {
                throw new ArgumentException("'percentPacketLossReceiving' out of range");
            }
            if (percentPacketLossSending < 0 || percentPacketLossSending > 100)
            {
                throw new ArgumentException("'percentPacketLossSending' out of range");
            }

            this.transport = transport;
            this.random = random;
            this.percentPacketLossReceiving = percentPacketLossReceiving;
            this.percentPacketLossSending = percentPacketLossSending;
        }

        public int ReceiveLimit
        {
            get
            {
                return transport.ReceiveLimit;
            }
        }

        public int SendLimit
        {
            get
            {
                return transport.SendLimit;
            }
        }

        public int Receive(byte[] buf, int off, int len, int waitMillis)
        {
            long endMillis = DateTimeUtilities.CurrentUnixMs() + waitMillis;
            for (; ; )
            {
                int length = transport.Receive(buf, off, len, waitMillis);
                if (length < 0 || !lostPacket(percentPacketLossReceiving))
                {
                    return length;
                }

                Console.WriteLine("PACKET LOSS (" + length + " byte packet not received)");

                long now = DateTimeUtilities.CurrentUnixMs();
                if (now >= endMillis)
                {
                    return -1;
                }

                waitMillis = (int)(endMillis - now);
            }
        }

        public void Send(byte[] buf, int off, int len)
        {
            if (lostPacket(percentPacketLossSending))
            {
                Console.WriteLine("PACKET LOSS (" + len + " byte packet not sent)");
            }
            else
            {
                transport.Send(buf, off, len);
            }
        }

        public void Close()
        {
            transport.Close();
        }

        private bool lostPacket(int percentPacketLoss)
        {
            return random.Next(100) < percentPacketLoss;
        }

        void IDisposable.Dispose()
        {
            Close();
        }
    }
}