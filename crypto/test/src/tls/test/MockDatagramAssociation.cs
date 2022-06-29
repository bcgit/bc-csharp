using System;
using System.Collections.Generic;
using System.Threading;

using Org.BouncyCastle.Utilities;

namespace Org.BouncyCastle.Tls.Tests
{
    public class MockDatagramAssociation
    {
        private int m_mtu;
        private MockDatagramTransport m_client, m_server;

        public MockDatagramAssociation(int mtu)
        {
            this.m_mtu = mtu;

            var clientQueue = new List<byte[]>();
            var serverQueue = new List<byte[]>();

            this.m_client = new MockDatagramTransport(this, clientQueue, serverQueue);
            this.m_server = new MockDatagramTransport(this, serverQueue, clientQueue);
        }

        public virtual DatagramTransport Client
        {
            get { return m_client; }
        }

        public virtual DatagramTransport Server
        {
            get { return m_server; }
        }

        private class MockDatagramTransport
            : DatagramTransport
        {
            private readonly MockDatagramAssociation m_outer;
            private IList<byte[]> m_receiveQueue, m_sendQueue;

            internal MockDatagramTransport(MockDatagramAssociation outer, IList<byte[]> receiveQueue,
                IList<byte[]> sendQueue)
            {
                this.m_outer = outer;
                this.m_receiveQueue = receiveQueue;
                this.m_sendQueue = sendQueue;
            }

            public virtual int GetReceiveLimit()
            {
                return m_outer.m_mtu;
            }

            public virtual int GetSendLimit()
            {
                return m_outer.m_mtu;
            }

            public virtual int Receive(byte[] buf, int off, int len, int waitMillis)
            {
                lock (m_receiveQueue)
                {
                    if (m_receiveQueue.Count < 1)
                    {
                        try
                        {
                            Monitor.Wait(m_receiveQueue, waitMillis);
                        }
                        catch (ThreadInterruptedException)
                        {
                            // TODO Keep waiting until full wait expired?
                        }

                        if (m_receiveQueue.Count < 1)
                            return -1;
                    }

                    byte[] packet = m_receiveQueue[0];
                    m_receiveQueue.RemoveAt(0);
                    int copyLength = System.Math.Min(len, packet.Length);
                    Array.Copy(packet, 0, buf, off, copyLength);
                    return copyLength;
                }
            }

            public virtual void Send(byte[] buf, int off, int len)
            {
                if (len > m_outer.m_mtu)
                {
                    // TODO Simulate rejection?
                }

                byte[] packet = Arrays.CopyOfRange(buf, off, off + len);

                lock (m_sendQueue)
                {
                    m_sendQueue.Add(packet);
                    Monitor.PulseAll(m_sendQueue);
                }
            }

            public virtual void Close()
            {
                // TODO?
            }
        }
    }
}
