using System.Collections;
using System.Threading;
using System;
using System.Collections.Generic;
namespace Org.BouncyCastle.Crypto.Tls.Test
{

    public class MockDatagramAssociation
    {
        private int mtu;
        private MockDatagramTransport client, server;

        public MockDatagramAssociation(int mtu)
        {
            this.mtu = mtu;

            var clientQueue = new Queue<ArraySegment<byte>>();
            var serverQueue = new Queue<ArraySegment<byte>>();

            this.client = new MockDatagramTransport(this, clientQueue, serverQueue);
            this.server = new MockDatagramTransport(this, serverQueue, clientQueue);
        }

        public DatagramTransport Client
        {
            get
            {
                return client;
            }
        }

        public DatagramTransport Server
        {
            get
            {
                return server;
            }
        }

        private class MockDatagramTransport : DatagramTransport
        {
            private Queue<ArraySegment<byte>> receiveQueue, sendQueue;
            private AutoResetEvent recieveQueueEvent = new AutoResetEvent(false);
            private MockDatagramAssociation outer;

            public MockDatagramTransport(MockDatagramAssociation outer, Queue<ArraySegment<byte>> receiveQueue, Queue<ArraySegment<byte>> sendQueue)
            {
                this.outer = outer;
                this.receiveQueue = receiveQueue;
                this.sendQueue = sendQueue;
            }

            public int ReceiveLimit
            {
                get
                {
                    return outer.mtu;
                }
            }

            public int SendLimit
            {
                get
                {
                    return outer.mtu;
                }
            }

            public int Receive(byte[] buf, int off, int len, int waitMillis)
            {
                lock(receiveQueue)                
                {
                    if (receiveQueue.Count == 0)
                    {
                        try
                        {
                            Monitor.Wait(receiveQueue, waitMillis);
                        }
                        catch (Exception e)
                        {
                            // TODO Keep waiting until full wait expired?
                        }
                        if (receiveQueue.Count == 0)
                        {
                            return -1;
                        }
                    }

                    ArraySegment<byte> packet = (ArraySegment<byte>)receiveQueue.Dequeue();

                    int copyLength = System.Math.Min(len, packet.Count);
                    Buffer.BlockCopy(packet.Array, packet.Offset, buf, off, copyLength);
                    return copyLength;
                }
            }

            public void Send(byte[] buf, int off, int len)
            {
                if (len > outer.mtu)
                {
                    // TODO Simulate rejection?
                }

                byte[] copy = new byte[len];
                Buffer.BlockCopy(buf, off, copy, 0, len);
                ArraySegment<byte> packet = new ArraySegment<byte>(copy, 0, len);

                lock (sendQueue)
                {
                    sendQueue.Enqueue(packet);
                    Monitor.Pulse(sendQueue);
                }
            }

            public void Close()
            {
                // TODO?
            }

            void IDisposable.Dispose()
            {
                Close();
            }
        }
    }
}


