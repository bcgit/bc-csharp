using System;
using System.Text;
using System.Threading;

using NUnit.Framework;

using Org.BouncyCastle.Tls.Crypto;
using Org.BouncyCastle.Utilities;

namespace Org.BouncyCastle.Tls.Tests
{
    [TestFixture]
    public class DtlsProtocolTest
    {
        [Test]
        public void TestClientServer()
        {
            MockDtlsClient client = new MockDtlsClient(null);
            MockDtlsServer server = new MockDtlsServer();

            DtlsClientProtocol clientProtocol = new DtlsClientProtocol();
            DtlsServerProtocol serverProtocol = new DtlsServerProtocol();

            MockDatagramAssociation network = new MockDatagramAssociation(1500);

            ServerTask serverTask = new ServerTask(serverProtocol, server, network.Server);

            Thread serverThread = new Thread(serverTask.Run);
            serverThread.Start();

            DatagramTransport clientTransport = network.Client;

            clientTransport = new UnreliableDatagramTransport(clientTransport, new Random(), 0, 0);

            clientTransport = new LoggingDatagramTransport(clientTransport, Console.Out);

            DtlsTransport dtlsClient = clientProtocol.Connect(client, clientTransport);

            for (int i = 1; i <= 10; ++i)
            {
                byte[] data = new byte[i];
                Arrays.Fill(data, (byte)i);
                dtlsClient.Send(data, 0, data.Length);
            }

            byte[] buf = new byte[dtlsClient.GetReceiveLimit()];
            while (dtlsClient.Receive(buf, 0, buf.Length, 100) >= 0)
            {
            }

            dtlsClient.Close();

            serverTask.Shutdown(serverThread);
        }

        internal class ServerTask
        {
            private readonly DtlsServerProtocol m_serverProtocol;
            private readonly TlsServer m_server;
            private readonly DatagramTransport m_serverTransport;
            private volatile bool m_isShutdown = false;

            internal ServerTask(DtlsServerProtocol serverProtocol, TlsServer server, DatagramTransport serverTransport)
            {
                m_serverProtocol = serverProtocol;
                m_server = server;
                m_serverTransport = serverTransport;
            }

            public void Run()
            {
                try
                {
                    TlsCrypto serverCrypto = m_server.Crypto;

                    DtlsRequest request = null;

                    // Use DtlsVerifier to require a HelloVerifyRequest cookie exchange before accepting
                    {
                        DtlsVerifier verifier = new DtlsVerifier(serverCrypto);

                        // NOTE: Test value only - would typically be the client IP address
                        byte[] clientID = Encoding.UTF8.GetBytes("MockDtlsClient");

                        int receiveLimit = m_serverTransport.GetReceiveLimit();
                        int dummyOffset = serverCrypto.SecureRandom.Next(16) + 1;
                        byte[] buf = new byte[dummyOffset + m_serverTransport.GetReceiveLimit()];

                        do
                        {
                            if (m_isShutdown)
                                return;

                            int length = m_serverTransport.Receive(buf, dummyOffset, receiveLimit, 100);
                            if (length > 0)
                            {
                                request = verifier.VerifyRequest(clientID, buf, dummyOffset, length, m_serverTransport);
                            }
                        }
                        while (request == null);
                    }

                    // NOTE: A real server would handle each DtlsRequest in a new task/thread and continue accepting
                    {
                        DtlsTransport dtlsTransport = m_serverProtocol.Accept(m_server, m_serverTransport, request);
                        byte[] buf = new byte[dtlsTransport.GetReceiveLimit()];
                        while (!m_isShutdown)
                        {
                            int length = dtlsTransport.Receive(buf, 0, buf.Length, 100);
                            if (length >= 0)
                            {
                                dtlsTransport.Send(buf, 0, length);
                            }
                        }
                        dtlsTransport.Close();
                    }
                }
                catch (Exception e)
                {
                    Console.Error.WriteLine(e);
                    Console.Error.Flush();
                }
            }

            internal void Shutdown(Thread serverThread)
            {
                if (!m_isShutdown)
                {
                    m_isShutdown = true;
                    serverThread.Join();
                }
            }
        }
    }
}
