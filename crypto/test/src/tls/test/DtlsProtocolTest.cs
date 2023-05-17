using System;
using System.Text;
using System.Threading;

using NUnit.Framework;

using Org.BouncyCastle.Security;
using Org.BouncyCastle.Utilities;

namespace Org.BouncyCastle.Tls.Tests
{
    [TestFixture]
    public class DtlsProtocolTest
    {
        [Test]
        public void TestClientServer()
        {
            SecureRandom secureRandom = new SecureRandom();

            DtlsClientProtocol clientProtocol = new DtlsClientProtocol();
            DtlsServerProtocol serverProtocol = new DtlsServerProtocol();

            MockDatagramAssociation network = new MockDatagramAssociation(1500);

            Server server = new Server(serverProtocol, network.Server);

            Thread serverThread = new Thread(new ThreadStart(server.Run));
            serverThread.Start();

            DatagramTransport clientTransport = network.Client;

            clientTransport = new UnreliableDatagramTransport(clientTransport, secureRandom, 0, 0);

            clientTransport = new LoggingDatagramTransport(clientTransport, Console.Out);

            MockDtlsClient client = new MockDtlsClient(null);

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

            server.Shutdown(serverThread);
        }

        internal class Server
        {
            private readonly DtlsServerProtocol m_serverProtocol;
            private readonly DatagramTransport m_serverTransport;
            private volatile bool m_isShutdown = false;

            internal Server(DtlsServerProtocol serverProtocol, DatagramTransport serverTransport)
            {
                this.m_serverProtocol = serverProtocol;
                this.m_serverTransport = serverTransport;
            }

            public void Run()
            {
                try
                {
                    MockDtlsServer server = new MockDtlsServer();

                    DtlsRequest request = null;

                    // Use DtlsVerifier to require a HelloVerifyRequest cookie exchange before accepting
                    {
                        DtlsVerifier verifier = new DtlsVerifier(server.Crypto);

                        // NOTE: Test value only - would typically be the client IP address
                        byte[] clientID = Encoding.UTF8.GetBytes("MockDtlsClient");

                        int receiveLimit = m_serverTransport.GetReceiveLimit();
                        int dummyOffset = server.Crypto.SecureRandom.Next(16) + 1;
                        byte[] transportBuf = new byte[dummyOffset + m_serverTransport.GetReceiveLimit()];

                        do
                        {
                            if (m_isShutdown)
                                return;

                            int length = m_serverTransport.Receive(transportBuf, dummyOffset, receiveLimit, 1000);
                            if (length > 0)
                            {
                                request = verifier.VerifyRequest(clientID, transportBuf, dummyOffset, length,
                                    m_serverTransport);
                            }
                        }
                        while (request == null);
                    }

                    DtlsTransport dtlsServer = m_serverProtocol.Accept(server, m_serverTransport, request);
                    byte[] buf = new byte[dtlsServer.GetReceiveLimit()];
                    while (!m_isShutdown)
                    {
                        int length = dtlsServer.Receive(buf, 0, buf.Length, 1000);
                        if (length >= 0)
                        {
                            dtlsServer.Send(buf, 0, length);
                        }
                    }
                    dtlsServer.Close();
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
                    this.m_isShutdown = true;
                    serverThread.Join();
                }
            }
        }
    }
}
