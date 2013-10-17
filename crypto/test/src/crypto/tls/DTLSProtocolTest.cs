using Org.BouncyCastle.Utilities.Test;
using Org.BouncyCastle.Security;
using System;
using System.Threading;
using Org.BouncyCastle.Utilities;

namespace Org.BouncyCastle.Crypto.Tls.Test
{
    public class DTLSProtocolTest : SimpleTest
    {
        public void TestClientServer()
        {
            SecureRandom secureRandom = new SecureRandom();

            DTLSClientProtocol clientProtocol = new DTLSClientProtocol(secureRandom);
            DTLSServerProtocol serverProtocol = new DTLSServerProtocol(secureRandom);

            MockDatagramAssociation network = new MockDatagramAssociation(1500);

            ServerThread serverThread = new ServerThread(serverProtocol, network.Server);
            serverThread.Start();

            DatagramTransport clientTransport = network.Client;

            clientTransport = new UnreliableDatagramTransport(clientTransport, secureRandom, 0, 0);

            clientTransport = new LoggingDatagramTransport(clientTransport, Console.Out);

            MockDTLSClient client = new MockDTLSClient(null);
            DTLSTransport dtlsClient = clientProtocol.Connect(client, clientTransport);

            for (int i = 1; i <= network.Server.ReceiveLimit; ++i)
            {
                byte[] data = new byte[i];
                Arrays.Fill(data, (byte)i);
                dtlsClient.Send(data, 0, data.Length);
            }

            byte[] buf = new byte[dtlsClient.ReceiveLimit];
            while (dtlsClient.Receive(buf, 0, buf.Length, 1000) >= 0)
            {
                ;
            }

            dtlsClient.Close();

            serverThread.Shutdown();
        }

        private class ServerThread
        {
            private readonly DTLSServerProtocol serverProtocol;
            private readonly DatagramTransport serverTransport;
            private volatile bool isShutdown = false;
            private Thread thread;

            public ServerThread(DTLSServerProtocol serverProtocol, DatagramTransport serverTransport)
            {
                this.serverProtocol = serverProtocol;
                this.serverTransport = serverTransport;
                this.thread = new Thread(Run);
            }

            public void Start()
            {
                this.thread.Start();
            }

            public void Run()
            {
                try
                {
                    MockDTLSServer server = new MockDTLSServer();
                    DTLSTransport dtlsServer = serverProtocol.Accept(server, serverTransport);
                    byte[] buf = new byte[dtlsServer.ReceiveLimit];
                    while (!isShutdown)
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
                    Console.WriteLine(e.StackTrace);
                }
            }

            public void Shutdown()
            {
                if (!isShutdown)
                {
                    isShutdown = true;
                    this.thread.Join();
                }
            }
        }

        public override string Name
        {
            get { return "DTLSProtocolTest"; }
        }

        public override void PerformTest()
        {
            TestClientServer();
        }
    }
}