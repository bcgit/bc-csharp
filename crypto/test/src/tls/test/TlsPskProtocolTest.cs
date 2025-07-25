using System;
using System.Threading;

using NUnit.Framework;

using Org.BouncyCastle.Utilities;
using Org.BouncyCastle.Utilities.IO;

namespace Org.BouncyCastle.Tls.Tests
{
    [TestFixture]
    public class TlsPskProtocolTest
    {
        [Test]
        public void BadClientKey()
        {
            MockPskTlsClient client = new MockPskTlsClient(null, badKey: true);
            MockPskTlsServer server = new MockPskTlsServer();

            ImplTestKeyMismatch(client, server);
        }

        [Test]
        public void BadServerKey()
        {
            MockPskTlsClient client = new MockPskTlsClient(null);
            MockPskTlsServer server = new MockPskTlsServer(badKey: true);

            ImplTestKeyMismatch(client, server);
        }

        [Test]
        public void TestClientServer()
        {
            MockPskTlsClient client = new MockPskTlsClient(null);
            MockPskTlsServer server = new MockPskTlsServer();

            PipedStream clientPipe = new PipedStream();
            PipedStream serverPipe = new PipedStream(clientPipe);

            TlsClientProtocol clientProtocol = new TlsClientProtocol(clientPipe);
            TlsServerProtocol serverProtocol = new TlsServerProtocol(serverPipe);

            ServerTask serverTask = new ServerTask(serverProtocol, server);

            Thread serverThread = new Thread(serverTask.Run);
            serverThread.Start();

            clientProtocol.Connect(client);

            byte[] data = new byte[1000];
            client.Crypto.SecureRandom.NextBytes(data);

            using (var stream = clientProtocol.Stream)
            {
                stream.Write(data, 0, data.Length);

                byte[] echo = new byte[data.Length];
                int count = Streams.ReadFully(stream, echo);

                Assert.AreEqual(count, data.Length);
                Assert.IsTrue(Arrays.AreEqual(data, echo));
            }

            serverThread.Join();
        }

        private void ImplTestKeyMismatch(MockPskTlsClient client, MockPskTlsServer server)
        {
            PipedStream clientPipe = new PipedStream();
            PipedStream serverPipe = new PipedStream(clientPipe);

            TlsClientProtocol clientProtocol = new TlsClientProtocol(clientPipe);
            TlsServerProtocol serverProtocol = new TlsServerProtocol(serverPipe);

            ServerTask serverTask = new ServerTask(serverProtocol, server);

            Thread serverThread = new Thread(serverTask.Run);
            serverThread.Start();

            bool correctException = false;
            short alertDescription = -1;

            try
            {
                clientProtocol.Connect(client);
            }
            catch (TlsFatalAlertReceived e)
            {
                correctException = true;
                alertDescription = e.AlertDescription;
            }
            catch (Exception)
            {
            }
            finally
            {
                clientProtocol.Close();
            }

            serverThread.Join();

            Assert.True(correctException);
            Assert.AreEqual(AlertDescription.bad_record_mac, alertDescription);
        }

        internal class ServerTask
        {
            private readonly TlsServerProtocol m_serverProtocol;
            private readonly TlsServer m_server;

            internal ServerTask(TlsServerProtocol serverProtocol, TlsServer server)
            {
                m_serverProtocol = serverProtocol;
                m_server = server;
            }

            public void Run()
            {
                try
                {
                    m_serverProtocol.Accept(m_server);

                    using (var stream = m_serverProtocol.Stream)
                    {
                        Streams.PipeAll(stream, stream);
                    }
                }
                catch (Exception)
                {
                }
            }
        }
    }
}
