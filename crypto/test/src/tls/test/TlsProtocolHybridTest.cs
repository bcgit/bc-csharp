using System;
using System.IO;
using System.Threading;

using NUnit.Framework;

using Org.BouncyCastle.Utilities;
using Org.BouncyCastle.Utilities.IO;

namespace Org.BouncyCastle.Tls.Tests
{
    [TestFixture]
    public class TlsProtocolHybridTest
    {
        // mismatched hybrid groups w/o non-hybrids
        [Test]
        public void TestMismatchedGroups()
        {
            PipedStream clientPipe = new PipedStream();
            PipedStream serverPipe = new PipedStream(clientPipe);

            TlsClientProtocol clientProtocol = new TlsClientProtocol(clientPipe);
            TlsServerProtocol serverProtocol = new TlsServerProtocol(serverPipe);

            MockTlsHybridClient client = new MockTlsHybridClient(null);
            MockTlsHybridServer server = new MockTlsHybridServer();

            client.SetNamedGroups(new int[]{ NamedGroup.SecP256r1MLKEM768 });
            server.SetNamedGroups(new int[]{ NamedGroup.X25519MLKEM768 });

            ServerTask serverTask = new ServerTask(serverProtocol, server, shouldFail: true);
            Thread serverThread = new Thread(serverTask.Run);
            try
            {
                serverThread.Start();
            }
            catch (Exception)
            {
            }

            try
            {
                clientProtocol.Connect(client);
                Assert.Fail();
            }
            catch (Exception)
            {
            }

            serverThread.Join();
        }

        [Test]
        public void TestSecP256r1MLKEM768()
        {
            ImplTestClientServer(NamedGroup.SecP256r1MLKEM768);
        }

        [Test]
        public void TestSecP384r1MLKEM1024()
        {
            ImplTestClientServer(NamedGroup.SecP384r1MLKEM1024);
        }

        [Test]
        public void TestX25519MLKEM768()
        {
            ImplTestClientServer(NamedGroup.X25519MLKEM768);
        }

        private void ImplTestClientServer(int hybridGroup)
        {
            PipedStream clientPipe = new PipedStream();
            PipedStream serverPipe = new PipedStream(clientPipe);

            TlsClientProtocol clientProtocol = new TlsClientProtocol(clientPipe);
            TlsServerProtocol serverProtocol = new TlsServerProtocol(serverPipe);

            MockTlsHybridClient client = new MockTlsHybridClient(null);
            MockTlsHybridServer server = new MockTlsHybridServer();

            client.SetNamedGroups(new int[]{ hybridGroup });
            server.SetNamedGroups(new int[]{ hybridGroup });

            ServerTask serverTask = new ServerTask(serverProtocol, server, shouldFail: false);
            Thread serverThread = new Thread(serverTask.Run);
            serverThread.Start();

            clientProtocol.Connect(client);

            byte[] data = new byte[1000];
            client.Crypto.SecureRandom.NextBytes(data);

            Stream output = clientProtocol.Stream;
            output.Write(data, 0, data.Length);

            byte[] echo = new byte[data.Length];
            int count = Streams.ReadFully(clientProtocol.Stream, echo);

            Assert.AreEqual(count, data.Length);
            Assert.IsTrue(Arrays.AreEqual(data, echo));

            output.Close();

            serverThread.Join();
        }

        internal class ServerTask
        {
            private readonly TlsServerProtocol m_serverProtocol;
            private readonly TlsServer m_server;
            private readonly bool m_shouldFail;

            internal ServerTask(TlsServerProtocol serverProtocol, TlsServer server, bool shouldFail)
            {
                m_serverProtocol = serverProtocol;
                m_server = server;
                m_shouldFail = shouldFail;
            }

            public void Run()
            {
                try
                {
                    try
                    {
                        m_serverProtocol.Accept(m_server);
                        if (m_shouldFail)
                        {
                            Assert.Fail();
                        }

                        using (var stream = m_serverProtocol.Stream)
                        {
                            Streams.PipeAll(stream, stream);
                        }
                    }
                    catch (IOException)
                    {
                        if (!m_shouldFail)
                        {
                            Assert.Fail();
                        }
                    }

                    m_serverProtocol.Close();
                }
                catch (Exception)
                {
                }
            }
        }
    }
}
