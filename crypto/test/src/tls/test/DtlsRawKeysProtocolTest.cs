using System;
using System.Text;
using System.Threading;

using NUnit.Framework;

using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.Security;
using Org.BouncyCastle.Tls.Crypto;
using Org.BouncyCastle.Utilities;

namespace Org.BouncyCastle.Tls.Tests
{
    [TestFixture]
    public class DtlsRawKeysProtocolTest
    {
        private readonly SecureRandom Random = new SecureRandom();

        [Test]
        public void TestClientSendsExtensionButServerDoesNotSupportIt()
        {
            TestClientSendsExtensionButServerDoesNotSupportIt(ProtocolVersion.DTLSv12);
        }

        // TODO[dtls13]
        //[Test]
        //public void TestClientSendsExtensionButServerDoesNotSupportIt_13()
        //{
        //    TestClientSendsExtensionButServerDoesNotSupportIt(ProtocolVersion.DTLSv13);
        //}

        private void TestClientSendsExtensionButServerDoesNotSupportIt(ProtocolVersion tlsVersion)
        {
            MockRawKeysTlsClient client = new MockRawKeysTlsClient(CertificateType.X509, -1,
                new short[]{ CertificateType.RawPublicKey, CertificateType.X509 }, null, GenerateKeyPair(),
                tlsVersion);
            MockRawKeysTlsServer server = new MockRawKeysTlsServer(CertificateType.X509, -1, null, GenerateKeyPair(),
                tlsVersion);
            PumpData(client, server);
        }

        [Test]
        public void TestExtensionsAreOmittedIfSpecifiedButOnlyContainX509()
        {
            TestExtensionsAreOmittedIfSpecifiedButOnlyContainX509(ProtocolVersion.DTLSv12);
        }

        // TODO[dtls13]
        //[Test]
        //public void TestExtensionsAreOmittedIfSpecifiedButOnlyContainX509_13()
        //{
        //    TestExtensionsAreOmittedIfSpecifiedButOnlyContainX509(ProtocolVersion.DTLSv13);
        //}

        private void TestExtensionsAreOmittedIfSpecifiedButOnlyContainX509(ProtocolVersion tlsVersion)
        {
            MockRawKeysTlsClient client = new MockRawKeysTlsClient(CertificateType.X509, CertificateType.X509,
                new short[]{ CertificateType.X509 }, new short[]{ CertificateType.X509 }, GenerateKeyPair(),
                tlsVersion);
            MockRawKeysTlsServer server = new MockRawKeysTlsServer(CertificateType.X509, CertificateType.X509,
                new short[]{ CertificateType.X509 }, GenerateKeyPair(), tlsVersion);
            PumpData(client, server);

            Assert.IsFalse(server.m_receivedClientExtensions.ContainsKey(ExtensionType.client_certificate_type),
                "client cert type extension should not be sent");
            Assert.IsFalse(server.m_receivedClientExtensions.ContainsKey(ExtensionType.server_certificate_type),
                "server cert type extension should not be sent");
        }

        [Test]
        public void TestBothSidesUseRawKey()
        {
            TestBothSidesUseRawKey(ProtocolVersion.DTLSv12);
        }

        // TODO[dtls13]
        //[Test]
        //public void TestBothSidesUseRawKey_13()
        //{
        //    TestBothSidesUseRawKey(ProtocolVersion.DTLSv13);
        //}

        private void TestBothSidesUseRawKey(ProtocolVersion tlsVersion)
        {
            MockRawKeysTlsClient client = new MockRawKeysTlsClient(CertificateType.RawPublicKey,
                CertificateType.RawPublicKey, new short[]{ CertificateType.RawPublicKey },
                new short[]{ CertificateType.RawPublicKey }, GenerateKeyPair(), tlsVersion);
            MockRawKeysTlsServer server = new MockRawKeysTlsServer(CertificateType.RawPublicKey,
                CertificateType.RawPublicKey, new short[]{ CertificateType.RawPublicKey }, GenerateKeyPair(),
                tlsVersion);
            PumpData(client, server);
        }

        [Test]
        public void TestServerUsesRawKeyAndClientIsAnonymous()
        {
            TestServerUsesRawKeyAndClientIsAnonymous(ProtocolVersion.DTLSv12);
        }

        // TODO[dtls13]
        //[Test]
        //public void TestServerUsesRawKeyAndClientIsAnonymous_13()
        //{
        //    TestServerUsesRawKeyAndClientIsAnonymous(ProtocolVersion.DTLSv13);
        //}

        private void TestServerUsesRawKeyAndClientIsAnonymous(ProtocolVersion tlsVersion)
        {
            MockRawKeysTlsClient client = new MockRawKeysTlsClient(CertificateType.RawPublicKey, -1,
                new short[]{ CertificateType.RawPublicKey }, null, GenerateKeyPair(), tlsVersion);
            MockRawKeysTlsServer server = new MockRawKeysTlsServer(CertificateType.RawPublicKey, -1, null,
                GenerateKeyPair(), tlsVersion);
            PumpData(client, server);
        }

        [Test]
        public void TestServerUsesRawKeyAndClientUsesX509()
        {
            TestServerUsesRawKeyAndClientUsesX509(ProtocolVersion.DTLSv12);
        }

        // TODO[dtls13]
        //[Test]
        //public void TestServerUsesRawKeyAndClientUsesX509_13()
        //{
        //    TestServerUsesRawKeyAndClientUsesX509(ProtocolVersion.DTLSv13);
        //}

        private void TestServerUsesRawKeyAndClientUsesX509(ProtocolVersion tlsVersion)
        {
            MockRawKeysTlsClient client = new MockRawKeysTlsClient(CertificateType.RawPublicKey,
                CertificateType.X509, new short[]{ CertificateType.RawPublicKey }, null, GenerateKeyPair(),
                tlsVersion);
            MockRawKeysTlsServer server = new MockRawKeysTlsServer(CertificateType.RawPublicKey,
                CertificateType.X509, null, GenerateKeyPair(), tlsVersion);
            PumpData(client, server);
        }

        [Test]
        public void TestServerUsesX509AndClientUsesRawKey()
        {
            TestServerUsesX509AndClientUsesRawKey(ProtocolVersion.DTLSv12);
        }

        // TODO[dtls13]
        //[Test]
        //public void TestServerUsesX509AndClientUsesRawKey_13()
        //{
        //    TestServerUsesX509AndClientUsesRawKey(ProtocolVersion.DTLSv13);
        //}

        private void TestServerUsesX509AndClientUsesRawKey(ProtocolVersion tlsVersion)
        {
            MockRawKeysTlsClient client = new MockRawKeysTlsClient(CertificateType.X509, CertificateType.RawPublicKey,
                null, new short[]{ CertificateType.RawPublicKey }, GenerateKeyPair(), tlsVersion);
            MockRawKeysTlsServer server = new MockRawKeysTlsServer(CertificateType.X509, CertificateType.RawPublicKey,
                new short[]{ CertificateType.RawPublicKey }, GenerateKeyPair(), tlsVersion);
            PumpData(client, server);
        }

        [Test]
        public void TestClientSendsClientCertExtensionButServerHasNoCommonTypes()
        {
            TestClientSendsClientCertExtensionButServerHasNoCommonTypes(ProtocolVersion.DTLSv12);
        }

        // TODO[dtls13]
        //[Test]
        //public void TestClientSendsClientCertExtensionButServerHasNoCommonTypes_13()
        //{
        //    TestClientSendsClientCertExtensionButServerHasNoCommonTypes(ProtocolVersion.DTLSv13);
        //}

        private void TestClientSendsClientCertExtensionButServerHasNoCommonTypes(ProtocolVersion tlsVersion)
        {
            try
            {
                MockRawKeysTlsClient client = new MockRawKeysTlsClient(CertificateType.X509,
                    CertificateType.RawPublicKey, null, new short[]{ CertificateType.RawPublicKey }, GenerateKeyPair(),
                    tlsVersion);
                MockRawKeysTlsServer server = new MockRawKeysTlsServer(CertificateType.X509, CertificateType.X509,
                    new short[]{ CertificateType.X509 }, GenerateKeyPair(), tlsVersion);
                PumpData(client, server);
                Assert.Fail("Should have caused unsupported_certificate alert");
            }
            catch (TlsFatalAlertReceived alert)
            {
                Assert.AreEqual(AlertDescription.unsupported_certificate, alert.AlertDescription,
                    "Should have caused unsupported_certificate alert");
            }
        }

        [Test]
        public void TestClientSendsServerCertExtensionButServerHasNoCommonTypes()
        {
            TestClientSendsServerCertExtensionButServerHasNoCommonTypes(ProtocolVersion.DTLSv12);
        }

        // TODO[dtls13]
        //[Test]
        //public void TestClientSendsServerCertExtensionButServerHasNoCommonTypes_13()
        //{
        //    TestClientSendsServerCertExtensionButServerHasNoCommonTypes(ProtocolVersion.DTLSv13);
        //}

        private void TestClientSendsServerCertExtensionButServerHasNoCommonTypes(ProtocolVersion tlsVersion)
        {
            try
            {
                MockRawKeysTlsClient client = new MockRawKeysTlsClient(CertificateType.RawPublicKey,
                    CertificateType.RawPublicKey, new short[]{ CertificateType.RawPublicKey }, null, GenerateKeyPair(),
                    tlsVersion);
                MockRawKeysTlsServer server = new MockRawKeysTlsServer(CertificateType.X509,
                    CertificateType.RawPublicKey, new short[]{ CertificateType.RawPublicKey }, GenerateKeyPair(),
                    tlsVersion);
                PumpData(client, server);
                Assert.Fail("Should have caused unsupported_certificate alert");
            }
            catch (TlsFatalAlertReceived alert)
            {
                Assert.AreEqual(AlertDescription.unsupported_certificate, alert.AlertDescription,
                    "Should have caused unsupported_certificate alert");
            }
        }

        private Ed25519PrivateKeyParameters GenerateKeyPair() => new Ed25519PrivateKeyParameters(Random);

        private void PumpData(TlsClient client, TlsServer server)
        {
            DtlsClientProtocol clientProtocol = new DtlsClientProtocol();
            DtlsServerProtocol serverProtocol = new DtlsServerProtocol();

            MockDatagramAssociation network = new MockDatagramAssociation(1500);

            ServerTask serverTask = new ServerTask(serverProtocol, server, network.Server);

            Thread serverThread = new Thread(serverTask.Run);
            serverThread.Start();

            DatagramTransport clientTransport = network.Client;

            clientTransport = new UnreliableDatagramTransport(clientTransport, Random, 0, 0);

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
                        byte[] clientID = Encoding.UTF8.GetBytes("MockRawKeysTlsClient");

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
