using System;
using System.Threading;

using NUnit.Framework;

using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.Security;
using Org.BouncyCastle.Utilities;
using Org.BouncyCastle.Utilities.IO;

namespace Org.BouncyCastle.Tls.Tests
{
    [TestFixture]
    public class TlsRawKeysProtocolTest
    {
        private readonly SecureRandom Random = new SecureRandom();

        [Test]
        public void TestClientSendsExtensionButServerDoesNotSupportIt()
        {
            TestClientSendsExtensionButServerDoesNotSupportIt(ProtocolVersion.TLSv12);
        }

        [Test]
        public void TestClientSendsExtensionButServerDoesNotSupportIt_13()
        {
            TestClientSendsExtensionButServerDoesNotSupportIt(ProtocolVersion.TLSv13);
        }

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
            TestExtensionsAreOmittedIfSpecifiedButOnlyContainX509(ProtocolVersion.TLSv12);
        }

        [Test]
        public void TestExtensionsAreOmittedIfSpecifiedButOnlyContainX509_13()
        {
            TestExtensionsAreOmittedIfSpecifiedButOnlyContainX509(ProtocolVersion.TLSv13);
        }

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
            TestBothSidesUseRawKey(ProtocolVersion.TLSv12);
        }

        [Test]
        public void TestBothSidesUseRawKey_13()
        {
            TestBothSidesUseRawKey(ProtocolVersion.TLSv13);
        }

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
            TestServerUsesRawKeyAndClientIsAnonymous(ProtocolVersion.TLSv12);
        }

        [Test]
        public void TestServerUsesRawKeyAndClientIsAnonymous_13()
        {
            TestServerUsesRawKeyAndClientIsAnonymous(ProtocolVersion.TLSv13);
        }

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
            TestServerUsesRawKeyAndClientUsesX509(ProtocolVersion.TLSv12);
        }

        [Test]
        public void TestServerUsesRawKeyAndClientUsesX509_13()
        {
            TestServerUsesRawKeyAndClientUsesX509(ProtocolVersion.TLSv13);
        }

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
            TestServerUsesX509AndClientUsesRawKey(ProtocolVersion.TLSv12);
        }

        [Test]
        public void TestServerUsesX509AndClientUsesRawKey_13()
        {
            TestServerUsesX509AndClientUsesRawKey(ProtocolVersion.TLSv13);
        }

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
            TestClientSendsClientCertExtensionButServerHasNoCommonTypes(ProtocolVersion.TLSv12);
        }

        [Test]
        public void TestClientSendsClientCertExtensionButServerHasNoCommonTypes_13()
        {
            TestClientSendsClientCertExtensionButServerHasNoCommonTypes(ProtocolVersion.TLSv13);
        }

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
            TestClientSendsServerCertExtensionButServerHasNoCommonTypes(ProtocolVersion.TLSv12);
        }

        [Test]
        public void TestClientSendsServerCertExtensionButServerHasNoCommonTypes_13()
        {
            TestClientSendsServerCertExtensionButServerHasNoCommonTypes(ProtocolVersion.TLSv13);
        }

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

        private Ed25519PrivateKeyParameters GenerateKeyPair()
        {
            return new Ed25519PrivateKeyParameters(Random);
        }

        private void PumpData(TlsClient client, TlsServer server)
        {
            PipedStream clientPipe = new PipedStream();
            PipedStream serverPipe = new PipedStream(clientPipe);

            TlsClientProtocol clientProtocol = new TlsClientProtocol(clientPipe);
            TlsServerProtocol serverProtocol = new TlsServerProtocol(serverPipe);

            ServerTask serverTask = new ServerTask(serverProtocol, server);

            Thread serverThread = new Thread(serverTask.Run);
            serverThread.Start();

            clientProtocol.Connect(client);

            // NOTE: Because we write-all before we read-any, this length can't be more than the pipe capacity
            int length = 1000;

            byte[] data = new byte[length];
            Random.NextBytes(data);

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
