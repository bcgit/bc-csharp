using NUnit.Framework;

using Org.BouncyCastle.Security;
using Org.BouncyCastle.Tls.Crypto;
using Org.BouncyCastle.Tls.Crypto.Impl.BC;

namespace Org.BouncyCastle.Tls.Tests
{
    [TestFixture]
    public class TlsRawKeysProtocolTest
    {
        protected readonly SecureRandom Random = new SecureRandom();

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
            MockRawKeysTlsClient client = new MockRawKeysTlsClient(CreateCrypto(), CertificateType.X509, -1,
                new short[]{ CertificateType.RawPublicKey, CertificateType.X509 }, null, tlsVersion);
            MockRawKeysTlsServer server = new MockRawKeysTlsServer(CreateCrypto(), CertificateType.X509, -1, null,
                tlsVersion);

            TlsLoopback.Run(client, server).ThrowIfFailed();
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
            MockRawKeysTlsClient client = new MockRawKeysTlsClient(CreateCrypto(), CertificateType.X509,
                CertificateType.X509, new short[]{ CertificateType.X509 }, new short[]{ CertificateType.X509 },
                tlsVersion);
            MockRawKeysTlsServer server = new MockRawKeysTlsServer(CreateCrypto(), CertificateType.X509,
                CertificateType.X509, new short[]{ CertificateType.X509 }, tlsVersion);

            TlsLoopback.Run(client, server).ThrowIfFailed();

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
            MockRawKeysTlsClient client = new MockRawKeysTlsClient(CreateCrypto(), CertificateType.RawPublicKey,
                CertificateType.RawPublicKey, new short[]{ CertificateType.RawPublicKey },
                new short[]{ CertificateType.RawPublicKey }, tlsVersion);
            MockRawKeysTlsServer server = new MockRawKeysTlsServer(CreateCrypto(), CertificateType.RawPublicKey,
                CertificateType.RawPublicKey, new short[]{ CertificateType.RawPublicKey }, tlsVersion);

            TlsLoopback.Run(client, server).ThrowIfFailed();
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
            MockRawKeysTlsClient client = new MockRawKeysTlsClient(CreateCrypto(), CertificateType.RawPublicKey, -1,
                new short[]{ CertificateType.RawPublicKey }, null, tlsVersion);
            MockRawKeysTlsServer server = new MockRawKeysTlsServer(CreateCrypto(), CertificateType.RawPublicKey, -1,
                null, tlsVersion);

            TlsLoopback.Run(client, server).ThrowIfFailed();
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
            MockRawKeysTlsClient client = new MockRawKeysTlsClient(CreateCrypto(), CertificateType.RawPublicKey,
                CertificateType.X509, new short[]{ CertificateType.RawPublicKey }, null, tlsVersion);
            MockRawKeysTlsServer server = new MockRawKeysTlsServer(CreateCrypto(), CertificateType.RawPublicKey,
                CertificateType.X509, null, tlsVersion);

            TlsLoopback.Run(client, server).ThrowIfFailed();
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
            MockRawKeysTlsClient client = new MockRawKeysTlsClient(CreateCrypto(), CertificateType.X509,
                CertificateType.RawPublicKey, null, new short[]{ CertificateType.RawPublicKey }, tlsVersion);
            MockRawKeysTlsServer server = new MockRawKeysTlsServer(CreateCrypto(), CertificateType.X509,
                CertificateType.RawPublicKey, new short[]{ CertificateType.RawPublicKey }, tlsVersion);

            TlsLoopback.Run(client, server).ThrowIfFailed();
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
            MockRawKeysTlsClient client = new MockRawKeysTlsClient(CreateCrypto(), CertificateType.X509,
                CertificateType.RawPublicKey, null, new short[]{ CertificateType.RawPublicKey }, tlsVersion);
            MockRawKeysTlsServer server = new MockRawKeysTlsServer(CreateCrypto(), CertificateType.X509,
                CertificateType.X509, new short[]{ CertificateType.X509 }, tlsVersion);

            TlsLoopback.Run(client, server).AssertClientReceivedFatalAlert(AlertDescription.unsupported_certificate);
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
            MockRawKeysTlsClient client = new MockRawKeysTlsClient(CreateCrypto(), CertificateType.RawPublicKey,
                CertificateType.RawPublicKey, new short[]{ CertificateType.RawPublicKey }, null, tlsVersion);
            MockRawKeysTlsServer server = new MockRawKeysTlsServer(CreateCrypto(), CertificateType.X509,
                CertificateType.RawPublicKey, new short[]{ CertificateType.RawPublicKey }, tlsVersion);

            TlsLoopback.Run(client, server).AssertClientReceivedFatalAlert(AlertDescription.unsupported_certificate);
        }

        protected virtual TlsCrypto CreateCrypto() => new BcTlsCrypto(Random);
    }
}
