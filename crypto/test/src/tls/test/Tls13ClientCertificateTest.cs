using System;
using System.Collections.Generic;

using NUnit.Framework;

using Org.BouncyCastle.Asn1;
using Org.BouncyCastle.Asn1.Ocsp;
using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Tls.Crypto;
using Org.BouncyCastle.Tls.Crypto.Impl.BC;
using Org.BouncyCastle.Utilities;

namespace Org.BouncyCastle.Tls.Tests
{
    /// <summary>
    /// What a TLS 1.3 server requires of the client's Certificate message beyond the certificates themselves (RFC 8446
    /// sec. 4.4.2): the certificate_request_context of the CertificateRequest it answers, and extensions that
    /// correspond to ones in that CertificateRequest.
    /// </summary>
    [TestFixture]
    public class Tls13ClientCertificateTest
    {
        private static readonly string[] ClientCertChain = new string[]{ "x509-client-rsa.pem" };
        private static readonly string ClientKeyResource = "x509-client-key-rsa.pem";

        [Test]
        public void PlainClientCertificateIsAccepted()
        {
            var client = new ClientCertificateTlsClient(TlsUtilities.EmptyBytes, null);

            TlsLoopback.Run(client, CreateServer()).ThrowIfFailed();

            Assert.AreEqual(ProtocolVersion.TLSv13, client.NegotiatedVersion);
        }

        /// <summary>
        /// RFC 8446 sec. 4.4.2: a Certificate answering a CertificateRequest carries that CertificateRequest's
        /// certificate_request_context, which is empty for one sent during the handshake.
        /// </summary>
        [Test]
        public void MismatchedCertificateRequestContextIsRejected()
        {
            var client = new ClientCertificateTlsClient(new byte[]{ 0x01 }, null);

            LoopbackResult result = TlsLoopback.Run(client, CreateServer());

            AssertServerFailedWith(result, AlertDescription.illegal_parameter);
        }

        /// <summary>
        /// RFC 8446 sec. 4.4.2: extensions in a client's Certificate must correspond to ones in the CertificateRequest,
        /// and this server's asks for no staple.
        /// </summary>
        [Test]
        public void UnrequestedEntryExtensionIsRejected()
        {
            byte[] extensionData = TlsExtensionsUtilities.CreateStatusRequestExtension13(
                new CertificateStatus(CertificateStatusType.ocsp, CreateOcspResponse()));

            var endEntityExtensions = new Dictionary<int, byte[]>()
            {
                { ExtensionType.status_request, extensionData },
            };

            var client = new ClientCertificateTlsClient(TlsUtilities.EmptyBytes, endEntityExtensions);

            LoopbackResult result = TlsLoopback.Run(client, CreateServer());

            AssertServerFailedWith(result, AlertDescription.unsupported_extension);
        }

        private static void AssertServerFailedWith(LoopbackResult result, short alertDescription)
        {
            Exception serverFailure = result.ServerException;
            Assert.True(serverFailure is TlsFatalAlert, "server failed with " + serverFailure);
            Assert.AreEqual(alertDescription, ((TlsFatalAlert)serverFailure).AlertDescription);
        }

        private static MockTlsServer CreateServer() =>
            new MockTlsServer(){ SupportedVersions = ProtocolVersion.TLSv13.Only() };

        private static OcspResponse CreateOcspResponse()
        {
            return new OcspResponse(new OcspResponseStatus(OcspResponseStatus.Successful),
                new ResponseBytes(OcspObjectIdentifiers.PkixOcspBasic,
                DerOctetString.WithContents(Strings.ToByteArray("client-staple"))));
        }

        /// <summary>
        /// Answers the server's CertificateRequest with the RSA test client certificate, sent with the given
        /// certificate_request_context and extensions on its (only) CertificateEntry.
        /// </summary>
        private class ClientCertificateTlsClient
            : MockTlsClient
        {
            private readonly byte[] m_certificateRequestContext;
            private readonly IDictionary<int, byte[]> m_endEntityExtensions;

            internal ClientCertificateTlsClient(byte[] certificateRequestContext,
                IDictionary<int, byte[]> endEntityExtensions)
                : base(null)
            {
                m_certificateRequestContext = certificateRequestContext;
                m_endEntityExtensions = endEntityExtensions;

                SupportedVersions = ProtocolVersion.TLSv13.Only();
            }

            protected override TlsCredentials SelectClientCredentials(CertificateRequest certificateRequest)
            {
                CertificateEntry[] certificateEntryList = TlsTestUtilities.LoadCertificateChain(m_context,
                    ClientCertChain).GetCertificateEntryList();

                certificateEntryList[0] = new CertificateEntry(certificateEntryList[0].Certificate,
                    m_endEntityExtensions);

                Certificate certificate = new Certificate(m_certificateRequestContext, certificateEntryList);

                AsymmetricKeyParameter privateKey = TlsTestUtilities.LoadBcPrivateKeyResource(ClientKeyResource);

                return new BcDefaultTlsCredentialedSigner(new TlsCryptoParameters(m_context),
                    (BcTlsCrypto)m_context.Crypto, privateKey, certificate,
                    SignatureAndHashAlgorithm.rsa_pss_rsae_sha256);
            }
        }
    }
}
