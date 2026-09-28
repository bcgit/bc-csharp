using System;
using System.Collections.Generic;

using NUnit.Framework;

using Org.BouncyCastle.Asn1;
using Org.BouncyCastle.Math;
using Org.BouncyCastle.Tls.Crypto;
using Org.BouncyCastle.Tls.Crypto.Impl.BC;
using Org.BouncyCastle.Utilities;

namespace Org.BouncyCastle.Tls.Tests
{
    /// <summary>
    /// How <see cref="TlsUtilities.CheckTlsFeatures"/> handles the RFC 7633 id-pe-tlsfeature certificate extension,
    /// driven directly rather than through a handshake.
    /// </summary>
    [TestFixture]
    public class CheckTlsFeaturesExtensionTest
    {
        /// <summary>
        /// A top-level object other than a SEQUENCE (here an INTEGER) is rejected with a fatal alert.
        /// </summary>
        [Test]
        public void NonSequenceTlsFeaturesRejected()
        {
            // An id-pe-tlsfeature extension whose content is an INTEGER, not the RFC 7633 SEQUENCE OF INTEGER
            byte[] nonSequence = DerInteger.ValueOf(5).GetEncoded(Asn1Encodable.Der);

            Certificate serverCertificate = MakeCertificate(nonSequence);

            var noExtensions = new Dictionary<int, byte[]>();

            TlsFatalAlert e = Assert.Throws<TlsFatalAlert>(
                () => CheckTlsFeatures(serverCertificate, noExtensions, noExtensions));

            Assert.AreEqual(AlertDescription.bad_certificate, e.AlertDescription);
            // TlsFatalAlert prefixes the alert text; the detail message is appended after "; "
            Assert.True(e.Message.EndsWith("Server certificate has invalid TLS Features extension"), e.Message);
        }

        /// <summary>
        /// A well-formed SEQUENCE OF INTEGER passes where the client offered none of its features, so that nothing is
        /// in force.
        /// </summary>
        [Test]
        public void ValidTlsFeaturesAccepted()
        {
            byte[] tlsFeatures = new DerSequence(DerInteger.ValueOf(5)).GetEncoded(Asn1Encodable.Der);

            Certificate serverCertificate = MakeCertificate(tlsFeatures);

            CheckTlsFeatures(serverCertificate, new Dictionary<int, byte[]>(), new Dictionary<int, byte[]>());
        }

        [Test]
        public void NoTlsFeaturesExtension()
        {
            Certificate serverCertificate = MakeCertificate(null);

            CheckTlsFeatures(serverCertificate, new Dictionary<int, byte[]>(), new Dictionary<int, byte[]>());
        }

        /// <summary>
        /// A (D)TLS 1.2 ServerHello may carry no extensions at all, leaving the server extensions null. A feature in
        /// force is then simply unsatisfied, and must fail with an alert rather than a NullReferenceException.
        /// </summary>
        [Test]
        public void FeatureUnsatisfiedByAbsentServerExtensions()
        {
            byte[] tlsFeatures = new DerSequence(DerInteger.ValueOf(ExtensionType.status_request))
                .GetEncoded(Asn1Encodable.Der);

            Certificate serverCertificate = MakeCertificate(tlsFeatures);

            var clientExtensions = new Dictionary<int, byte[]>();
            TlsExtensionsUtilities.AddStatusRequestExtension(clientExtensions,
                new CertificateStatusRequest(CertificateStatusType.ocsp, new OcspStatusRequest(null, null)));

            TlsFatalAlert e = Assert.Throws<TlsFatalAlert>(
                () => CheckTlsFeatures(serverCertificate, clientExtensions, null));

            Assert.AreEqual(AlertDescription.certificate_unknown, e.AlertDescription);
        }

        /// <summary>Runs the check as a (D)TLS 1.2 client would, for a server that stapled nothing.</summary>
        private static void CheckTlsFeatures(Certificate serverCertificate, IDictionary<int, byte[]> clientExtensions,
            IDictionary<int, byte[]> serverExtensions)
        {
            BcTlsCrypto crypto = new BcTlsCrypto();

            TlsClientContextImpl clientContext = new TlsClientContextImpl(crypto);
            clientContext.HandshakeBeginning(new StubTlsClient(crypto));
            clientContext.SecurityParameters.m_negotiatedVersion = ProtocolVersion.TLSv12;

            TlsServerCertificate tlsServerCertificate = new TlsServerCertificateImpl(serverCertificate, null,
                new CertificateStatus[serverCertificate.Length]);

            TlsUtilities.CheckTlsFeatures(clientContext, tlsServerCertificate, clientExtensions, serverExtensions);
        }

        private static Certificate MakeCertificate(byte[] tlsFeaturesExtensionContent) =>
            new Certificate(new TlsCertificate[]{ new StubTlsCertificate(tlsFeaturesExtensionContent) });

        private class StubTlsClient
            : DefaultTlsClient
        {
            internal StubTlsClient(TlsCrypto crypto)
                : base(crypto)
            {
            }

            public override TlsAuthentication GetAuthentication() => throw new NotSupportedException();
        }

        /// <summary>
        /// Answers <see cref="GetExtension"/> for the id-pe-tlsfeature OID only; nothing else is used by
        /// <see cref="TlsUtilities.CheckTlsFeatures"/>.
        /// </summary>
        private class StubTlsCertificate
            : TlsCertificate
        {
            private readonly byte[] m_tlsFeaturesExtensionContent;

            internal StubTlsCertificate(byte[] tlsFeaturesExtensionContent)
            {
                m_tlsFeaturesExtensionContent = tlsFeaturesExtensionContent;
            }

            public TlsEncryptor CreateEncryptor(int tlsCertificateRole) => throw new NotSupportedException();

            public TlsVerifier CreateVerifier(short signatureAlgorithm) => throw new NotSupportedException();

            public Tls13Verifier CreateVerifier(int signatureScheme) => throw new NotSupportedException();

            public byte[] GetEncoded() => throw new NotSupportedException();

            public byte[] GetExtension(DerObjectIdentifier extensionOid) =>
                TlsObjectIdentifiers.id_pe_tlsfeature.Equals(extensionOid)
                    ? Arrays.Clone(m_tlsFeaturesExtensionContent)
                    : null;

            public BigInteger SerialNumber => throw new NotSupportedException();

            public string SigAlgOid => throw new NotSupportedException();

            public Asn1Encodable GetSigAlgParams() => throw new NotSupportedException();

            public short GetLegacySignatureAlgorithm() => throw new NotSupportedException();

            public bool SupportsSignatureAlgorithm(short signatureAlgorithm) => throw new NotSupportedException();

            public bool SupportsSignatureAlgorithmCA(short signatureAlgorithm) => throw new NotSupportedException();

            public TlsCertificate CheckUsageInRole(int tlsCertificateRole) => throw new NotSupportedException();
        }
    }
}
