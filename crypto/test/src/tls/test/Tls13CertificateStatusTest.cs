using System;
using System.Collections.Generic;

using NUnit.Framework;

using Org.BouncyCastle.Asn1;
using Org.BouncyCastle.Asn1.Ocsp;
using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Crypto.Operators;
using Org.BouncyCastle.Tls.Crypto;
using Org.BouncyCastle.Tls.Crypto.Impl.BC;
using Org.BouncyCastle.Utilities;
using Org.BouncyCastle.X509;

namespace Org.BouncyCastle.Tls.Tests
{
    [TestFixture]
    public class Tls13CertificateStatusTest
    {
        private static readonly string[] CertChain = new string[]{ "x509-server-rsa-sign.pem", "x509-ca-rsa.pem" };
        private static readonly string KeyResource = "x509-server-key-rsa-sign.pem";
        private static readonly string CAKeyResource = "x509-ca-key-rsa.pem";

        private static readonly int[] MustStaple = new int[]{ ExtensionType.status_request };
        private static readonly int[] MultiCertMustStaple = new int[]{ ExtensionType.status_request_v2 };

        [Test]
        public void OcspMultiIsDistributedAcrossCertificateEntries()
        {
            List<OcspResponse> ocspResponseList = new List<OcspResponse>()
            {
                CreateOcspResponse("end-entity"),
                CreateOcspResponse("intermediate"),
            };

            CertificateEntry[] certificateEntryList = RunHandshake(
                new CertificateStatus(CertificateStatusType.ocsp_multi, ocspResponseList), false);

            Assert.AreEqual(2, certificateEntryList.Length);
            Assert.AreEqual("end-entity", GetStapledMarker(certificateEntryList[0]));
            Assert.AreEqual("intermediate", GetStapledMarker(certificateEntryList[1]));
        }

        /// <summary>
        /// The ocsp shape answers for the end-entity certificate alone, as it does in the "certificate_status" message
        /// of TLS 1.2 - the rest of the chain simply goes unstapled.
        /// </summary>
        [Test]
        public void SingleOcspStatusAnswersTheEndEntityOnly()
        {
            CertificateEntry[] certificateEntryList = RunHandshake(
                new CertificateStatus(CertificateStatusType.ocsp, CreateOcspResponse("end-entity")), false);

            Assert.AreEqual(2, certificateEntryList.Length);
            Assert.AreEqual("end-entity", GetStapledMarker(certificateEntryList[0]));
            Assert.Null(GetStapledMarker(certificateEntryList[1]), "the rest of the chain should carry no staple");
        }

        /// <summary>
        /// A null status is how a server declines, and it must leave the Certificate message as it was - an entry
        /// carrying an empty extensions table would be a change in what goes on the wire.
        /// </summary>
        [Test]
        public void NoStatusLeavesTheEntriesAlone()
        {
            CertificateEntry[] certificateEntryList = RunHandshake(null, false);

            Assert.AreEqual(2, certificateEntryList.Length);
            Assert.Null(GetStapledMarker(certificateEntryList[0]));
            Assert.Null(GetStapledMarker(certificateEntryList[1]));
        }

        /// <summary>
        /// A server that attaches its own staple to the Certificate its credentials supply - the only way to do this
        /// before the callback was consulted in TLS 1.3 - keeps the extension it built, even where the callback offers
        /// a response for the same entry.
        /// </summary>
        [Test]
        public void ServerSuppliedEntryExtensionIsPreserved()
        {
            List<OcspResponse> ocspResponseList = new List<OcspResponse>()
            {
                CreateOcspResponse("from-callback"),
                CreateOcspResponse("from-callback"),
            };

            CertificateEntry[] certificateEntryList = RunHandshake(
                new CertificateStatus(CertificateStatusType.ocsp_multi, ocspResponseList), true);

            Assert.AreEqual(2, certificateEntryList.Length);
            Assert.AreEqual("from-callback", GetStapledMarker(certificateEntryList[0]));
            Assert.AreEqual("attached-by-server", GetStapledMarker(certificateEntryList[1]));
        }

        /// <summary>
        /// The read side of the same wire form: a client hands the staples back per certificate through
        /// <see cref="TlsServerCertificate.GetCertificateStatusAt(int)"/>, whichever entry each arrived in, and
        /// <see cref="TlsServerCertificate.CertificateStatus"/> answers for the end-entity certificate as it does up to
        /// TLS 1.2.
        /// </summary>
        [Test]
        public void ClientReadsAStapleForEachCertificate()
        {
            List<OcspResponse> ocspResponseList = new List<OcspResponse>()
            {
                CreateOcspResponse("end-entity"),
                CreateOcspResponse("intermediate"),
            };

            var certificateStatus = new CertificateStatus(CertificateStatusType.ocsp_multi, ocspResponseList);
            var serverCertificate = RunHandshake(certificateStatus, false, true).ServerCertificate;

            Assert.AreEqual(2, serverCertificate.Certificate.Length);
            Assert.AreEqual("end-entity", GetMarker(TlsUtilities.GetCertificateStatusAt(serverCertificate, 0)));
            Assert.AreEqual("intermediate", GetMarker(TlsUtilities.GetCertificateStatusAt(serverCertificate, 1)));
            Assert.AreEqual("end-entity", GetMarker(serverCertificate.CertificateStatus));
        }

        /// <summary>
        /// A single response answers for the end-entity certificate, so the rest of the chain reads back unstapled
        /// rather than picking up the one response that did arrive.
        /// </summary>
        [Test]
        public void ClientReadsSingleOcspAgainstTheEndEntityOnly()
        {
            var certificateStatus = new CertificateStatus(CertificateStatusType.ocsp, CreateOcspResponse("end-entity"));
            var serverCertificate = RunHandshake(certificateStatus, false, true).ServerCertificate;

            Assert.AreEqual("end-entity", GetMarker(TlsUtilities.GetCertificateStatusAt(serverCertificate, 0)));
            Assert.Null(GetMarker(TlsUtilities.GetCertificateStatusAt(serverCertificate, 1)));
            Assert.AreEqual("end-entity", GetMarker(serverCertificate.CertificateStatus));
        }

        [Test]
        public void ClientReadsNoStatusWhereNoneWasStapled()
        {
            var serverCertificate = RunHandshake(null, false, true).ServerCertificate;

            Assert.Null(serverCertificate.CertificateStatus);
            Assert.Null(TlsUtilities.GetCertificateStatusAt(serverCertificate, 0));
            Assert.Null(TlsUtilities.GetCertificateStatusAt(serverCertificate, 1));
        }

        /// <summary>
        /// An index that is not an index of Certificate names no certificate, so it has no status: null, rather than an
        /// exception, since the interface gives a caller no count to check against other than the chain's own length.
        /// </summary>
        [Test]
        public void ClientReadsNullOutsideTheChain()
        {
            List<OcspResponse> ocspResponseList = new List<OcspResponse>()
            {
                CreateOcspResponse("end-entity"),
                CreateOcspResponse("intermediate"),
            };

            var certificateStatus = new CertificateStatus(CertificateStatusType.ocsp_multi, ocspResponseList);
            var serverCertificate = RunHandshake(certificateStatus, false, true).ServerCertificate;

            int length = serverCertificate.Certificate.Length;
            Assert.AreEqual(2, length);
            Assert.Null(TlsUtilities.GetCertificateStatusAt(serverCertificate, -1));
            Assert.Null(TlsUtilities.GetCertificateStatusAt(serverCertificate, length));
            Assert.Null(TlsUtilities.GetCertificateStatusAt(serverCertificate, int.MaxValue));
        }

        /// <summary>
        /// RFC 8446 sec. 4.2: a server answers only the extensions the client sent, so a staple the client never asked
        /// for is ignored - not read, and not a reason to fail the handshake. The staple has to be attached to the
        /// Certificate by hand here, the protocol declining to consult CertificateStatus for a client that did not ask.
        /// </summary>
        [Test]
        public void ClientIgnoresAnUnsolicitedStaple()
        {
            byte[] extensionData = TlsExtensionsUtilities.CreateStatusRequestExtension13(
                new CertificateStatus(CertificateStatusType.ocsp, CreateOcspResponse("unsolicited")));

            CapturingTlsClient client = RunHandshake(null, false, false, extensionData);

            Assert.AreEqual("unsolicited", GetStapledMarker(client.CertificateEntryList[0]),
                "the staple should still have been on the wire");

            Assert.Null(client.ServerCertificate.CertificateStatus);
            Assert.Null(TlsUtilities.GetCertificateStatusAt(client.ServerCertificate, 0));
        }

        /// <summary>
        /// RFC 8446 sec. 4.4.2.1 admits only an RFC 6066 CertificateStatus of type ocsp in the extension, so anything
        /// else is a decode_error, as it is for the TLS 1.2 "certificate_status" message. A client that asked for a
        /// staple now reads what arrives, so a server that mis-staples no longer goes unnoticed.
        /// </summary>
        [Test]
        public void MalformedStapleFailsTheHandshake()
        {
            CapturingTlsClient client = new CapturingTlsClient(true);

            LoopbackResult result = RunHandshake(client, null, false, Strings.ToByteArray("not a CertificateStatus"));

            // The client's own exception is the one that says why: all the server saw was the pipe closing under it
            Exception clientFailure = result.ClientException;
            Assert.That(clientFailure is TlsFatalAlert, "client failed with " + clientFailure);
            Assert.AreEqual(AlertDescription.decode_error, ((TlsFatalAlert)clientFailure).AlertDescription);
        }

        /*
         * RFC 7633 TLS feature ("must-staple") checks. A feature listing a status request is only satisfied by an
         * actual response for the end-entity certificate: from TLS 1.3 that arrives in its CertificateEntry (never in
         * EncryptedExtensions), and up to TLS 1.2 the ServerHello echo alone is not enough, since RFC 6066 sec. 8 lets
         * a server then omit the "certificate_status" message.
         */

        /// <summary>
        /// bc-java issue #2458: RFC 8446 sec. 4.4.2.1 puts a TLS 1.3 server's staple in the CertificateEntry, so that
        /// is where a must-staple end-entity certificate has to be satisfied from.
        /// </summary>
        [Test]
        public void MustStapleIsSatisfiedByTheCertificateEntryStaple()
        {
            var client = new CapturingTlsClient(true);

            RunTlsFeatureHandshake(client, MustStaple, CreateOcspSingle("end-entity"), false).ThrowIfFailed();

            Assert.AreEqual(ProtocolVersion.TLSv13, client.NegotiatedVersion);
            Assert.AreEqual("end-entity", GetMarker(client.ServerCertificate.CertificateStatus));
        }

        [Test]
        public void MustStapleFailsWithoutAStaple()
        {
            var client = new CapturingTlsClient(true);

            LoopbackResult result = RunTlsFeatureHandshake(client, MustStaple, null, false);

            Assert.AreEqual(ProtocolVersion.TLSv13, client.NegotiatedVersion);
            AssertClientFailedWith(result, AlertDescription.certificate_unknown);
        }

        /// <summary>
        /// RFC 7633 sec. 4.3.3: a feature is only in force where the client's ClientHello offered it too.
        /// </summary>
        [Test]
        public void MustStapleIsNotInForceUnlessRequested()
        {
            var client = new CapturingTlsClient(false);

            RunTlsFeatureHandshake(client, MustStaple, null, false).ThrowIfFailed();

            Assert.AreEqual(ProtocolVersion.TLSv13, client.NegotiatedVersion);
            Assert.Null(client.ServerCertificate.CertificateStatus);
        }

        [Test]
        public void Tls12MustStapleIsSatisfiedByTheCertificateStatusMessage()
        {
            var client = new CapturingTlsClient(true) { SupportedVersions = ProtocolVersion.TLSv12.Only() };

            RunTlsFeatureHandshake(client, MustStaple, CreateOcspSingle("end-entity"), false).ThrowIfFailed();

            Assert.AreEqual(ProtocolVersion.TLSv12, client.NegotiatedVersion);
            Assert.AreEqual("end-entity", GetMarker(client.ServerCertificate.CertificateStatus));
        }

        /// <summary>
        /// The server echoes "status_request" - as AbstractTlsServer does whenever the client offered it - but, holding
        /// no status, sends no "certificate_status" message. RFC 6066 sec. 8 permits that, so the echo alone would let
        /// anyone holding the key of a revoked must-staple certificate simply not staple.
        /// </summary>
        [Test]
        public void Tls12MustStapleFailsOnAnEchoWithoutAStatus()
        {
            var client = new CapturingTlsClient(true) { SupportedVersions = ProtocolVersion.TLSv12.Only() };

            LoopbackResult result = RunTlsFeatureHandshake(client, MustStaple, null, false);

            Assert.AreEqual(ProtocolVersion.TLSv12, client.NegotiatedVersion);
            AssertClientFailedWith(result, AlertDescription.certificate_unknown);
        }

        [Test]
        public void Tls12MultiCertMustStapleIsSatisfiedByAnEndEntityResponse()
        {
            var client = new CapturingTlsClient(false)
            {
                SupportedVersions = ProtocolVersion.TLSv12.Only(),
                RequestMultiCertStatus = true,
            };

            CertificateStatus certificateStatus = CreateOcspMulti(CreateOcspResponse("end-entity"),
                CreateOcspResponse("intermediate"));

            RunTlsFeatureHandshake(client, MultiCertMustStaple, certificateStatus, true).ThrowIfFailed();

            Assert.AreEqual(ProtocolVersion.TLSv12, client.NegotiatedVersion);
            Assert.AreEqual("end-entity", GetMarker(TlsUtilities.GetCertificateStatusAt(client.ServerCertificate, 0)));
        }

        /// <summary>
        /// RFC 6961 sec. 2.2 lets an element of the list be absent, so an ocsp_multi status can arrive holding nothing
        /// for the end-entity certificate - which answers nothing for must-staple, however much it holds for the rest
        /// of the chain.
        /// </summary>
        [Test]
        public void Tls12MultiCertMustStapleFailsWithoutAnEndEntityResponse()
        {
            var client = new CapturingTlsClient(false)
            {
                SupportedVersions = ProtocolVersion.TLSv12.Only(),
                RequestMultiCertStatus = true,
            };

            CertificateStatus certificateStatus = CreateOcspMulti(null, CreateOcspResponse("intermediate"));

            LoopbackResult result = RunTlsFeatureHandshake(client, MultiCertMustStaple, certificateStatus, true);

            Assert.AreEqual(ProtocolVersion.TLSv12, client.NegotiatedVersion);
            AssertClientFailedWith(result, AlertDescription.certificate_unknown);
        }

        /// <summary>
        /// RFC 8446 sec. 4.2 has no place for "status_request_v2", so a TLS 1.3 server has no way to answer it, and the
        /// feature is not in force once TLS 1.3 is negotiated - even though a client that also offers TLS 1.2 sends it.
        /// </summary>
        [Test]
        public void MultiCertMustStapleIsNotInForceInTls13()
        {
            var client = new CapturingTlsClient(false)
            {
                SupportedVersions = ProtocolVersion.TLSv13.DownTo(ProtocolVersion.TLSv12),
                RequestMultiCertStatus = true,
            };

            RunTlsFeatureHandshake(client, MultiCertMustStaple, null, false).ThrowIfFailed();

            Assert.AreEqual(ProtocolVersion.TLSv13, client.NegotiatedVersion);
        }

        private static void AssertClientFailedWith(LoopbackResult result, short alertDescription)
        {
            Exception clientFailure = result.ClientException;
            Assert.True(clientFailure is TlsFatalAlert, "client failed with " + clientFailure);
            Assert.AreEqual(alertDescription, ((TlsFatalAlert)clientFailure).AlertDescription);
        }

        /// <summary>
        /// Drives a handshake against a server that supports TLS 1.2 and 1.3 - so the client's versions decide - and
        /// whose end-entity certificate carries a TLS feature extension listing <paramref name="tlsFeatures"/>.
        /// </summary>
        /// <param name="multiCertStatus">Have the server answer "status_request_v2".</param>
        private static LoopbackResult RunTlsFeatureHandshake(CapturingTlsClient client, int[] tlsFeatures,
            CertificateStatus certificateStatus, bool multiCertStatus)
        {
            var server = new StatusStaplingTlsServer(certificateStatus, false, null)
            {
                SupportedVersions = ProtocolVersion.TLSv13.DownTo(ProtocolVersion.TLSv12),
                TlsFeatures = tlsFeatures,
                MultiCertStatus = multiCertStatus,
            };

            return TlsLoopback.Run(client, server);
        }

        /// <param name="attachToSecondEntry">
        /// Have the server attach a staple of its own to the second entry of the Certificate its credentials supply.
        /// </param>
        /// <returns>The CertificateEntry list the client received.</returns>
        private static CertificateEntry[] RunHandshake(CertificateStatus certificateStatus, bool attachToSecondEntry) =>
            RunHandshake(certificateStatus, attachToSecondEntry, true).CertificateEntryList;

        private static CapturingTlsClient RunHandshake(CertificateStatus certificateStatus, bool attachToSecondEntry,
            bool requestStatus)
        {
            return RunHandshake(certificateStatus, attachToSecondEntry, requestStatus, null);
        }

        /// <param name="requestStatus">Have the client ask for a staple at all.</param>
        /// <param name="malformedExtension">
        /// A "status_request" extension body for the server to attach to the first entry in place of a well formed one,
        /// or null for none.
        /// </param>
        private static CapturingTlsClient RunHandshake(CertificateStatus certificateStatus, bool attachToSecondEntry,
            bool requestStatus, byte[] malformedExtension)
        {
            var capturingTlsClient = new CapturingTlsClient(requestStatus);

            RunHandshake(capturingTlsClient, certificateStatus, attachToSecondEntry, malformedExtension)
                .ThrowIfFailed();

            Assert.NotNull(capturingTlsClient.CertificateEntryList, "no server Certificate message was seen");

            return capturingTlsClient;
        }

        /// <summary>
        /// Drives a handshake with a caller-supplied client, leaving it to the caller to decide whether a failure was
        /// expected.
        /// </summary>
        private static LoopbackResult RunHandshake(CapturingTlsClient client, CertificateStatus certificateStatus,
            bool attachToSecondEntry, byte[] malformedExtension)
        {
            StatusStaplingTlsServer server = new StatusStaplingTlsServer(certificateStatus, attachToSecondEntry,
                malformedExtension);

            return TlsLoopback.Run(client, server);
        }

        /// <summary>
        /// The marker the response in this status carries, or null where there is no status. The statuses read back per
        /// certificate are always of type ocsp, a single response.
        /// </summary>
        private static string GetMarker(CertificateStatus certificateStatus)
        {
            if (null == certificateStatus)
                return null;

            Assert.AreEqual(CertificateStatusType.ocsp, certificateStatus.StatusType);

            return Strings.FromByteArray(certificateStatus.OcspResponse.ResponseBytes.Response.GetOctets());
        }

        /// <summary>
        /// The marker the entry's staple carries, or null if it carries no staple. Decodes the RFC 6066
        /// CertificateStatus by hand - a one-byte status type then the DER response in a 24-bit length field - rather
        /// than through CertificateStatus.parse, which wants a TlsContext this test has no handle on.
        /// </summary>
        private static string GetStapledMarker(CertificateEntry certificateEntry)
        {
            var extensions = certificateEntry.Extensions;
            if (null == extensions)
                return null;

            if (!extensions.TryGetValue(ExtensionType.status_request, out byte[] extensionData))
                return null;

            Assert.Greater(extensionData.Length, 4);
            Assert.AreEqual(CertificateStatusType.ocsp, extensionData[0]);

            int length = (int)extensionData[1] << 16 | extensionData[2] << 8 | extensionData[3];
            Assert.AreEqual(extensionData.Length - 4, length);

            OcspResponse ocspResponse = OcspResponse.GetInstance(Arrays.CopySegment(extensionData, 4, length));

            return Strings.FromByteArray(ocspResponse.ResponseBytes.Response.GetOctets());
        }

        /// <summary>
        /// A response whose only distinguishing feature is the marker in its responseBytes: nothing in the stapling
        /// path looks inside a response - verifying one is the receiving client's part - so this is enough to tell
        /// which entry got which.
        /// </summary>
        private static OcspResponse CreateOcspResponse(string marker)
        {
            return new OcspResponse(new OcspResponseStatus(OcspResponseStatus.Successful),
                new ResponseBytes(OcspObjectIdentifiers.PkixOcspBasic,
                DerOctetString.WithContents(Strings.ToByteArray(marker))));
        }

        private static CertificateStatus CreateOcspSingle(string marker) =>
            new CertificateStatus(CertificateStatusType.ocsp, CreateOcspResponse(marker));

        private static CertificateStatus CreateOcspMulti(params OcspResponse[] ocspResponses) =>
            new CertificateStatus(CertificateStatusType.ocsp_multi, new List<OcspResponse>(ocspResponses));

        /// <summary>
        /// The test end-entity certificate reissued by the test CA with an RFC 7633 TLS feature extension listing
        /// <paramref name="tlsFeatures"/>, and otherwise unchanged - the same key, so it still pairs with KeyResource.
        /// </summary>
        private static TlsCertificate CreateEndEntityWithTlsFeatures(TlsCrypto crypto, int[] tlsFeatures)
        {
            var tlsFeaturesVector = new Asn1EncodableVector(tlsFeatures.Length);
            foreach (int tlsFeature in tlsFeatures)
            {
                tlsFeaturesVector.Add(DerInteger.ValueOf(tlsFeature));
            }

            var generator = new X509V3CertificateGenerator(TlsTestUtilities.LoadBcCertificateResource(CertChain[0]));
            generator.AddExtension(TlsObjectIdentifiers.id_pe_tlsfeature, false, new DerSequence(tlsFeaturesVector));

            AsymmetricKeyParameter caPrivateKey = TlsTestUtilities.LoadBcPrivateKeyResource(CAKeyResource);
            X509Certificate certificate = generator.Generate(new Asn1SignatureFactory("SHA256WithRSA", caPrivateKey));

            return crypto.CreateCertificate(certificate.GetEncoded());
        }

        private static Certificate ReplaceEndEntity(Certificate certificate, TlsCertificate endEntity)
        {
            CertificateEntry[] certificateEntryList = certificate.GetCertificateEntryList();

            certificateEntryList[0] = new CertificateEntry(endEntity, certificateEntryList[0].Extensions);

            return new Certificate(certificate.GetCertificateRequestContext(), certificateEntryList);
        }

        private static Certificate AddStatusRequest(Certificate certificate, int index, OcspResponse ocspResponse)
        {
            return AddExtensionData(certificate, index, TlsExtensionsUtilities.CreateStatusRequestExtension13(
                new CertificateStatus(CertificateStatusType.ocsp, ocspResponse)));
        }

        private static Certificate AddExtensionData(Certificate certificate, int index, byte[] extensionData)
        {
            CertificateEntry[] certificateEntryList = certificate.GetCertificateEntryList();

            var extensions = new Dictionary<int, byte[]>()
            {
                { ExtensionType.status_request, extensionData },
            };

            certificateEntryList[index] = new CertificateEntry(certificateEntryList[index].Certificate, extensions);

            return new Certificate(certificate.GetCertificateRequestContext(), certificateEntryList);
        }

        private class CapturingTlsClient
            : DefaultTlsClient
        {
            private readonly bool m_requestStatus;

            internal ProtocolVersion[] SupportedVersions = ProtocolVersion.TLSv13.Only();

            /// <summary>Have the client also offer "status_request_v2" (RFC 6961), where it offers TLS 1.2.</summary>
            internal bool RequestMultiCertStatus = false;

            internal CertificateEntry[] CertificateEntryList = null;
            internal ProtocolVersion NegotiatedVersion = null;
            internal TlsServerCertificate ServerCertificate = null;

            internal CapturingTlsClient(bool requestStatus)
                : base(new BcTlsCrypto())
            {
                m_requestStatus = requestStatus;
            }

            protected override ProtocolVersion[] GetSupportedVersions() => SupportedVersions;

            protected override CertificateStatusRequest GetCertificateStatusRequest() =>
                m_requestStatus ? base.GetCertificateStatusRequest() : null;

            protected override IList<CertificateStatusRequestItemV2> GetMultiCertStatusRequest()
            {
                if (!RequestMultiCertStatus)
                    return null;

                return new List<CertificateStatusRequestItemV2>()
                {
                    new CertificateStatusRequestItemV2(CertificateStatusType.ocsp_multi,
                        new OcspStatusRequest(null, null)),
                };
            }

            public override void NotifyServerVersion(ProtocolVersion serverVersion)
            {
                base.NotifyServerVersion(serverVersion);

                NegotiatedVersion = serverVersion;
            }

            public override TlsAuthentication GetAuthentication() => new MyTlsAuthentication(this);

            internal sealed class MyTlsAuthentication
                : TlsAuthentication
            {
                private readonly CapturingTlsClient m_outer;

                internal MyTlsAuthentication(CapturingTlsClient outer)
                {
                    m_outer = outer;
                }

                public void NotifyServerCertificate(TlsServerCertificate serverCertificate)
                {
                    m_outer.ServerCertificate = serverCertificate;
                    m_outer.CertificateEntryList = serverCertificate.Certificate.GetCertificateEntryList();
                }

                public TlsCredentials GetClientCredentials(CertificateRequest certificateRequest) => null;
            }
        }

        /// <summary>
        /// Serves a two certificate chain, so that a positional list of responses has more than one entry to be spread
        /// over.
        /// </summary>
        private class StatusStaplingTlsServer
            : MockTlsServer
        {
            private readonly CertificateStatus certificateStatus;
            private readonly bool attachToSecondEntry;
            private readonly byte[] malformedExtension;

            internal StatusStaplingTlsServer(CertificateStatus certificateStatus, bool attachToSecondEntry,
                byte[] malformedExtension)
            {
                this.certificateStatus = certificateStatus;
                this.attachToSecondEntry = attachToSecondEntry;
                this.malformedExtension = malformedExtension;
            }

            /// <summary>
            /// TLS features for the end-entity certificate to list (see RFC 7633), or null to serve it unchanged.
            /// </summary>
            internal int[] TlsFeatures { get; set; } = null;

            /// <summary>Answer "status_request_v2" (RFC 6961) where the client offers it.</summary>
            internal bool MultiCertStatus { get; set; } = false;

            protected override ProtocolVersion[] GetSupportedVersions() =>
                SupportedVersions ?? ProtocolVersion.TLSv13.Only();

            protected override bool AllowMultiCertStatus() => MultiCertStatus;

            public override TlsCredentials GetCredentials()
            {
                SignatureAndHashAlgorithm signatureAndHashAlgorithm = SelectRsaSignatureAndHashAlgorithm();

                Certificate certificate = TlsTestUtilities.LoadCertificateChain(m_context, CertChain);
                if (null != TlsFeatures)
                {
                    certificate = ReplaceEndEntity(certificate,
                        CreateEndEntityWithTlsFeatures(m_context.Crypto, TlsFeatures));
                }
                if (attachToSecondEntry)
                {
                    certificate = AddStatusRequest(certificate, 1, CreateOcspResponse("attached-by-server"));
                }
                if (null != malformedExtension)
                {
                    certificate = AddExtensionData(certificate, 0, malformedExtension);
                }

                AsymmetricKeyParameter privateKey = TlsTestUtilities.LoadBcPrivateKeyResource(KeyResource);

                return new BcDefaultTlsCredentialedSigner(new TlsCryptoParameters(m_context),
                    (BcTlsCrypto)m_context.Crypto, privateKey, certificate, signatureAndHashAlgorithm);
            }

            public override CertificateStatus GetCertificateStatus() => certificateStatus;

            private SignatureAndHashAlgorithm SelectRsaSignatureAndHashAlgorithm()
            {
                var supportedSignatureAlgorithms = m_context.SecurityParameters.ClientSigAlgs;
                if (null == supportedSignatureAlgorithms)
                {
                    supportedSignatureAlgorithms = TlsUtilities.GetDefaultSignatureAlgorithms(SignatureAlgorithm.rsa);
                }

                foreach (var alg in supportedSignatureAlgorithms)
                {
                    if (SignatureAlgorithm.rsa == alg.Signature)
                        return alg;
                }

                return null;
            }
        }
    }
}
