using System;
using System.Collections.Generic;

using NUnit.Framework;

using Org.BouncyCastle.Asn1;
using Org.BouncyCastle.Asn1.Ocsp;
using Org.BouncyCastle.Math;
using Org.BouncyCastle.Tls.Crypto;

namespace Org.BouncyCastle.Tls.Tests
{
    /// <summary>
    /// How <see cref="TlsUtilities.Add13CertificateStatus(Certificate, CertificateStatus)"/> distributes a server's
    /// OCSP staples over the CertificateEntry extensions of RFC 8446 sec. 4.4.2.1, and what it does with a response the
    /// entry cannot carry.
    /// </summary>
    /// <remarks>
    /// <see cref="Certificate.Encode"/> writes an entry's whole extensions block with a 16-bit length, so a large
    /// enough response overflows it. Nothing bounds an OCSP response to a size that rules this out - a responder
    /// chooses what it sends, and may include a certificate chain of its own - so the response that does not fit has to
    /// be dropped.Letting it through fails the handshake at encode time, which would make an oversized staple worse
    /// than no staple at all.
    /// </remarks>
    [TestFixture]
    public class Add13CertificateStatusTest
    {
        /// <summary>
        /// The largest response an otherwise extension-free entry can carry: the entry's extensions block is written
        /// with <see cref="TlsUtilities.WriteOpaque16(byte[], System.IO.Stream)"/>, and this extension costs four bytes
        /// of type and length plus a CertificateStatus body of a status type and an opaque24 length ahead of the
        /// response itself.
        /// </summary>
        private const int MaxDerLength = 65535 - 4 - 1 - 3;

        [Test]
        public void StapleIsAttachedToEveryEntryAnsweredFor()
        {
            Certificate certificate = CreateCertificate(2, null);

            Certificate result = TlsUtilities.Add13CertificateStatus(certificate,
                CreateOcspMulti(new OcspResponse[]{ CreateOcspResponse(64), CreateOcspResponse(64) }));

            Assert.AreNotSame(certificate, result, "a new Certificate should have been built");
            Assert.NotNull(StapleOf(result, 0));
            Assert.NotNull(StapleOf(result, 1));
        }

        /// <summary>
        /// The boundary itself is carried, so the guard is a limit rather than a margin.
        /// </summary>
        [Test]
        public void LargestCarryableResponseIsStapled()
        {
            Certificate certificate = CreateCertificate(1, null);

            Certificate result = TlsUtilities.Add13CertificateStatus(certificate,
                CreateOcspSingle(CreateOcspResponseOfEncodedLength(MaxDerLength)));

            Assert.NotNull(StapleOf(result, 0), "the largest response that fits should be stapled");
        }

        /// <summary>
        /// One byte over, and the staple is dropped - not turned into a fatal alert from Certificate.Encode.
        /// </summary>
        [Test]
        public void OversizedResponseIsDroppedRatherThanFatal()
        {
            Certificate certificate = CreateCertificate(1, null);

            Certificate result = TlsUtilities.Add13CertificateStatus(certificate,
                CreateOcspSingle(CreateOcspResponseOfEncodedLength(MaxDerLength + 1)));

            Assert.AreSame(certificate, result, "with nothing stapled the original Certificate should come back");
            Assert.Null(StapleOf(result, 0));

            // the real point: what comes back is encodable, where the unguarded form overflowed here
            AssertEntryIsEncodable(result, 0);
        }

        /// <summary>
        /// An oversized response for one certificate does not cost the rest of the chain its staples.
        /// </summary>
        [Test]
        public void OversizedResponseDoesNotSuppressTheOthers()
        {
            Certificate certificate = CreateCertificate(2, null);

            Certificate result = TlsUtilities.Add13CertificateStatus(certificate,
                CreateOcspMulti(new OcspResponse[]{ CreateOcspResponseOfEncodedLength(MaxDerLength + 1),
                    CreateOcspResponse(64) }));

            Assert.Null(StapleOf(result, 0), "the oversized response should have been dropped");
            Assert.NotNull(StapleOf(result, 1), "the response that fits should still be stapled");
            AssertEntryIsEncodable(result, 0);
            AssertEntryIsEncodable(result, 1);
        }

        /// <summary>
        /// An extension the server attached itself takes up room in the same block, so the limit is on what is left
        /// rather than on the response alone.
        /// </summary>
        [Test]
        public void ExistingExtensionsCountTowardTheLimit()
        {
            var existing = new Dictionary<int, byte[]>();
            existing[ExtensionType.signed_certificate_timestamp] = new byte[1024];

            Certificate certificate = CreateCertificate(1, existing);

            Certificate result = TlsUtilities.Add13CertificateStatus(certificate,
                CreateOcspSingle(CreateOcspResponseOfEncodedLength(MaxDerLength - 1024 - 4)));

            Assert.NotNull(StapleOf(result, 0),
                "a response that fits alongside the existing extension should be stapled");
            AssertEntryIsEncodable(result, 0);

            Certificate tooBig = TlsUtilities.Add13CertificateStatus(CreateCertificate(1, existing),
                CreateOcspSingle(CreateOcspResponseOfEncodedLength(MaxDerLength - 1024 - 4 + 1)));

            Assert.Null(StapleOf(tooBig, 0), "the existing extension should have left no room for one byte more");
            AssertEntryIsEncodable(tooBig, 0);
        }

        private static byte[] StapleOf(Certificate certificate, int index)
        {
            var extensions = certificate.GetCertificateEntryAt(index).Extensions;
            if (extensions != null && extensions.TryGetValue(ExtensionType.status_request, out byte[] extensionData))
                return extensionData;

            return null;
        }

        /// <summary>
        /// The constraint <see cref="Certificate.Encode(TlsContext, System.IO.Stream, System.IO.Stream)"/> applies: it
        /// builds each entry's extensions block with
        /// <see cref="TlsProtocol.WriteExtensionsData(IDictionary{int, byte[]})"/> and writes it with
        /// <see cref="TlsUtilities.WriteOpaque16(byte[], System.IO.Stream)"/>, so a block that is not a valid uint16 is
        /// a fatal alert there.
        /// </summary>
        /// <remarks>
        /// Asserted directly rather than by encoding, which would need a negotiated TLS 1.3 context.
        /// </remarks>
        private static void AssertEntryIsEncodable(Certificate certificate, int index)
        {
            var extensions = certificate.GetCertificateEntryAt(index).Extensions;

            int length = null == extensions ? 0 : TlsProtocol.WriteExtensionsData(extensions).Length;

            Assert.That(TlsUtilities.IsValidUint16(length),
                "the entry's extensions block does not fit the 16-bit length Certificate.Encode writes: " + length);
        }

        private static Certificate CreateCertificate(int count, IDictionary<int, byte[]> extensions)
        {
            CertificateEntry[] certificateEntryList = new CertificateEntry[count];
            for (int i = 0; i < count; ++i)
            {
                certificateEntryList[i] = new CertificateEntry(new StubTlsCertificate(),
                    null == extensions ? null : new Dictionary<int, byte[]>(extensions));
            }

            return new Certificate(CertificateType.X509, TlsUtilities.EmptyBytes, certificateEntryList);
        }

        private static CertificateStatus CreateOcspSingle(OcspResponse ocspResponse) =>
            new CertificateStatus(CertificateStatusType.ocsp, ocspResponse);

        private static CertificateStatus CreateOcspMulti(OcspResponse[] ocspResponses) =>
            new CertificateStatus(CertificateStatusType.ocsp_multi, new List<OcspResponse>(ocspResponses));

        private static OcspResponse CreateOcspResponse(int payloadLength)
        {
            return new OcspResponse(new OcspResponseStatus(OcspResponseStatus.Successful),
                new ResponseBytes(OcspObjectIdentifiers.PkixOcspBasic,
                DerOctetString.WithContents(new byte[payloadLength])));
        }

        /// <summary>
        /// A response encoding to exactly <paramref name="derLength"/> bytes, so a test can sit on the limit rather
        /// than guess at it.
        /// </summary>
        /// <remarks>
        /// The ASN.1 framing is a fixed overhead once the payload is long enough for its length to take three bytes, so
        /// correcting the payload by the shortfall converges at once; the loop is there only to make that an assertion
        /// rather than an assumption.
        /// </remarks>
        private static OcspResponse CreateOcspResponseOfEncodedLength(int derLength)
        {
            int payloadLength = derLength;

            for (int i = 0; i < 4; ++i)
            {
                OcspResponse ocspResponse = CreateOcspResponse(payloadLength);

                int actual = ocspResponse.GetEncoded(Asn1Encodable.Der).Length;
                if (actual == derLength)
                    return ocspResponse;

                payloadLength += derLength - actual;
            }

            throw new InvalidOperationException("unable to build an OCSPResponse of length " + derLength);
        }

        /// <summary>
        /// <see cref="TlsUtilities.Add13CertificateStatus(Certificate, CertificateStatus)"/> only ever carries the
        /// certificate from one entry to the next, so a stand-in keeps the test off the crypto layer and its key
        /// material.
        /// </summary>
        private class StubTlsCertificate
            : TlsCertificate
        {
            public TlsEncryptor CreateEncryptor(int tlsCertificateRole) => throw new NotSupportedException();

            public TlsVerifier CreateVerifier(short signatureAlgorithm) => throw new NotSupportedException();

            public Tls13Verifier CreateVerifier(int signatureScheme) => throw new NotSupportedException();

            public byte[] GetEncoded() => new byte[]{ 0x30, 0x00 };

            public byte[] GetExtension(DerObjectIdentifier extensionOid) => null;

            public BigInteger SerialNumber => BigInteger.Zero;

            public string SigAlgOid => throw new NotSupportedException();

            public Asn1Encodable GetSigAlgParams() => throw new NotSupportedException();

            public short GetLegacySignatureAlgorithm() => throw new NotSupportedException();

            public bool SupportsSignatureAlgorithm(short signatureAlgorithm) => throw new NotSupportedException();

            public bool SupportsSignatureAlgorithmCA(short signatureAlgorithm) => throw new NotSupportedException();

            public TlsCertificate CheckUsageInRole(int tlsCertificateRole) => throw new NotSupportedException();
        }
    }
}
