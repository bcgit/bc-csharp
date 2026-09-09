using System;
using System.Collections.Generic;

using NUnit.Framework;

using Org.BouncyCastle.Asn1;
using Org.BouncyCastle.Asn1.Ocsp;
using Org.BouncyCastle.Math;
using Org.BouncyCastle.Tls.Crypto;
using Org.BouncyCastle.Utilities;

namespace Org.BouncyCastle.Tls.Tests
{
    /// <summary>
    /// How <see cref="TlsUtilities.SpreadCertificateStatus(Certificate, CertificateStatus)"/> reads a
    /// "certificate_status" message out per certificate, which is what lets
    /// <see cref="TlsUtilities.GetCertificateStatusAt(TlsServerCertificate, int)"/> answer the same way up to TLS 1.2
    /// as it does for the per-CertificateEntry extensions of TLS 1.3.
    /// </summary>
    /// <remarks>
    /// The ocsp shape answers for the end-entity certificate alone (RFC 6066 sec. 8) and the ocsp_multi shape answers
    /// positionally, its list possibly shorter than the chain and possibly with an absent element where no response is
    /// held(RFC 6961 sec. 2.2).
    /// </remarks>
    [TestFixture]
    public class SpreadCertificateStatusTest
    {
        [Test]
        public void OcspAnswersForTheEndEntityOnly()
        {
            CertificateStatus[] result = TlsUtilities.SpreadCertificateStatus(CreateCertificate(2),
                new CertificateStatus(CertificateStatusType.ocsp, CreateOcspResponse("end-entity")));

            Assert.AreEqual(2, result.Length);
            Assert.AreEqual("end-entity", MarkerOf(result[0]));
            Assert.Null(result[1], "the rest of the chain is unanswered for");
        }

        [Test]
        public void OcspMultiAnswersPositionally()
        {
            CertificateStatus[] result = TlsUtilities.SpreadCertificateStatus(CreateCertificate(3),
                CreateOcspMulti(new OcspResponse[]{
                    CreateOcspResponse("end-entity"),
                    CreateOcspResponse("intermediate"),
                    CreateOcspResponse("root") }));

            Assert.AreEqual(3, result.Length);
            Assert.AreEqual("end-entity", MarkerOf(result[0]));
            Assert.AreEqual("intermediate", MarkerOf(result[1]));
            Assert.AreEqual("root", MarkerOf(result[2]));
        }

        /// <summary>
        /// RFC 6961 sec. 2.2: the list "MAY be shorter than the number of certificates" - the certificates it does not
        /// reach are simply unstapled.
        /// </summary>
        [Test]
        public void ShortOcspMultiLeavesTheRestUnanswered()
        {
            CertificateStatus[] result = TlsUtilities.SpreadCertificateStatus(CreateCertificate(3),
                CreateOcspMulti(new OcspResponse[]{ CreateOcspResponse("end-entity") }));

            Assert.AreEqual(3, result.Length);
            Assert.AreEqual("end-entity", MarkerOf(result[0]));
            Assert.Null(result[1]);
            Assert.Null(result[2]);
        }

        /// <summary>
        /// An absent element answers for nothing rather than being handed on as a status carrying no response, which is
        /// what <see cref="CertificateStatus.OcspResponseList"/> admits and what a responder that holds a response for
        /// the end-entity but not its issuer produces.
        /// </summary>
        [Test]
        public void AbsentOcspMultiElementIsNotAStatus()
        {
            CertificateStatus[] result = TlsUtilities.SpreadCertificateStatus(CreateCertificate(2),
                CreateOcspMulti(new OcspResponse[]{ null, CreateOcspResponse("intermediate") }));

            Assert.Null(result[0]);
            Assert.AreEqual("intermediate", MarkerOf(result[1]));
        }

        /// <summary>
        /// More responses than there are certificates - which a BC server never sends, Add13CertificateStatus
        /// refusing to - must not read past the chain.
        /// </summary>
        [Test]
        public void LongOcspMultiIsTrimmedToTheChain()
        {
            CertificateStatus[] result = TlsUtilities.SpreadCertificateStatus(CreateCertificate(1),
                CreateOcspMulti(new OcspResponse[]{
                    CreateOcspResponse("end-entity"),
                    CreateOcspResponse("intermediate") }));

            Assert.AreEqual(1, result.Length);
            Assert.AreEqual("end-entity", MarkerOf(result[0]));
        }

        [Test]
        public void NoStatusAnswersForNothing()
        {
            CertificateStatus[] result = TlsUtilities.SpreadCertificateStatus(CreateCertificate(2), null);

            Assert.AreEqual(2, result.Length);
            Assert.Null(result[0]);
            Assert.Null(result[1]);
        }

        /// <summary>
        /// A status where there is no chain to spread it over: the result is empty rather than an exception, so that
        /// <see cref="TlsServerCertificate.CertificateStatus"/> reading element zero of it has something to test.
        /// </summary>
        [Test]
        public void EmptyChainTakesNoStatus()
        {
            CertificateStatus[] result = TlsUtilities.SpreadCertificateStatus(CreateCertificate(0),
                new CertificateStatus(CertificateStatusType.ocsp, CreateOcspResponse("end-entity")));

            Assert.AreEqual(0, result.Length);
        }

        /// <summary>
        /// Every status read out per certificate is a single response, whichever shape it arrived in - the contract
        /// <see cref="TlsUtilities.GetCertificateStatusAt(TlsServerCertificate, int)"/> states.
        /// </summary>
        private static string MarkerOf(CertificateStatus certificateStatus)
        {
            Assert.AreEqual(CertificateStatusType.ocsp, certificateStatus.StatusType);

            return Strings.FromByteArray(certificateStatus.OcspResponse.ResponseBytes.Response.GetOctets());
        }

        private static Certificate CreateCertificate(int count)
        {
            CertificateEntry[] certificateEntryList = new CertificateEntry[count];
            for (int i = 0; i < count; ++i)
            {
                certificateEntryList[i] = new CertificateEntry(new StubTlsCertificate(), null);
            }

            return new Certificate(CertificateType.X509, TlsUtilities.EmptyBytes, certificateEntryList);
        }

        private static CertificateStatus CreateOcspMulti(OcspResponse[] ocspResponses) =>
            new CertificateStatus(CertificateStatusType.ocsp_multi, new List<OcspResponse>(ocspResponses));

        /// <summary>
        /// A response whose only distinguishing feature is the marker in its responseBytes: nothing here looks inside
        /// one, so this is enough to tell which certificate got which.
        /// </summary>
        private static OcspResponse CreateOcspResponse(string marker)
        {
            return new OcspResponse(new OcspResponseStatus(OcspResponseStatus.Successful),
                new ResponseBytes(OcspObjectIdentifiers.PkixOcspBasic,
                    DerOctetString.WithContents(Strings.ToByteArray(marker))));
        }

        /// <summary>
        /// SpreadCertificateStatus only ever counts the certificates, so a stand-in keeps the test off the crypto
        /// layer and its key material.
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
