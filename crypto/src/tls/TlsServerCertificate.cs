using System;

namespace Org.BouncyCastle.Tls
{
    /// <summary>Server certificate carrier interface.</summary>
    // TODO[api] Turn this into a concrete sealed class (record)
    public interface TlsServerCertificate
    {
        /// <summary>Gets the certificate chain of the server.</summary>
        Certificate Certificate { get; }

        /// <summary>
        /// The OCSP status the server stapled for the end-entity certificate, or null if it stapled none.
        /// </summary>
        /// <remarks>
        /// Up to TLS 1.2 this is the "certificate_status" message the server sent (RFC 6066 sec. 8), which is of type
        /// ocsp_multi when the client asked with "status_request_v2" (RFC 6961 sec. 2.2), in which case the responses
        /// after the first answer for the rest of the chain and
        /// <see cref="TlsUtilities.GetCertificateStatusAt(TlsServerCertificate, int)"/> reaches them. From TLS 1.3
        /// there is no such message - each response rides in a "status_request" extension of the CertificateEntry
        /// carrying the certificate it answers for (RFC 8446 sec. 4.4.2.1) - and this is the one from the first entry,
        /// of type ocsp; use <see cref="TlsUtilities.GetCertificateStatusAt(TlsServerCertificate, int)"/> for the
        /// others.
        /// </remarks>
        /// <returns>
        /// The status answering for the end-entity certificate, or null.
        /// </returns>
        CertificateStatus CertificateStatus { get; }

        // TODO[api]
        /*
        /// <summary>
        /// The OCSP status the server stapled for certificate <paramref name="index"/> of <see cref="Certificate"/>, or
        /// null if it stapled none for that certificate. This reads the same way whichever version was negotiated, so a
        /// caller that pairs responses with the certificates they answer for does not have to know where they arrived
        /// from.
        /// </summary>
        /// <remarks>
        /// A status returned here is always of type ocsp, a single response answering for a single certificate: in TLS
        /// 1.3 that is what a CertificateEntry's extension carries, and up to TLS 1.2 the ocsp_multi list of a
        /// "certificate_status" message is positional in the same way (RFC 6961 sec. 2.2 - the list may be shorter than
        /// the chain, and an element may be absent where no response is held).
        /// </remarks>
        /// <param name="index">
        /// The index into <see cref="Certificate"/> of the certificate in question.
        /// </param>
        /// <returns>
        /// The status answering for that certificate, or null - also where <paramref name="index"/> is not an index of
        /// <see cref="Certificate"/>, since no certificate there has a status.
        /// </returns>
        CertificateStatus GetCertificateStatusAt(int index);
        */
    }
}
