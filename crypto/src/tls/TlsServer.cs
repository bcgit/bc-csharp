using System;
using System.Collections.Generic;
using System.IO;

using Org.BouncyCastle.Tls.Crypto;

namespace Org.BouncyCastle.Tls
{
    /// <summary>Interface describing a TLS server endpoint.</summary>
    public interface TlsServer
        : TlsPeer
    {
        // TODO[api]
        //bool PreferLocalSupportedGroups();

        void Init(TlsServerContext context);

        /// <summary>Return the specified session, if available.</summary>
        /// <remarks>
        /// Note that the peer's certificate chain for the session (if any) may need to be periodically revalidated.
        /// </remarks>
        /// <param name="sessionID">the ID of the session to resume.</param>
        /// <returns>A <see cref="TlsSession"/> with the specified session ID, or null.</returns>
        /// <seealso cref="SessionParameters.PeerCertificate"/>
        TlsSession GetSessionToResume(byte[] sessionID);

        /// <summary>Return the new session ID.</summary>
        byte[] GetNewSessionID();

        /// <summary>Return the <see cref="TlsPskExternal">external PSK</see> to select from the ClientHello.</summary>
        /// <remarks>
        /// WARNING: EXPERIMENTAL FEATURE, UNSTABLE API
        /// Note that this will only be called when TLS 1.3 or higher is amongst the offered protocol versions, and one
        /// or more PSKs are actually offered.
        /// </remarks>
        /// <param name="identities">an <see cref="IList{T}"/> of <see cref="PskIdentity"/> instances.</param>
        /// <returns>The <see cref="TlsPskExternal"/> corresponding to the selected identity, or null to not select
        /// any.</returns>
        TlsPskExternal GetExternalPsk(IList<PskIdentity> identities);

        void NotifySession(TlsSession session);

        /// <exception cref="IOException"/>
        void NotifyClientVersion(ProtocolVersion clientVersion);

        /// <exception cref="IOException"/>
        void NotifyFallback(bool isFallback);

        /// <exception cref="IOException"/>
        void NotifyOfferedCipherSuites(int[] offeredCipherSuites);

        /// <param name="clientExtensions">(Int32 -> byte[])</param>
        /// <exception cref="IOException"/>
        void ProcessClientExtensions(IDictionary<int, byte[]> clientExtensions);

        /// <exception cref="IOException"/>
        ProtocolVersion GetServerVersion();

        /// <exception cref="IOException"/>
        int[] GetSupportedGroups();

        /// <exception cref="IOException"/>
        int GetSelectedCipherSuite();

        /// <returns>(Int32 -> byte[])</returns>
        /// <exception cref="IOException"/>
        IDictionary<int, byte[]> GetServerExtensions();

        /// <param name="serverExtensions">(Int32 -> byte[])</param>
        /// <exception cref="IOException"/>
        void GetServerExtensionsForConnection(IDictionary<int, byte[]> serverExtensions);

        /// <returns>(SupplementalDataEntry)</returns>
        /// <exception cref="IOException"/>
        IList<SupplementalDataEntry> GetServerSupplementalData();

        /// <summary>Return server credentials to use.</summary>
        /// <remarks>
        /// The returned value may be null, or else it MUST implement <em>exactly one</em> of
        /// <see cref="TlsCredentialedAgreement"/>, <see cref="TlsCredentialedDecryptor"/>, or
        /// <see cref = "TlsCredentialedSigner"/>, depending on the key exchange that was negotiated.
        /// </remarks>
        /// <returns>a <see cref="TlsCredentials"/> object or null for anonymous key exchanges.</returns>
        /// <exception cref="IOException"/>
        TlsCredentials GetCredentials();

        /// <summary>
        /// This method will be called (only) if <see cref="SecurityParameters.StatusRequestVersion"/> is non-zero,
        /// meaning the client asked for a stapled response and the server undertook to answer: up to(D)TLS 1.2, that it
        /// echoed an extension of type "status_request" (<i>RFC 6066 sec. 8. Certificate Status Request</i>) or
        /// "status_request_v2" (<i>RFC 6961 sec. 2.2. Multiple Certificate Status Request Record</i>) with empty
        /// "extension_data" in the extended server hello; in TLS 1.3, simply that the client offered "status_request".
        /// </summary>
        /// <remarks>
        /// If a non-null <see cref="CertificateStatus"/> is returned, it is sent to the client as a handshake message
        /// of type "certificate_status".
        /// <para>
        /// The status request version says which of the two shapes the client will accept; returning the other one is a
        /// fatal alert at the client:
        /// <list type="bullet">
        /// <item><b>1</b> - "status_request" was echoed. Return a <see cref="CertificateStatusType.ocsp"/> status
        /// carrying a single response, for the end-entity certificate.</item>
        /// <item><b>2</b> - "status_request_v2" was echoed. Return a <see cref="CertificateStatusType.ocsp_multi"/>
        /// status carrying one entry per certificate in the chain that was sent, in the same order, with a null entry
        /// wherever no response is available.</item>
        /// </list>
        /// </para>
        /// <para>
        /// Whether either extension is echoed at all up to (D)TLS 1.2 is decided by
        /// <see cref="AbstractTlsServer.AllowCertificateStatus"/> (defaults to <c>true</c>) and
        /// <see cref="AbstractTlsServer.AllowMultiCertStatus"/> (defaults to <c>false</c>).
        /// </para>
        /// <para>
        /// How the returned status reaches the client depends on the negotiated version. Up to (D) TLS 1.2 it is sent
        /// as a handshake message of type "certificate_status", for the whole chain at once. In TLS 1.3 there is no
        /// such message: the response travels in a "status_request" extension of the <see cref="CertificateEntry"/>
        /// containing the certificate it answers for (<i>RFC 8446 sec. 4.4.2.1</i>), and the protocol distributes what
        /// this callback returns across those entries - an <see cref="CertificateStatusType.ocsp"/> status answering
        /// for the end-entity certificate, an <see cref="CertificateStatusType.ocsp_multi"/> status answering
        /// positionally, entry <c>i</c> of its list for certificate <c>i</c> of the chain. So a TLS 1.3 server with a
        /// response for more than the end-entity certificate returns the ocsp_multi shape even though the status
        /// request version is 1. An entry the server has itself given a "status_request" extension - by attaching it to
        /// the <see cref="Certificate"/> its credentials supply, which was previously the only way to staple in TLS 1.3
        /// - is left as it stands.
        /// </para>
        /// </remarks>
        /// <returns>A <see cref="CertificateStatus"/> to be sent to the client (or null for none).</returns>
        /// <exception cref="IOException"/>
        CertificateStatus GetCertificateStatus();

        /// <exception cref="IOException"/>
        CertificateRequest GetCertificateRequest();

        /// <exception cref="IOException"/>
        TlsPskIdentityManager GetPskIdentityManager();

        /// <exception cref="IOException"/>
        TlsSrpLoginParameters GetSrpLoginParameters();

        /// <exception cref="IOException"/>
        TlsDHConfig GetDHConfig();

        /// <exception cref="IOException"/>
        TlsECConfig GetECDHConfig();

        /// <param name="clientSupplementalData">(SupplementalDataEntry)</param>
        /// <exception cref="IOException"/>
        void ProcessClientSupplementalData(IList<SupplementalDataEntry> clientSupplementalData);

        /// <summary>Called by the protocol handler to report the client certificate, only if
        /// <see cref="GetCertificateRequest"/> returned non-null.</summary>
        /// <remarks>
        /// Note: this method is responsible for certificate verification and validation.
        /// </remarks>
        /// <param name="clientCertificate">the effective client certificate (may be an empty chain).</param>
        /// <exception cref="IOException"/>
        void NotifyClientCertificate(Certificate clientCertificate);

        /// <summary>RFC 5077 3.3. NewSessionTicket Handshake Message.</summary>
        /// <remarks>
        /// This method will be called (only) if a NewSessionTicket extension was sent by the server. See <i>RFC 5077
        /// 4. Recommended Ticket Construction</i> for recommended format and protection.
        /// </remarks>
        /// <returns>The ticket.</returns>
        /// <exception cref="IOException"/>
        NewSessionTicket GetNewSessionTicket();
    }
}
