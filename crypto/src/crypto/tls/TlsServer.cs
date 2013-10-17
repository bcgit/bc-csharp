using System.Collections;

namespace Org.BouncyCastle.Crypto.Tls
{

    public interface TlsServer : TlsPeer
    {
        void Init(TlsServerContext context);

        void NotifyClientVersion(ProtocolVersion clientVersion);

        void NotifyOfferedCipherSuites(CipherSuite[] offeredCipherSuites);

        void NotifyOfferedCompressionMethods(CompressionMethod[] offeredCompressionMethods);

        // Hashtable is (Integer -> byte[])
        void ProcessClientExtensions(IDictionary clientExtensions);

        ProtocolVersion ServerVersion { get; }

        CipherSuite SelectedCipherSuite { get; }

        CompressionMethod SelectedCompressionMethod { get; }

        // Hashtable is (Integer -> byte[])
        IDictionary GetServerExtensions();

        // IList is (SupplementalDataEntry)
        IList GetServerSupplementalData();

        TlsCredentials Credentials { get; }

        /**
         * This method will be called (only) if the server included an extension of type
         * "status_request" with empty "extension_data" in the extended server hello. See <i>RFC 3546
         * 3.6. Certificate Status Request</i>. If a non-null {@link CertificateStatus} is returned, it
         * is sent to the client as a handshake message of type "certificate_status".
         * 
         * @return A {@link CertificateStatus} to be sent to the client (or null for none).
         * @throws IOException
         */
        CertificateStatus CertificateStatus { get; }

        TlsKeyExchange GetKeyExchange();

        CertificateRequest GetCertificateRequest();

        // IList is (SupplementalDataEntry)
        void ProcessClientSupplementalData(IList clientSupplementalData);

        /**
         * Called by the protocol handler to report the client certificate, only if
         * {@link #GetCertificateRequest()} returned non-null.
         * 
         * Note: this method is responsible for certificate verification and validation.
         * 
         * @param clientCertificate
         *            the effective client certificate (may be an empty chain).
         * @throws IOException
         */
        void NotifyClientCertificate(Certificate clientCertificate);

        /**
         * RFC 5077 3.3. NewSessionTicket Handshake Message.
         * <p/>
         * This method will be called (only) if a NewSessionTicket extension was sent by the server. See
         * <i>RFC 5077 4. Recommended Ticket Construction</i> for recommended format and protection.
         *
         * @return The ticket.
         * @throws IOException
         */
        NewSessionTicket GetNewSessionTicket();
    }
}

