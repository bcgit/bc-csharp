using System;
using System.Collections;
using System.IO;

namespace Org.BouncyCastle.Crypto.Tls
{
    public interface TlsClient : TlsPeer
    {
        /**
         * Return the session this client wants to resume, if any. Note that the peer's certificate
         * chain for the session (if any) may need to be periodically revalidated.
         * 
         * @return A {@link TlsSession} representing the resumable session to be used for this
         *         connection, or null to use a new session.
         * @see SessionParameters#getPeerCertificate()
         */
        TlsSession SessionToResume
        {
            get;
        }

        ProtocolVersion ClientHelloRecordLayerVersion
        {
            get;
        }

        ProtocolVersion ClientVersion
        {
            get;
        }

        /// <summary>
        /// Get the list of cipher suites that this client supports.
        /// </summary>
        /// <returns>
        /// An array of <see cref="CipherSuite"/>, each specifying a supported cipher suite.
        /// </returns>
        CipherSuite[] GetCipherSuites();

        /// <summary>
        /// Called at the start of a new TLS session, before any other methods.
        /// </summary>
        /// <param name="context">
        /// A <see cref="TlsProtocolHandler"/>
        /// </param>
        void Init(TlsClientContext context);


        void NotifyServerVersion(ProtocolVersion selectedVersion);

        /// <summary>
        /// Get the list of compression methods that this client supports.
        /// </summary>
        /// <returns>
        /// An array of <see cref="CompressionMethod"/>, each specifying a supported compression method.
        /// </returns>
        CompressionMethod[] GetCompressionMethods();

        /// <summary>
        /// Get the (optional) table of client extensions to be included in (extended) client hello.
        /// </summary>
        /// <returns>
        /// A <see cref="IDictionary"/> (<see cref="ExtensionType"/> -> byte[]). May be null.
        /// </returns>
        /// <exception cref="IOException"></exception>
        IDictionary GetClientExtensions();

        /// <summary>
        /// Reports the session ID once it has been determined.
        /// </summary>
        /// <param name="sessionID">
        /// A <see cref="System.Byte"/>
        /// </param>
        void NotifySessionID(byte[] sessionID);

        /// <summary>
        /// Report the cipher suite that was selected by the server.
        /// </summary>
        /// <remarks>
        /// The protocol handler validates this value against the offered cipher suites
        /// <seealso cref="GetCipherSuites"/>
        /// </remarks>
        /// <param name="selectedCipherSuite">
        /// A <see cref="CipherSuite"/>
        /// </param>
        void NotifySelectedCipherSuite(CipherSuite selectedCipherSuite);

        /// <summary>
        /// Report the compression method that was selected by the server.
        /// </summary>
        /// <remarks>
        /// The protocol handler validates this value against the offered compression methods
        /// <seealso cref="GetCompressionMethods"/>
        /// </remarks>
        /// <param name="selectedCompressionMethod">
        /// A <see cref="CompressionMethod"/>
        /// </param>
        void NotifySelectedCompressionMethod(CompressionMethod selectedCompressionMethod);

        // Vector is (SupplementalDataEntry)
        void ProcessServerSupplementalData(IList serverSupplementalData);

        /// <summary>
        /// Report the extensions from an extended server hello.
        /// </summary>
        /// <remarks>
        /// Will only be called if we returned a non-null result from <see cref="GetClientExtensions"/>.
        /// </remarks>
        /// <param name="serverExtensions">
        /// A <see cref="IDictionary"/>  (<see cref="ExtensionType"/> -> byte[])
        /// </param>
        void ProcessServerExtensions(IDictionary serverExtensions);

        /// <summary>
        /// Return an implementation of <see cref="TlsKeyExchange"/> to negotiate the key exchange
        /// part of the protocol.
        /// </summary>
        /// <returns>
        /// A <see cref="TlsKeyExchange"/>
        /// </returns>
        /// <exception cref="IOException"/>
        TlsKeyExchange GetKeyExchange();

        /// <summary>
        /// Return an implementation of <see cref="TlsAuthentication"/> to handle authentication
        /// part of the protocol.
        /// </summary>
        /// <exception cref="IOException"/>
        TlsAuthentication GetAuthentication();

        IList GetClientSupplementalData();       

        /**
         * RFC 5077 3.3. NewSessionTicket Handshake Message
         * <p/>
         * This method will be called (only) when a NewSessionTicket handshake message is received. The
         * ticket is opaque to the client and clients MUST NOT examine the ticket under the assumption
         * that it complies with e.g. <i>RFC 5077 4. Recommended Ticket Construction</i>.
         *
         * @param newSessionTicket The ticket.
         * @throws IOException
         */
        void NotifyNewSessionTicket(NewSessionTicket newSessionTicket);
    }
}
