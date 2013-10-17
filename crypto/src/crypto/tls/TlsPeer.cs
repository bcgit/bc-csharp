using System;
using System.IO;

namespace Org.BouncyCastle.Crypto.Tls
{

    public interface TlsPeer
    {
        /// <summary>
        /// Report whether the server supports secure renegotiation
        /// </summary>
        /// <remarks>
        /// The protocol handler automatically processes the relevant extensions
        /// </remarks>
        /// <param name="secureNegotiation">
        /// A <see cref="System.Boolean"/>, true if the server supports secure renegotiation
        /// </param>
        /// <exception cref="IOException"></exception>
        void NotifySecureRenegotiation(bool secureNegotiation);

        /// <summary>
        /// Return an implementation of <see cref="TlsCompression"/> to handle record compression.
        /// </summary>
        /// <exception cref="IOException"/>
        TlsCompression GetCompression();

        /// <summary>
        /// Return an implementation of <see cref="TlsCipher"/> to use for encryption/decryption.
        /// </summary>
        /// <returns>
        /// A <see cref="TlsCipher"/>
        /// </returns>
        /// <exception cref="IOException"/>
        TlsCipher GetCipher();

        /**
         * This method will be called when an alert is raised by the protocol.
         *
         * @param alertLevel       {@link AlertLevel}
         * @param alertDescription {@link AlertDescription}
         * @param message          A human-readable message explaining what caused this alert. May be null.
         * @param cause            The exception that caused this alert to be raised. May be null.
         */
        void NotifyAlertRaised(AlertLevel alertLevel, AlertDescription alertDescription, String message, Exception cause);

        /**
         * This method will be called when an alert is received from the remote peer.
         *
         * @param alertLevel       {@link AlertLevel}
         * @param alertDescription {@link AlertDescription}
         */
        void NotifyAlertReceived(AlertLevel  alertLevel, AlertDescription alertDescription);

        /**
         * Notifies the peer that the handshake has been successfully completed.
         */
        void NotifyHandshakeComplete();
    }

}
