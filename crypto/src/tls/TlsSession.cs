using System;

namespace Org.BouncyCastle.Tls
{
    /// <summary>Base interface for a carrier object for a TLS session.</summary>
    public interface TlsSession
    {
        /// <summary>Export a copy of the parameters of the session.</summary>
        /// <returns>The session parameters, or null if the handshake has not established any.</returns>
        SessionParameters ExportSessionParameters();

        /// <summary>Gets the session ID.</summary>
        byte[] SessionID { get; }

        /// <summary>Invalidate the session so that it cannot be resumed.</summary>
        void Invalidate();

        /// <summary>Gets a value indicating whether this is resumable.</summary>
        bool IsResumable { get; }
    }
}
