using System;

namespace Org.BouncyCastle.Tls
{
    /// <summary>Base interface for a carrier object for a TLS session.</summary>
    public interface TlsSession
    {
        SessionParameters ExportSessionParameters();

        /// <summary>Gets the session ID.</summary>
        byte[] SessionID { get; }

        void Invalidate();

        /// <summary>Gets a value indicating whether this is resumable.</summary>
        bool IsResumable { get; }
    }
}
