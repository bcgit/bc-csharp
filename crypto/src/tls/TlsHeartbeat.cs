using System;

namespace Org.BouncyCastle.Tls
{
    /// <summary>Interface for the heartbeat configuration of a TLS connection.</summary>
    public interface TlsHeartbeat
    {
        byte[] GeneratePayload();

        /// <summary>Gets the idle millis.</summary>
        int IdleMillis { get; }

        /// <summary>Gets the timeout millis.</summary>
        int TimeoutMillis { get; }
    }
}
