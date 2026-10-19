using System;

namespace Org.BouncyCastle.Tls
{
    public interface TlsHeartbeat
    {
        byte[] GeneratePayload();

        /// <summary>Gets the idle millis.</summary>
        int IdleMillis { get; }

        /// <summary>Gets the timeout millis.</summary>
        int TimeoutMillis { get; }
    }
}
