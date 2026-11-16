using System;

namespace Org.BouncyCastle.Tls
{
    /// <summary>Base interface for an object that can process a PSK identity.</summary>
    public interface TlsPskIdentityManager
    {
        /// <summary>Return the hint.</summary>
        byte[] GetHint();

        /// <summary>Get the pre-shared key for an identity.</summary>
        /// <param name="identity">The identity.</param>
        /// <returns>The key, or null if the identity is not known.</returns>
        byte[] GetPsk(byte[] identity);
    }
}
