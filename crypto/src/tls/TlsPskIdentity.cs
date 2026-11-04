using System;

namespace Org.BouncyCastle.Tls
{
    /// <summary>Processor interface for a PSK identity.</summary>
    public interface TlsPskIdentity
    {
        /// <summary>Indicate that the identity hint of the server is not required.</summary>
        void SkipIdentityHint();

        /// <summary>Notify of the identity hint received from the server.</summary>
        /// <param name="psk_identity_hint">The identity hint.</param>
        void NotifyIdentityHint(byte[] psk_identity_hint);

        /// <summary>Return the psk identity.</summary>
        byte[] GetPskIdentity();

        /// <summary>Return the psk.</summary>
        byte[] GetPsk();
    }
}
