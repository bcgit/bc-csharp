using System;

namespace Org.BouncyCastle.Tls
{
    /// <summary>Processor interface for a PSK identity.</summary>
    public interface TlsPskIdentity
    {
        void SkipIdentityHint();

        void NotifyIdentityHint(byte[] psk_identity_hint);

        /// <summary>Return the psk identity.</summary>
        byte[] GetPskIdentity();

        /// <summary>Return the psk.</summary>
        byte[] GetPsk();
    }
}
