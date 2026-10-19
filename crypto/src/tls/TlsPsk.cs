using System;

using Org.BouncyCastle.Tls.Crypto;

namespace Org.BouncyCastle.Tls
{
    /// <summary>Interface for a pre-shared key and its associated identity.</summary>
    public interface TlsPsk
    {
        /// <summary>Gets the identity.</summary>
        byte[] Identity { get; }

        /// <summary>Gets the key.</summary>
        TlsSecret Key { get; }

        /// <summary>Gets the prf algorithm.</summary>
        int PrfAlgorithm { get; }
    }
}
