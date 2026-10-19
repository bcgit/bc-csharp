using System;

using Org.BouncyCastle.Tls.Crypto;

namespace Org.BouncyCastle.Tls
{
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
