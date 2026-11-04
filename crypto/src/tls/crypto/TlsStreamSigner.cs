using System;
using System.IO;

namespace Org.BouncyCastle.Tls.Crypto
{
    /// <summary>Interface for a signer that signs a stream of data.</summary>
    public interface TlsStreamSigner
    {
        /// <exception cref="IOException"/>
        Stream Stream { get; }

        /// <exception cref="IOException"/>
        byte[] GetSignature();
    }
}
