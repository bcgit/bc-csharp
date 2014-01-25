using System;
using System.IO;

namespace Org.BouncyCastle.Crypto.Tls
{
    public interface TlsCipherFactory
    {
        /// <exception cref="IOException"></exception>
        TlsCipher CreateCipher(TlsClientContext context, int encryptionAlgorithm,
            DigestAlgorithm digestAlgorithm);
    }
}
