using System;
using System.IO;

namespace Org.BouncyCastle.Tls.Crypto
{
    public interface TlsStreamSigner
    {
        /// <exception cref="IOException"/>
        Stream GetOutputStream();

        /// <exception cref="IOException"/>
        byte[] GetSignature();
    }
}
