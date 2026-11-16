using System;
using System.IO;

namespace Org.BouncyCastle.Tls
{
    /// <summary>Interface for TLS objects that can be closed.</summary>
    public interface TlsCloseable
    {
        /// <exception cref="IOException"/>
        void Close();
    }
}
