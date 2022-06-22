using System;
using System.IO;

namespace Org.BouncyCastle.Pkcs
{
    /// <summary>
    /// Base exception for parsing related issues in the PKCS namespace.
    /// </summary>
    public class PkcsIOException: IOException
    {
        public PkcsIOException(string message) : base(message)
        {
        }

        public PkcsIOException(string message, Exception underlying) : base(message, underlying)
        {
        }
    }
}
