using System;

namespace Org.BouncyCastle.Pkcs
{
    /// <summary>
    /// Base exception for PKCS related issues.
    /// </summary>
    public class PkcsException : Exception
    {
        public PkcsException(String message) : base(message)
        {
        }

        public PkcsException(String message, Exception underlying) : base(message, underlying)
        {
        }
    }
}
