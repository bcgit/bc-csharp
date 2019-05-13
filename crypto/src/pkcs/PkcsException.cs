using System;

namespace Org.BouncyCastle.Pkcs
{
    /// <summary>
    /// Base exception for PKCS related issues.
    /// </summary>
    public class PkcsException
        : Exception
    {
        public PkcsException(string message)
            : base(message)
        {
        }

        public PkcsException(string message, Exception underlying)
            : base(message, underlying)
        {
        }
    }
}
