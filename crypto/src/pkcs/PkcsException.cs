using System;
using System.Runtime.Serialization;

using Org.BouncyCastle.Utilities;

namespace Org.BouncyCastle.Pkcs
{
    /// <summary>Base exception for PKCS related issues.</summary>
    [Serializable]
    public class PkcsException
        : Exception
    {
        public PkcsException()
            : base()
        {
        }

        public PkcsException(string message)
            : base(message)
        {
        }

        public PkcsException(string message, Exception innerException)
            : base(message, innerException)
        {
        }

#if NET8_0_OR_GREATER
        [Obsolete(Exceptions.SYSLIB0051_Message, DiagnosticId="SYSLIB0051", UrlFormat="https://aka.ms/dotnet-warnings/{0}")]
#endif
        protected PkcsException(SerializationInfo info, StreamingContext context)
            : base(info, context)
        {
        }
    }
}
