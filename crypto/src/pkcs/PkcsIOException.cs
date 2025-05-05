using System;
using System.IO;
using System.Runtime.Serialization;

using Org.BouncyCastle.Utilities;

namespace Org.BouncyCastle.Pkcs
{
    /// <summary>Base exception for parsing related issues in the PKCS namespace.</summary>
    [Serializable]
    public class PkcsIOException
        : IOException
    {
        public PkcsIOException()
            : base()
        {
        }

        public PkcsIOException(string message)
            : base(message)
        {
        }

        public PkcsIOException(string message, Exception innerException)
            : base(message, innerException)
        {
        }

#if NET8_0_OR_GREATER
        [Obsolete(Exceptions.SYSLIB0051_Message, DiagnosticId="SYSLIB0051", UrlFormat="https://aka.ms/dotnet-warnings/{0}")]
#endif
        protected PkcsIOException(SerializationInfo info, StreamingContext context)
            : base(info, context)
        {
        }
    }
}
