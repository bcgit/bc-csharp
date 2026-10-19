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
        /// <summary>Create an exception with no detail message.</summary>
        public PkcsIOException()
            : base()
        {
        }

        /// <summary>Create an exception with the specified detail message.</summary>
        /// <param name="message">The detail message.</param>
        public PkcsIOException(string message)
            : base(message)
        {
        }

        /// <summary>Create an exception with the specified detail message and cause.</summary>
        /// <param name="message">The detail message.</param>
        /// <param name="innerException">The cause.</param>
        public PkcsIOException(string message, Exception innerException)
            : base(message, innerException)
        {
        }

        /// <summary>Create a new <see cref="PkcsIOException"/>.</summary>
        /// <param name="info">The info.</param>
        /// <param name="context">The context.</param>
#if NET8_0_OR_GREATER
        [Obsolete(Exceptions.SYSLIB0051_Message, DiagnosticId="SYSLIB0051", UrlFormat="https://aka.ms/dotnet-warnings/{0}")]
#endif
        protected PkcsIOException(SerializationInfo info, StreamingContext context)
            : base(info, context)
        {
        }
    }
}
