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
        /// <summary>Create an exception with no detail message.</summary>
        public PkcsException()
            : base()
        {
        }

        /// <summary>Create an exception with the specified detail message.</summary>
        /// <param name="message">The detail message.</param>
        public PkcsException(string message)
            : base(message)
        {
        }

        /// <summary>Create an exception with the specified detail message and cause.</summary>
        /// <param name="message">The detail message.</param>
        /// <param name="innerException">The cause.</param>
        public PkcsException(string message, Exception innerException)
            : base(message, innerException)
        {
        }

        /// <summary>Create a new <see cref="PkcsException"/>.</summary>
        /// <param name="info">The serialization information.</param>
        /// <param name="context">The streaming context.</param>
#if NET8_0_OR_GREATER
        [Obsolete(Exceptions.SYSLIB0051_Message, DiagnosticId="SYSLIB0051", UrlFormat="https://aka.ms/dotnet-warnings/{0}")]
#endif
        protected PkcsException(SerializationInfo info, StreamingContext context)
            : base(info, context)
        {
        }
    }
}
