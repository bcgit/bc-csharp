using System;
using System.Runtime.Serialization;

using Org.BouncyCastle.Utilities;

namespace Org.BouncyCastle.Security
{
    /// <summary>Base exception for security related failures.</summary>
    [Serializable]
    public class GeneralSecurityException
        : Exception
    {
        /// <summary>Create an exception with no detail message.</summary>
        public GeneralSecurityException()
            : base()
        {
        }

        /// <summary>Create an exception with the specified detail message.</summary>
        /// <param name="message">The detail message.</param>
        public GeneralSecurityException(string message)
            : base(message)
        {
        }

        /// <summary>Create an exception with the specified detail message and cause.</summary>
        /// <param name="message">The detail message.</param>
        /// <param name="innerException">The cause.</param>
        public GeneralSecurityException(string message, Exception innerException)
            : base(message, innerException)
        {
        }

#if NET8_0_OR_GREATER
        [Obsolete(Exceptions.SYSLIB0051_Message, DiagnosticId="SYSLIB0051", UrlFormat="https://aka.ms/dotnet-warnings/{0}")]
#endif
        protected GeneralSecurityException(SerializationInfo info, StreamingContext context)
            : base(info, context)
        {
        }
    }
}
