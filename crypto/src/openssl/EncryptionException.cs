using System;
using System.Runtime.Serialization;

using Org.BouncyCastle.Utilities;

namespace Org.BouncyCastle.OpenSsl
{
    /// <summary>Exception thrown when a PEM object cannot be encrypted or decrypted.</summary>
    [Serializable]
    public class EncryptionException
        // TODO[api] Change to IOException
#pragma warning disable CS0618 // Type or member is obsolete
        : Security.EncryptionException
#pragma warning restore CS0618 // Type or member is obsolete
    {
        /// <summary>Create an exception with no detail message.</summary>
        public EncryptionException()
            : base()
        {
        }

        /// <summary>Create an exception with the specified detail message.</summary>
        /// <param name="message">The detail message.</param>
        public EncryptionException(string message)
            : base(message)
        {
        }

        /// <summary>Create an exception with the specified detail message and cause.</summary>
        /// <param name="message">The detail message.</param>
        /// <param name="innerException">The cause.</param>
        public EncryptionException(string message, Exception innerException)
            : base(message, innerException)
        {
        }

        /// <summary>Create a new <see cref="EncryptionException"/>.</summary>
        /// <param name="info">The serialization information.</param>
        /// <param name="context">The streaming context.</param>
#if NET8_0_OR_GREATER
        [Obsolete(Exceptions.SYSLIB0051_Message, DiagnosticId="SYSLIB0051", UrlFormat="https://aka.ms/dotnet-warnings/{0}")]
#endif
        protected EncryptionException(SerializationInfo info, StreamingContext context)
            : base(info, context)
        {
        }
    }
}
