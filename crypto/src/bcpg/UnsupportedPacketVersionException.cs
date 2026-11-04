using System;
using System.Runtime.Serialization;

using Org.BouncyCastle.Utilities;

namespace Org.BouncyCastle.Bcpg
{
    /// <summary>Exception thrown when a packet has a version that is not supported.</summary>
    [Serializable]
    public class UnsupportedPacketVersionException
        : Exception
    {
        /// <summary>Create a new <see cref="UnsupportedPacketVersionException"/>.</summary>
        public UnsupportedPacketVersionException()
            : base()
        {
        }

        /// <summary>Create a new <see cref="UnsupportedPacketVersionException"/>.</summary>
        /// <param name="message">The message.</param>
        public UnsupportedPacketVersionException(string message)
            : base(message)
        {
        }

        /// <summary>Create a new <see cref="UnsupportedPacketVersionException"/>.</summary>
        /// <param name="message">The message.</param>
        /// <param name="innerException">The inner exception.</param>
        public UnsupportedPacketVersionException(string message, Exception innerException)
            : base(message, innerException)
        {
        }

        /// <summary>Create a new <see cref="UnsupportedPacketVersionException"/>.</summary>
        /// <param name="info">The serialization information.</param>
        /// <param name="context">The streaming context.</param>
#if NET8_0_OR_GREATER
        [Obsolete(Exceptions.SYSLIB0051_Message, DiagnosticId="SYSLIB0051", UrlFormat="https://aka.ms/dotnet-warnings/{0}")]
#endif
        protected UnsupportedPacketVersionException(SerializationInfo info, StreamingContext context)
            : base(info, context)
        {
        }
    }
}
