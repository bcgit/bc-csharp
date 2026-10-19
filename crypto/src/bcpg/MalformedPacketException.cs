using System;
using System.IO;
using System.Runtime.Serialization;

using Org.BouncyCastle.Utilities;

namespace Org.BouncyCastle.Bcpg
{
    /// <summary>Exception thrown when a packet is malformed.</summary>
    [Serializable]
    public class MalformedPacketException
        : IOException
    {
        /// <summary>Create a new <see cref="MalformedPacketException"/>.</summary>
        public MalformedPacketException()
            : base()
        {
        }

        /// <summary>Create a new <see cref="MalformedPacketException"/>.</summary>
        /// <param name="message">The message.</param>
        public MalformedPacketException(string message)
            : base(message)
        {
        }

        /// <summary>Create a new <see cref="MalformedPacketException"/>.</summary>
        /// <param name="message">The message.</param>
        /// <param name="innerException">The inner exception.</param>
        public MalformedPacketException(string message, Exception innerException)
            : base(message, innerException)
        {
        }

        /// <summary>Create a new <see cref="MalformedPacketException"/>.</summary>
        /// <param name="info">The serialization information.</param>
        /// <param name="context">The streaming context.</param>
#if NET8_0_OR_GREATER
        [Obsolete(Exceptions.SYSLIB0051_Message, DiagnosticId="SYSLIB0051", UrlFormat="https://aka.ms/dotnet-warnings/{0}")]
#endif
        protected MalformedPacketException(SerializationInfo info, StreamingContext context)
            : base(info, context)
        {
        }
    }
}
