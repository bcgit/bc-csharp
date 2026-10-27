using System;
using System.Runtime.Serialization;

namespace Org.BouncyCastle.Utilities
{
    /// <summary>
    /// Exception to be thrown on a failure to reset an object implementing <see cref="IMemoable"/>.
    /// </summary>
    /// <remarks>
    /// The exception extends <see cref="InvalidCastException"/> to enable users to have a single handling case, only
    /// introducing specific handling of this one if required.
    /// </remarks>
    [Serializable]
    public class MemoableResetException
        : InvalidCastException
    {
        /// <summary>Create a new <see cref="MemoableResetException"/>.</summary>
        public MemoableResetException()
            : base()
        {
        }

        /// <summary>Create a new <see cref="MemoableResetException"/>.</summary>
        /// <param name="message">The message.</param>
        public MemoableResetException(string message)
            : base(message)
        {
        }

        /// <summary>Create a new <see cref="MemoableResetException"/>.</summary>
        /// <param name="message">The message.</param>
        /// <param name="innerException">The inner exception.</param>
        public MemoableResetException(string message, Exception innerException)
            : base(message, innerException)
        {
        }

        /// <summary>Create a new <see cref="MemoableResetException"/>.</summary>
        /// <param name="info">The serialization information.</param>
        /// <param name="context">The streaming context.</param>
#if NET8_0_OR_GREATER
        [Obsolete(Exceptions.SYSLIB0051_Message, DiagnosticId="SYSLIB0051", UrlFormat="https://aka.ms/dotnet-warnings/{0}")]
#endif
        protected MemoableResetException(SerializationInfo info, StreamingContext context)
            : base(info, context)
        {
        }
    }
}
