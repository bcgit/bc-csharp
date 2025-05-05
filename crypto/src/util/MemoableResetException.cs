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
        public MemoableResetException()
            : base()
        {
        }

        public MemoableResetException(string message)
            : base(message)
        {
        }

        public MemoableResetException(string message, Exception innerException)
            : base(message, innerException)
        {
        }

#if NET8_0_OR_GREATER
        [Obsolete(Exceptions.SYSLIB0051_Message, DiagnosticId="SYSLIB0051", UrlFormat="https://aka.ms/dotnet-warnings/{0}")]
#endif
        protected MemoableResetException(SerializationInfo info, StreamingContext context)
            : base(info, context)
        {
        }
    }
}
