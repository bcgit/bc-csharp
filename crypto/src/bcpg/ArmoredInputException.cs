using System;
using System.IO;
using System.Runtime.Serialization;

using Org.BouncyCastle.Utilities;

namespace Org.BouncyCastle.Bcpg
{
    [Serializable]
    public class ArmoredInputException
        : IOException
    {
        /// <summary>Create a new <see cref="ArmoredInputException"/>.</summary>
        public ArmoredInputException()
            : base()
        {
        }

        /// <summary>Create a new <see cref="ArmoredInputException"/>.</summary>
        /// <param name="message">The message.</param>
        public ArmoredInputException(string message)
            : base(message)
        {
        }

        /// <summary>Create a new <see cref="ArmoredInputException"/>.</summary>
        /// <param name="message">The message.</param>
        /// <param name="innerException">The inner exception.</param>
        public ArmoredInputException(string message, Exception innerException)
            : base(message, innerException)
        {
        }

        /// <summary>Create a new <see cref="ArmoredInputException"/>.</summary>
        /// <param name="info">The info.</param>
        /// <param name="context">The context.</param>
#if NET8_0_OR_GREATER
        [Obsolete(Exceptions.SYSLIB0051_Message, DiagnosticId="SYSLIB0051", UrlFormat="https://aka.ms/dotnet-warnings/{0}")]
#endif
        protected ArmoredInputException(SerializationInfo info, StreamingContext context)
            : base(info, context)
        {
        }
    }
}
