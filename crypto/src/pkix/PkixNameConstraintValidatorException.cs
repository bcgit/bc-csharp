using System;
using System.Runtime.Serialization;

using Org.BouncyCastle.Utilities;

namespace Org.BouncyCastle.Pkix
{
    /// <summary>Exception thrown when a name does not satisfy the name constraints being checked.</summary>
    [Serializable]
    public class PkixNameConstraintValidatorException
        : Exception
    {
        /// <summary>Create a new <see cref="PkixNameConstraintValidatorException"/>.</summary>
        public PkixNameConstraintValidatorException()
            : base()
        {
        }

        /// <summary>Create a new <see cref="PkixNameConstraintValidatorException"/>.</summary>
        /// <param name="message">The message.</param>
        public PkixNameConstraintValidatorException(string message)
            : base(message)
        {
        }

        /// <summary>Create a new <see cref="PkixNameConstraintValidatorException"/>.</summary>
        /// <param name="message">The message.</param>
        /// <param name="innerException">The inner exception.</param>
        public PkixNameConstraintValidatorException(string message, Exception innerException)
            : base(message, innerException)
        {
        }

        /// <summary>Create a new <see cref="PkixNameConstraintValidatorException"/>.</summary>
        /// <param name="info">The serialization information.</param>
        /// <param name="context">The streaming context.</param>
#if NET8_0_OR_GREATER
        [Obsolete(Exceptions.SYSLIB0051_Message, DiagnosticId="SYSLIB0051", UrlFormat="https://aka.ms/dotnet-warnings/{0}")]
#endif
        protected PkixNameConstraintValidatorException(SerializationInfo info, StreamingContext context)
            : base(info, context)
        {
        }
    }
}
