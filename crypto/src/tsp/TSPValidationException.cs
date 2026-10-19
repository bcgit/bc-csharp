using System;
using System.Runtime.Serialization;

using Org.BouncyCastle.Utilities;

namespace Org.BouncyCastle.Tsp
{
    /// <summary>
    /// Exception thrown if a TSP request or response fails to validate.
    /// </summary>
    /// <remarks>
    /// If a failure code is associated with the exception it can be retrieved using the <see cref="FailureCode"/>
    /// property.
    /// </remarks>
    [Serializable]
    public class TspValidationException
        : TspException
    {
        // TODO[api] Make private
        /// <summary>The failure code associated with this exception, or -1 if none was set.</summary>
        protected readonly int m_failureCode;

        /// <summary>Create an exception with no associated failure code.</summary>
        /// <param name="message">The message describing the validation failure.</param>
        public TspValidationException(string message)
            : this(message, -1)
        {
        }

        /// <summary>Create an exception with an associated failure code.</summary>
        /// <param name="message">The message describing the validation failure.</param>
        /// <param name="failureCode">
        /// The failure code, as one of the constants in <see cref="PkiFailureInfo"/>.
        /// </param>
        public TspValidationException(string message, int failureCode)
            : base(message)
        {
            m_failureCode = failureCode;
        }

        /// <summary>Create a new <see cref="TspValidationException"/>.</summary>
        /// <param name="info">The info.</param>
        /// <param name="context">The context.</param>
#if NET8_0_OR_GREATER
        [Obsolete(Exceptions.SYSLIB0051_Message, DiagnosticId="SYSLIB0051", UrlFormat="https://aka.ms/dotnet-warnings/{0}")]
#endif
        protected TspValidationException(SerializationInfo info, StreamingContext context)
            : base(info, context)
        {
            m_failureCode = info.GetInt32("failureCode");
        }

        /// <inheritdoc/>
#if NET8_0_OR_GREATER
        [Obsolete(Exceptions.SYSLIB0051_Message, DiagnosticId="SYSLIB0051", UrlFormat="https://aka.ms/dotnet-warnings/{0}")]
#endif
        public override void GetObjectData(SerializationInfo info, StreamingContext context)
        {
            base.GetObjectData(info, context);
            info.AddValue("failureCode", m_failureCode);
        }

        /// <returns>The failure code associated with this exception, if one is set.</returns>
        public int FailureCode => m_failureCode;
    }
}
