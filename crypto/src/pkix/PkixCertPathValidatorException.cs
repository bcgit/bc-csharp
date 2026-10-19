using System;
using System.Runtime.Serialization;

using Org.BouncyCastle.Security;
#if NET8_0_OR_GREATER
using Org.BouncyCastle.Utilities;
#endif

namespace Org.BouncyCastle.Pkix
{
    /// <summary>
    /// An exception indicating one of a variety of problems encountered when validating a certification path.
    /// </summary>
    /// <remarks>
    /// Instances may also include the (zero based) index of the certificate in the certification path that caused the
    /// exception to be thrown. Use the <see cref="Index"/> property to retrieve this information. The
    /// <see cref="Reason"/> property classifies the problem, where known.
    /// </remarks>
    [Serializable]
    public class PkixCertPathValidatorException
        : GeneralSecurityException
    {
        /// <summary>The index of the offending certificate in the path, or -1 if none has been set.</summary>
        protected readonly int m_index = -1;
        private readonly PkixCertPathValidatorReason m_reason = PkixCertPathValidatorReason.Unspecified;

        /// <summary>Create an exception with no detail message.</summary>
        public PkixCertPathValidatorException()
            : base()
        {
        }

        /// <summary>Create an exception with the specified detail message.</summary>
        /// <param name="message">The detail message.</param>
        public PkixCertPathValidatorException(string message)
            : base(message)
        {
        }

        /// <summary>Create an exception with the specified detail message and cause.</summary>
        /// <param name="message">The detail message.</param>
        /// <param name="innerException">The cause.</param>
        public PkixCertPathValidatorException(string message, Exception innerException)
            : base(message, innerException)
        {
        }

        /// <summary>
        /// Creates a <c>PkixCertPathValidatorException</c> with the specified detail message, cause and index.
        /// </summary>
        /// <param name="message">The detail message (or null if none).</param>
        /// <param name="innerException">The cause (or null if none).</param>
        /// <param name="index">The index of the certificate in the path that caused the exception.</param>
        /// <exception cref="ArgumentException"><paramref name="index"/> is less than -1.</exception>
        public PkixCertPathValidatorException(string message, Exception innerException, int index)
            : this(message, innerException, index, PkixCertPathValidatorReason.Unspecified)
        {
        }

        /// <summary>
        /// Creates a <c>PkixCertPathValidatorException</c> with the specified detail message, cause, index, and
        /// reason.
        /// </summary>
        /// <param name="message">The detail message (or <c>null</c> if none).</param>
        /// <param name="innerException">The cause (or <c>null</c> if none).</param>
        /// <param name="index">The index of the certificate in the certification path that caused the exception to
        /// be thrown, or -1 if not applicable.</param>
        /// <param name="reason">The reason the validation failed.</param>
        public PkixCertPathValidatorException(string message, Exception innerException, int index,
            PkixCertPathValidatorReason reason)
            : base(message, innerException)
        {
            if (index < -1)
                throw new ArgumentException("cannot be < -1", nameof(index));

            m_index = index;
            m_reason = reason;
        }

        /// <summary>Create a new <see cref="PkixCertPathValidatorException"/>.</summary>
        /// <param name="info">The info.</param>
        /// <param name="context">The context.</param>
#if NET8_0_OR_GREATER
        [Obsolete(Exceptions.SYSLIB0051_Message, DiagnosticId="SYSLIB0051", UrlFormat="https://aka.ms/dotnet-warnings/{0}")]
#endif
        protected PkixCertPathValidatorException(SerializationInfo info, StreamingContext context)
            : base(info, context)
        {
            m_index = info.GetInt32("index");

            // Absent when serialized by an earlier version
            foreach (SerializationEntry entry in info)
            {
                if (entry.Name == "reason")
                {
                    m_reason = (PkixCertPathValidatorReason)info.GetInt32("reason");
                    break;
                }
            }
        }

        /// <inheritdoc/>
#if NET8_0_OR_GREATER
        [Obsolete(Exceptions.SYSLIB0051_Message, DiagnosticId="SYSLIB0051", UrlFormat="https://aka.ms/dotnet-warnings/{0}")]
#endif
        public override void GetObjectData(SerializationInfo info, StreamingContext context)
        {
            base.GetObjectData(info, context);
            info.AddValue("index", m_index);
            info.AddValue("reason", (int)m_reason);
        }

        /// <summary>Returns the index of the certificate in the certification path that caused the exception to be
        /// thrown.</summary>
        /// <remarks>
        /// Note that the list of certificates in a <see cref="PkixCertPath"/> is zero based. If no index has been set,
        /// -1 is returned.
        /// </remarks>
        /// <returns>The index that has been set, or -1 if none has been set.</returns>
        public int Index => m_index;

        /// <summary>The reason the validation failed.</summary>
        /// <remarks>
        /// If no reason has been set, <see cref="PkixCertPathValidatorReason.Unspecified"/> is returned.
        /// </remarks>
        public PkixCertPathValidatorReason Reason => m_reason;
    }
}
