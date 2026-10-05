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
    /// exception to be thrown. Use the <see cref="Index"/> property to retrieve this information.
    /// </remarks>
    [Serializable]
    public class PkixCertPathValidatorException
        : GeneralSecurityException
    {
        protected readonly int m_index = -1;

        public PkixCertPathValidatorException()
            : base()
        {
        }

        public PkixCertPathValidatorException(string message)
            : base(message)
        {
        }

        public PkixCertPathValidatorException(string message, Exception innerException)
            : base(message, innerException)
        {
        }

        /// <summary>
        /// Creates a <code>PkixCertPathValidatorException</code> with the specified
        /// detail message, cause, certification path, and index.
        /// </summary>
        /// <param name="message">the detail message (or <code>null</code> if none)</param>
        /// <param name="innerException">the cause (or <code>null</code> if none)</param>
        /// <param name="index">the index of the certificate in the certification path that</param>
        public PkixCertPathValidatorException(string message, Exception innerException, int index)
            : base(message, innerException)
        {
            if (index < -1)
                throw new ArgumentException("cannot be < -1", nameof(index));

            m_index = index;
        }

#if NET8_0_OR_GREATER
        [Obsolete(Exceptions.SYSLIB0051_Message, DiagnosticId="SYSLIB0051", UrlFormat="https://aka.ms/dotnet-warnings/{0}")]
#endif
        protected PkixCertPathValidatorException(SerializationInfo info, StreamingContext context)
            : base(info, context)
        {
            m_index = info.GetInt32("index");
        }

#if NET8_0_OR_GREATER
        [Obsolete(Exceptions.SYSLIB0051_Message, DiagnosticId="SYSLIB0051", UrlFormat="https://aka.ms/dotnet-warnings/{0}")]
#endif
        public override void GetObjectData(SerializationInfo info, StreamingContext context)
        {
            base.GetObjectData(info, context);
            info.AddValue("index", m_index);
        }

        /// <summary>Returns the index of the certificate in the certification path that caused the exception to be
        /// thrown.</summary>
        /// <remarks>
        /// Note that the list of certificates in a <see cref="PkixCertPath"/> is zero based. If no index has been set,
        /// -1 is returned.
        /// </remarks>
        /// <returns>The index that has been set, or -1 if none has been set.</returns>
        public int Index => m_index;
    }
}
