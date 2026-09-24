using System;
using System.Runtime.Serialization;

#if NET8_0_OR_GREATER
using Org.BouncyCastle.Utilities;
#endif

namespace Org.BouncyCastle.Pkix
{
    [Serializable]
    internal class PkixRecoverableCertPathValidatorException
        : PkixCertPathValidatorException
    {
        internal PkixRecoverableCertPathValidatorException()
            : base()
        {
        }

        internal PkixRecoverableCertPathValidatorException(string message)
            : base(message)
        {
        }

        internal PkixRecoverableCertPathValidatorException(string message, Exception innerException)
            : base(message, innerException)
        {
        }

        /// <inheritdoc/>
        internal PkixRecoverableCertPathValidatorException(string message, Exception innerException, int index)
            : base(message, innerException, index)
        {
        }

#if NET8_0_OR_GREATER
        [Obsolete(Exceptions.SYSLIB0051_Message, DiagnosticId="SYSLIB0051", UrlFormat="https://aka.ms/dotnet-warnings/{0}")]
#endif
        protected PkixRecoverableCertPathValidatorException(SerializationInfo info, StreamingContext context)
            : base(info, context)
        {
        }
    }
}
