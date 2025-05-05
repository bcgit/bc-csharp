using System;
using System.Runtime.Serialization;

using Org.BouncyCastle.Security;
using Org.BouncyCastle.Utilities;

namespace Org.BouncyCastle.Pkix
{
    [Serializable]
    public class PkixCertPathBuilderException
        : GeneralSecurityException
    {
        public PkixCertPathBuilderException()
            : base()
        {
        }

        public PkixCertPathBuilderException(string message)
            : base(message)
        {
        }

        public PkixCertPathBuilderException(string message, Exception innerException)
            : base(message, innerException)
        {
        }

#if NET8_0_OR_GREATER
        [Obsolete(Exceptions.SYSLIB0051_Message, DiagnosticId="SYSLIB0051", UrlFormat="https://aka.ms/dotnet-warnings/{0}")]
#endif
        protected PkixCertPathBuilderException(SerializationInfo info, StreamingContext context)
            : base(info, context)
        {
        }
    }
}
