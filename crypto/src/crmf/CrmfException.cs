using System;
using System.Runtime.Serialization;

using Org.BouncyCastle.Utilities;

namespace Org.BouncyCastle.Crmf
{
    [Serializable]
    public class CrmfException
        : Exception
    {
        public CrmfException()
            : base()
        {
        }

        public CrmfException(string message)
            : base(message)
        {
        }

        public CrmfException(string message, Exception innerException)
            : base(message, innerException)
        {
        }

#if NET8_0_OR_GREATER
        [Obsolete(Exceptions.SYSLIB0051_Message, DiagnosticId="SYSLIB0051", UrlFormat="https://aka.ms/dotnet-warnings/{0}")]
#endif
        protected CrmfException(SerializationInfo info, StreamingContext context)
            : base(info, context)
        {
        }
    }
}
