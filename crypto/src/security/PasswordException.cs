using System;
using System.IO;
using System.Runtime.Serialization;

using Org.BouncyCastle.Utilities;

namespace Org.BouncyCastle.Security
{
    [Obsolete("Use Org.BouncyCastle.OpenSsl.PasswordException instead")]
    [Serializable]
    public class PasswordException
        : IOException
    {
        public PasswordException()
            : base()
        {
        }

        public PasswordException(string message)
            : base(message)
        {
        }

        public PasswordException(string message, Exception innerException)
            : base(message, innerException)
        {
        }

#if NET8_0_OR_GREATER
        [Obsolete(Exceptions.SYSLIB0051_Message, DiagnosticId="SYSLIB0051", UrlFormat="https://aka.ms/dotnet-warnings/{0}")]
#endif
        protected PasswordException(SerializationInfo info, StreamingContext context)
            : base(info, context)
        {
        }
    }
}
