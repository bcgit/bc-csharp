using System;
using System.Runtime.Serialization;

using Org.BouncyCastle.Utilities;

namespace Org.BouncyCastle.Bcpg
{
    [Serializable]
    public class UnsupportedPacketVersionException
        : Exception
    {
        public UnsupportedPacketVersionException()
            : base()
        {
        }

        public UnsupportedPacketVersionException(string message)
            : base(message)
        {
        }

        public UnsupportedPacketVersionException(string message, Exception innerException)
            : base(message, innerException)
        {
        }

#if NET8_0_OR_GREATER
        [Obsolete(Exceptions.SYSLIB0051_Message, DiagnosticId="SYSLIB0051", UrlFormat="https://aka.ms/dotnet-warnings/{0}")]
#endif
        protected UnsupportedPacketVersionException(SerializationInfo info, StreamingContext context)
            : base(info, context)
        {
        }
    }
}
