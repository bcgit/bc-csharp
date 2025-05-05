using System;
using System.IO;
using System.Runtime.Serialization;

using Org.BouncyCastle.Utilities;

namespace Org.BouncyCastle.Bcpg
{
    [Serializable]
    public class MalformedPacketException
        : IOException
    {
        public MalformedPacketException()
            : base()
        {
        }

        public MalformedPacketException(string message)
            : base(message)
        {
        }

        public MalformedPacketException(string message, Exception innerException)
            : base(message, innerException)
        {
        }

#if NET8_0_OR_GREATER
        [Obsolete(Exceptions.SYSLIB0051_Message, DiagnosticId="SYSLIB0051", UrlFormat="https://aka.ms/dotnet-warnings/{0}")]
#endif
        protected MalformedPacketException(SerializationInfo info, StreamingContext context)
            : base(info, context)
        {
        }
    }
}
