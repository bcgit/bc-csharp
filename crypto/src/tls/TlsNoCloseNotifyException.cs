using System;
using System.IO;
using System.Runtime.Serialization;

using Org.BouncyCastle.Utilities;

namespace Org.BouncyCastle.Tls
{
    /// <summary>This exception will be thrown (only) when the connection is closed by the peer without sending a
    /// <see cref="AlertDescription.close_notify">close_notify</see> warning alert.</summary>
    /// <remarks>
    /// If this happens, the TLS protocol cannot rule out truncation of the connection data (potentially
    /// malicious). It may be possible to check for truncation via some property of a higher level protocol
    /// built upon TLS, e.g.the Content-Length header for HTTPS.
    /// </remarks>
    [Serializable]
    public class TlsNoCloseNotifyException
        : EndOfStreamException
    {
        public TlsNoCloseNotifyException()
            : base("No close_notify alert received before connection closed")
        {
        }

#if NET8_0_OR_GREATER
        [Obsolete(Exceptions.SYSLIB0051_Message, DiagnosticId="SYSLIB0051", UrlFormat="https://aka.ms/dotnet-warnings/{0}")]
#endif
        protected TlsNoCloseNotifyException(SerializationInfo info, StreamingContext context)
            : base(info, context)
        {
        }
    }
}
