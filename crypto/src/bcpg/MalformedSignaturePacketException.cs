using System;

namespace Org.BouncyCastle.Bcpg
{
    /// <summary>
    /// A signature or one-pass signature packet that could not be parsed, whose body has been consumed, so that the
    /// packets after it can still be read (RFC 9580 5.2.5).
    /// </summary>
    internal sealed class MalformedSignaturePacketException
        : MalformedPacketException
    {
        internal MalformedSignaturePacketException(string message, Exception innerException)
            : base(message, innerException)
        {
        }
    }
}
