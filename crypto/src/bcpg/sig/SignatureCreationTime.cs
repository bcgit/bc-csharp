using System;

using Org.BouncyCastle.Utilities.Date;

namespace Org.BouncyCastle.Bcpg.Sig
{
    /// <summary>Signature Subpacket containing the time at which the signature was created.</summary>
    /// <remarks>
    /// <see href="https://datatracker.ietf.org/doc/html/rfc4880#section-5.2.3.4">
    /// RFC4880 - Signature Creation Time
    /// </see>
    /// <see href="https://www.rfc-editor.org/rfc/rfc9580.html#name-signature-creation-time">
    /// RFC9580 - Signature Creation Time
    /// </see>
    /// </remarks>
    public class SignatureCreationTime
        : SignatureSubpacket
    {
        [Obsolete("Will be removed")]
        protected static byte[] TimeToBytes(DateTime time)
        {
            long t = DateTimeUtilities.DateTimeToUnixMs(time) / 1000L;
            return Utilities.TimeToBytes((uint)t);
        }

        public SignatureCreationTime(bool critical, bool isLongLength, byte[] data)
            : base(SignatureSubpacketTag.CreationTime, critical, isLongLength, data)
        {
        }

#pragma warning disable CS0618 // Type or member is obsolete
        public SignatureCreationTime(bool critical, DateTime date)
            : base(SignatureSubpacketTag.CreationTime, critical, isLongLength: false, TimeToBytes(date))
        {
        }
#pragma warning restore CS0618 // Type or member is obsolete

        public DateTime GetTime()
        {
            long time = Utilities.TimeFromBytes(Data);
            return DateTimeUtilities.UnixMsToDateTime(time * 1000L);
        }
    }
}
