using System;

using Org.BouncyCastle.Utilities.Date;

namespace Org.BouncyCastle.Bcpg.Sig
{
    /**
    * packet giving signature creation time.
    */
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
            : base(SignatureSubpacketTag.CreationTime, critical, false, TimeToBytes(date))
        {
        }
#pragma warning restore CS0618 // Type or member is obsolete

        public DateTime GetTime()
        {
            long time = Utilities.TimeFromBytes(data);
			return DateTimeUtilities.UnixMsToDateTime(time * 1000L);
        }
    }
}
