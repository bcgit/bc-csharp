using System;

using Org.BouncyCastle.Crypto.Utilities;
using Org.BouncyCastle.Utilities.Date;

namespace Org.BouncyCastle.Bcpg.Sig
{
    /**
    * packet giving signature creation time.
    */
    public class SignatureCreationTime
        : SignatureSubpacket
    {
		protected static byte[] TimeToBytes(DateTime time)
        {
			long t = DateTimeUtilities.DateTimeToUnixMs(time) / 1000L;
            return Pack.UInt32_To_BE((uint)t);
        }

        public SignatureCreationTime(bool critical, bool isLongLength, byte[] data)
            : base(SignatureSubpacketTag.CreationTime, critical, isLongLength, data)
        {
        }

        public SignatureCreationTime(bool critical, DateTime date)
            : base(SignatureSubpacketTag.CreationTime, critical, false, TimeToBytes(date))
        {
        }

        public DateTime GetTime()
        {
            uint time = Pack.BE_To_UInt32(data, 0);
			return DateTimeUtilities.UnixMsToDateTime(time * 1000L);
        }
    }
}
