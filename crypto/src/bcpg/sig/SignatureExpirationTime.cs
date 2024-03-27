using System;

namespace Org.BouncyCastle.Bcpg.Sig
{
    /**
    * packet giving signature expiration time.
    */
    public class SignatureExpirationTime
        : SignatureSubpacket
    {
        [Obsolete("Will be removed")]
        protected static byte[] TimeToBytes(long t) => Utilities.TimeToBytes((uint)t);

        public SignatureExpirationTime(bool critical, bool isLongLength, byte[] data)
            : base(SignatureSubpacketTag.ExpireTime, critical, isLongLength, data)
        {
        }

        public SignatureExpirationTime(bool critical, long seconds)
            : base(SignatureSubpacketTag.ExpireTime, critical, false, Utilities.TimeToBytes((uint)seconds))
        {
        }

        /**
        * return time in seconds before signature expires after creation time.
        */
        public long Time => (long)Utilities.TimeFromBytes(data);
    }
}
