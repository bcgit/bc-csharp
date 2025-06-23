using System;

namespace Org.BouncyCastle.Bcpg.Sig
{
    /**
    * packet giving time after creation at which the key expires.
    */
    public class KeyExpirationTime
        : SignatureSubpacket
    {
        [Obsolete("Will be removed")]
        protected static byte[] TimeToBytes(long t) => Utilities.TimeToBytes((uint)t);

        public KeyExpirationTime(bool critical, bool isLongLength, byte[] data)
            : base(SignatureSubpacketTag.KeyExpireTime, critical, isLongLength, data)
        {
        }

        public KeyExpirationTime(bool critical, long seconds)
            : base(SignatureSubpacketTag.KeyExpireTime, critical, isLongLength: false,
                Utilities.TimeToBytes((uint)seconds))
        {
        }

        /**
         * Return the number of seconds after creation time a key is valid for.
         *
         * @return second count for key validity.
         */
        public long Time => Utilities.TimeFromBytes(data);
    }
}
