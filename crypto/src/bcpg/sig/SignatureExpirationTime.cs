using Org.BouncyCastle.Crypto.Utilities;

namespace Org.BouncyCastle.Bcpg.Sig
{
    /**
    * packet giving signature expiration time.
    */
    public class SignatureExpirationTime
        : SignatureSubpacket
    {
        protected static byte[] TimeToBytes(long t)
        {
            return Pack.UInt32_To_BE((uint)t);
        }

        public SignatureExpirationTime(bool critical, bool isLongLength, byte[] data)
            : base(SignatureSubpacketTag.ExpireTime, critical, isLongLength, data)
        {
        }

        public SignatureExpirationTime(bool critical, long seconds)
            : base(SignatureSubpacketTag.ExpireTime, critical, false, TimeToBytes(seconds))
        {
        }

        /**
        * return time in seconds before signature expires after creation time.
        */
        public long Time => Pack.BE_To_UInt32(data, 0);
    }
}
