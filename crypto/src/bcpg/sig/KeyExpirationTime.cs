using System;

namespace Org.BouncyCastle.Bcpg.Sig
{
    /// <summary>
    /// Signature Subpacket containing the number of seconds after the key's creation date, after which the key expires.
    /// </summary>
    /// <remarks>
    /// The special value of <c>0</c> means that the key never expires.
    /// <para>
    /// <see href="https://datatracker.ietf.org/doc/html/rfc4880#section-5.2.3.6">
    /// RFC4880 - Key Expiration Time
    /// </see>
    /// <see href="https://www.rfc-editor.org/rfc/rfc9580.html#name-key-expiration-time">
    /// RFC9580 - Key Expiration Time
    /// </see>
    /// </para>
    /// </remarks>
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
        public long Time => Utilities.TimeFromBytes(Data);
    }
}
