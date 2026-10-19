using System;

namespace Org.BouncyCastle.Bcpg.Sig
{
    /// <summary>
    /// Signature Subpacket containing the number of seconds after the signatures creation time after which the
    /// signature expires.
    /// </summary>
    /// <remarks>
    /// <see href="https://datatracker.ietf.org/doc/html/rfc4880#section-5.2.3.10">
    /// RFC4880 - Signature Expiration Time
    /// </see>
    /// <see href="https://www.rfc-editor.org/rfc/rfc9580.html#name-signature-expiration-time">
    /// RFC9580 - Signature Expiration Time
    /// </see>
    /// </remarks>
    public class SignatureExpirationTime
        : SignatureSubpacket
    {
        /// <summary>Convert a time in seconds to its encoding.</summary>
        /// <param name="t">The time in seconds.</param>
        /// <returns>The encoding.</returns>
        [Obsolete("Will be removed")]
        protected static byte[] TimeToBytes(long t) => Utilities.TimeToBytes((uint)t);

        /// <summary>Create a new <see cref="SignatureExpirationTime"/>.</summary>
        /// <param name="critical">Whether the extension is critical.</param>
        /// <param name="isLongLength">true if is long length, false otherwise.</param>
        /// <param name="data">The data.</param>
        public SignatureExpirationTime(bool critical, bool isLongLength, byte[] data)
            : base(SignatureSubpacketTag.ExpireTime, critical, isLongLength, VerifyData(data))
        {
        }

        /// <summary>Create a new <see cref="SignatureExpirationTime"/>.</summary>
        /// <param name="critical">Whether the extension is critical.</param>
        /// <param name="seconds">The seconds.</param>
        public SignatureExpirationTime(bool critical, long seconds)
            : base(SignatureSubpacketTag.ExpireTime, critical, isLongLength: false,
                Utilities.TimeToBytes((uint)seconds))
        {
        }

        private static byte[] VerifyData(byte[] data)
        {
            if (data.Length != 4)
                throw new ArgumentException("Malformed data length. Expected 4, got " + data.Length, nameof(data));

            return data;
        }

        /**
         * return time in seconds before signature expires after creation time.
         */
        public long Time => Utilities.TimeFromBytes(Data);
    }
}
