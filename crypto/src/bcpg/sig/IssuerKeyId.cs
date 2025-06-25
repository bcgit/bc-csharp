using System;

using Org.BouncyCastle.Crypto.Utilities;

namespace Org.BouncyCastle.Bcpg.Sig
{
    /**
    * packet giving signature creation time.
    */
    public class IssuerKeyId
        : SignatureSubpacket
    {
        [Obsolete("Will be removed")]
        protected static byte[] KeyIdToBytes(long keyId) => Pack.UInt64_To_BE((ulong)keyId);

        public IssuerKeyId(bool critical, bool isLongLength, byte[] data)
            : base(SignatureSubpacketTag.IssuerKeyId, critical, isLongLength, data)
        {
        }

        public IssuerKeyId(bool critical, long keyId)
            : base(SignatureSubpacketTag.IssuerKeyId, critical, isLongLength: false, Pack.UInt64_To_BE((ulong)keyId))
        {
        }

        /// <remarks>
        /// A Key ID is an 8-octet scalar. We convert it (big-endian) to an Int64 (UInt64 is not CLS compliant).
        /// </remarks>
        public long KeyId => (long)Pack.BE_To_UInt64(data);
    }
}
