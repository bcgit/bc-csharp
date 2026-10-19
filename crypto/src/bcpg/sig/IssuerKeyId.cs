using System;

using Org.BouncyCastle.Crypto.Utilities;

namespace Org.BouncyCastle.Bcpg.Sig
{
    /// <summary>Signature Subpacket containing the key-id of the issuers signing (sub-) key.</summary>
    /// <remarks>
    /// If the version of that key is greater than 4, this subpacket MUST NOT be included in the signature. For these
    /// keys, consider the <see cref="IssuerFingerprint"/> subpacket instead.
    /// <para>
    /// <see href="https://datatracker.ietf.org/doc/html/rfc4880#section-5.2.3.5">RFC4880 - Issuer</see>
    /// <see href="https://www.rfc-editor.org/rfc/rfc9580.html#name-issuer-key-id">RFC9580 - Issuer Key ID</see>
    /// </para>
    /// </remarks>
    public class IssuerKeyId
        : SignatureSubpacket
    {
        /// <summary>Convert a key ID to its encoding.</summary>
        /// <param name="keyId">The key ID.</param>
        /// <returns>The encoding.</returns>
        [Obsolete("Will be removed")]
        protected static byte[] KeyIdToBytes(long keyId) => Pack.UInt64_To_BE((ulong)keyId);

        /// <summary>Create a new <see cref="IssuerKeyId"/>.</summary>
        /// <param name="critical">Whether the extension is critical.</param>
        /// <param name="isLongLength">true if is long length, false otherwise.</param>
        /// <param name="data">The data.</param>
        public IssuerKeyId(bool critical, bool isLongLength, byte[] data)
            : base(SignatureSubpacketTag.IssuerKeyId, critical, isLongLength, data)
        {
        }

        /// <summary>Create a new <see cref="IssuerKeyId"/>.</summary>
        /// <param name="critical">Whether the extension is critical.</param>
        /// <param name="keyId">The key id.</param>
        public IssuerKeyId(bool critical, long keyId)
            : base(SignatureSubpacketTag.IssuerKeyId, critical, isLongLength: false, Pack.UInt64_To_BE((ulong)keyId))
        {
        }

        /// <summary>Return the key ID.</summary>
        public long GetKeyID() => FingerprintUtilities.ReadKeyID(Data, 0);

        /// <summary>Gets the key id.</summary>
        [Obsolete("Use 'GetKeyID' instead")]
        public long KeyId => GetKeyID();
    }
}
