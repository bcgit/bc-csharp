using System;

using Org.BouncyCastle.Crypto;

namespace Org.BouncyCastle.Bcpg.OpenPgp
{
    /// <remarks>General class to contain a private key for use with other OpenPGP objects.</remarks>
    public class PgpPrivateKey
    {
        private readonly ulong m_keyID;
        private readonly PublicKeyPacket m_publicKeyPacket;
        private readonly AsymmetricKeyParameter m_privateKey;

        /// <summary>
        /// Create a PgpPrivateKey from a keyID, the associated public data packet, and a regular private key.
        /// </summary>
        /// <param name="keyID">ID of the corresponding public key.</param>
        /// <param name="publicKeyPacket">the public key data packet to be associated with this private key.</param>
        /// <param name="privateKey">the private key data packet to be associated with this private key.</param>
        public PgpPrivateKey(long keyID, PublicKeyPacket publicKeyPacket, AsymmetricKeyParameter privateKey)
        {
            if (!privateKey.IsPrivate)
                throw new ArgumentException("Expected a private key", nameof(privateKey));

            m_keyID = (ulong)keyID;
            m_publicKeyPacket = publicKeyPacket;
            m_privateKey = privateKey;
        }

        /// <summary>The Key ID associated with the contained private key.</summary>
        /// <remarks>
        /// A Key ID is an 8-octet scalar. We convert it (big-endian) to an Int64 (UInt64 is not CLS compliant).
        /// </remarks>
        public long KeyId => (long)m_keyID;

        /// <summary>The public key packet associated with this private key, if available.</summary>
        public PublicKeyPacket PublicKeyPacket => m_publicKeyPacket;

        /// <summary>The contained private key.</summary>
        public AsymmetricKeyParameter Key => m_privateKey;
    }
}
