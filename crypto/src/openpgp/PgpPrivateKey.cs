using System;

using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Utilities;

namespace Org.BouncyCastle.Bcpg.OpenPgp
{
	/// <remarks>General class to contain a private key for use with other OpenPGP objects.</remarks>
    public class PgpPrivateKey
    {
        private readonly int version;
        private readonly long keyID;
        private readonly byte[] fingerprint;
        private readonly PublicKeyPacket publicKeyPacket;
        private readonly AsymmetricKeyParameter privateKey;

        /// <summary>
        /// Create a PgpPrivateKey from  associated public key, and a regular private key.
        /// </summary>
        /// <param name="pubKey">the corresponding public key</param>
        /// <param name="privateKey">the private key data packet to be associated with this private key.</param>
        public PgpPrivateKey(PgpPublicKey pubKey, AsymmetricKeyParameter privateKey)
            :this(pubKey.KeyId, pubKey.GetFingerprint(), pubKey.PublicKeyPacket, privateKey)
        {
        }

        private PgpPrivateKey(
            long keyID,
            byte[] fingerprint,
            PublicKeyPacket publicKeyPacket,
            AsymmetricKeyParameter privateKey)
        {
            if (!privateKey.IsPrivate)
                throw new ArgumentException("Expected a private key", nameof(privateKey));

            this.version = publicKeyPacket.Version;
            this.keyID = keyID;
            this.fingerprint = fingerprint;
            this.publicKeyPacket = publicKeyPacket;
            this.privateKey = privateKey;
        }

        /// <summary>
		/// Create a PgpPrivateKey from a keyID, the associated public data packet, and a regular private key.
		/// </summary>
		/// <param name="keyID">ID of the corresponding public key.</param>
        /// <param name="publicKeyPacket">the public key data packet to be associated with this private key.</param>
        /// <param name="privateKey">the private key data packet to be associated with this private key.</param>
        public PgpPrivateKey(
            long                    keyID,
            PublicKeyPacket         publicKeyPacket,
            AsymmetricKeyParameter	privateKey)
            :this(keyID, null, publicKeyPacket, privateKey)
        {
        }

        /// <summary>The keyId associated with the contained private key.</summary>
        public long KeyId
        {
			get { return keyID; }
        }

        /// <summary>
        /// The version of the contained private key.
        /// </summary>
        public int Version {
            get { return version; }
        }

        /// <summary>
        /// The Fingerprint associated with the contained private key.
        /// </summary>
        public byte[] GetFingerprint()
        {
            return Arrays.Clone(fingerprint);
        }

        /// <summary>The public key packet associated with this private key, if available.</summary>
        public PublicKeyPacket PublicKeyPacket
        {
            get { return publicKeyPacket; }
        }

        /// <summary>The contained private key.</summary>
        public AsymmetricKeyParameter Key
        {
			get { return privateKey; }
        }
    }
}
