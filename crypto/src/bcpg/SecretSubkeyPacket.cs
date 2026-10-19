namespace Org.BouncyCastle.Bcpg
{
    /// <summary>Basic packet for a PGP secret key.</summary>
    public class SecretSubkeyPacket
        : SecretKeyPacket
    {
        internal SecretSubkeyPacket(BcpgInputStream bcpgIn)
            : this(bcpgIn, newPacketFormat: false)
        {
        }

        internal SecretSubkeyPacket(BcpgInputStream bcpgIn, bool newPacketFormat)
            : base(PacketTag.SecretSubkey, bcpgIn, newPacketFormat)
        {
        }

        /// <summary>Create a new <see cref="SecretSubkeyPacket"/>.</summary>
        /// <param name="pubKeyPacket">The pub key packet.</param>
        /// <param name="encAlgorithm">The enc algorithm.</param>
        /// <param name="s2k">The s 2 k.</param>
        /// <param name="iv">The initialization vector.</param>
        /// <param name="secKeyData">The sec key data.</param>
        public SecretSubkeyPacket(PublicKeyPacket pubKeyPacket, SymmetricKeyAlgorithmTag encAlgorithm, S2k s2k,
            byte[] iv, byte[] secKeyData)
            : base(PacketTag.SecretSubkey, pubKeyPacket, encAlgorithm, s2k, iv, secKeyData)
        {
        }

        /// <summary>Create a new <see cref="SecretSubkeyPacket"/>.</summary>
        /// <param name="pubKeyPacket">The pub key packet.</param>
        /// <param name="encAlgorithm">The enc algorithm.</param>
        /// <param name="s2kUsage">The s 2 k usage.</param>
        /// <param name="s2k">The s 2 k.</param>
        /// <param name="iv">The initialization vector.</param>
        /// <param name="secKeyData">The sec key data.</param>
        public SecretSubkeyPacket(PublicKeyPacket pubKeyPacket, SymmetricKeyAlgorithmTag encAlgorithm, int s2kUsage,
            S2k s2k, byte[] iv, byte[] secKeyData)
            : this(pubKeyPacket, encAlgorithm, 0, s2kUsage, s2k, iv, secKeyData)
        {
        }

        /// <summary>Create a new <see cref="SecretSubkeyPacket"/>.</summary>
        /// <param name="pubKeyPacket">The pub key packet.</param>
        /// <param name="encAlgorithm">The enc algorithm.</param>
        /// <param name="aeadAlgorithm">The aead algorithm.</param>
        /// <param name="s2kUsage">The s 2 k usage.</param>
        /// <param name="s2k">The s 2 k.</param>
        /// <param name="iv">The initialization vector.</param>
        /// <param name="secKeyData">The sec key data.</param>
        public SecretSubkeyPacket(PublicKeyPacket pubKeyPacket, SymmetricKeyAlgorithmTag encAlgorithm,
            AeadAlgorithmTag aeadAlgorithm, int s2kUsage, S2k s2k, byte[] iv, byte[] secKeyData)
            : base(PacketTag.SecretSubkey, pubKeyPacket, encAlgorithm, aeadAlgorithm, s2kUsage, s2k, iv, secKeyData)
        {
        }

        /// <inheritdoc/>
        // TODO[api] Remove this redundant override
        public override void Encode(BcpgOutputStream bcpgOut) => base.Encode(bcpgOut);
    }
}
