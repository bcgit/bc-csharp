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

        public SecretSubkeyPacket(PublicKeyPacket pubKeyPacket, SymmetricKeyAlgorithmTag encAlgorithm, S2k s2k,
            byte[] iv, byte[] secKeyData)
            : base(PacketTag.SecretSubkey, pubKeyPacket, encAlgorithm, s2k, iv, secKeyData)
        {
        }

        public SecretSubkeyPacket(PublicKeyPacket pubKeyPacket, SymmetricKeyAlgorithmTag encAlgorithm, int s2kUsage,
            S2k s2k, byte[] iv, byte[] secKeyData)
            : this(pubKeyPacket, encAlgorithm, 0, s2kUsage, s2k, iv, secKeyData)
        {
        }

        public SecretSubkeyPacket(PublicKeyPacket pubKeyPacket, SymmetricKeyAlgorithmTag encAlgorithm,
            AeadAlgorithmTag aeadAlgorithm, int s2kUsage, S2k s2k, byte[] iv, byte[] secKeyData)
            : base(PacketTag.SecretSubkey, pubKeyPacket, encAlgorithm, aeadAlgorithm, s2kUsage, s2k, iv, secKeyData)
        {
        }

        // TODO[api] Remove this redundant override
        public override void Encode(BcpgOutputStream bcpgOut) => base.Encode(bcpgOut);
    }
}
