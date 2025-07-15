namespace Org.BouncyCastle.Bcpg
{
    /// <summary>Basic packet for a PGP secret key.</summary>
    public class SecretSubkeyPacket
        : SecretKeyPacket
    {
        internal SecretSubkeyPacket(BcpgInputStream bcpgIn)
            : base(bcpgIn)
        {
        }

        public SecretSubkeyPacket(PublicKeyPacket pubKeyPacket, SymmetricKeyAlgorithmTag encAlgorithm, S2k s2k,
            byte[] iv, byte[] secKeyData)
            : base(pubKeyPacket, encAlgorithm, s2k, iv, secKeyData)
        {
        }

        public SecretSubkeyPacket(PublicKeyPacket pubKeyPacket, SymmetricKeyAlgorithmTag encAlgorithm, int s2kUsage,
            S2k s2k, byte[] iv, byte[] secKeyData)
            : base(pubKeyPacket, encAlgorithm, s2kUsage, s2k, iv, secKeyData)
        {
        }

        public override void Encode(BcpgOutputStream bcpgOut) =>
            bcpgOut.WritePacket(PacketTag.SecretSubkey, GetEncodedContents());
    }
}
