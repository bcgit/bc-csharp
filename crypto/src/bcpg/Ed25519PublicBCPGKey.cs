namespace Org.BouncyCastle.Bcpg
{
    public sealed class Ed25519PublicBcpgKey
        : OctetArrayBcpgKey
    {
        // https://www.rfc-editor.org/rfc/rfc9580#name-algorithm-specific-part-for-ed2
        public const int length = 32;

        public Ed25519PublicBcpgKey(BcpgInputStream bcpgIn)
            : base(length, bcpgIn)
        {
        }

        public Ed25519PublicBcpgKey(byte[] key)
            :base(length, key)
        {
        }
    }
}