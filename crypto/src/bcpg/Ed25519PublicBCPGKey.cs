namespace Org.BouncyCastle.Bcpg
{
    public sealed class Ed25519PublicBcpgKey
        : OctetArrayBcpgKey
    {
        // https://www.ietf.org/archive/id/draft-ietf-openpgp-crypto-refresh-13.html#name-algorithm-specific-part-for-ed2
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