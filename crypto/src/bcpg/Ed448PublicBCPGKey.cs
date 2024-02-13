namespace Org.BouncyCastle.Bcpg
{
    public sealed class Ed448PublicBcpgKey
        : OctetArrayBcpgKey
    {
        // https://www.ietf.org/archive/id/draft-ietf-openpgp-crypto-refresh-13.html#name-algorithm-specific-part-for-ed4
        public const int length = 57;

        public Ed448PublicBcpgKey(BcpgInputStream bcpgIn)
            : base(length, bcpgIn)
        {
        }

        public Ed448PublicBcpgKey(byte[] key)
            : base(length, key)
        {
        }
    }
}
