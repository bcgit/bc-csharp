namespace Org.BouncyCastle.Bcpg
{
    public sealed class X448SecretBcpgKey
        : OctetArrayBcpgKey
    {
        // https://www.ietf.org/archive/id/draft-ietf-openpgp-crypto-refresh-13.html#name-algorithm-specific-part-for-x4
        public const int length = 56;

        public X448SecretBcpgKey(BcpgInputStream bcpgIn)
            : base(length, bcpgIn)
        {
        }

        public X448SecretBcpgKey(byte[] key)
            : base(length, key)
        {
        }
    }
}