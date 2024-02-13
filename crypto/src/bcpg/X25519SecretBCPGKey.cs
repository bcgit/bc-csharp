namespace Org.BouncyCastle.Bcpg
{
    public sealed class X25519SecretBcpgKey
        : OctetArrayBcpgKey
    {
        // https://www.ietf.org/archive/id/draft-ietf-openpgp-crypto-refresh-13.html#name-algorithm-specific-part-for-x
        public const int length = 32;

        public X25519SecretBcpgKey(BcpgInputStream bcpgIn)
            : base(length, bcpgIn)
        {
        }

        public X25519SecretBcpgKey(byte[] key)
            : base(length, key)
        {
        }
    }
}