namespace Org.BouncyCastle.Bcpg
{
    public sealed class X25519PublicBcpgKey
        : OctetArrayBcpgKey
    {
        // https://www.rfc-editor.org/rfc/rfc9580#name-algorithm-specific-part-for-x
        public const int length = 32;

        public X25519PublicBcpgKey(BcpgInputStream bcpgIn)
            : base(length, bcpgIn)
        {
        }

        public X25519PublicBcpgKey(byte[] key)
            : base(length, key)
        {
        }
    }
}