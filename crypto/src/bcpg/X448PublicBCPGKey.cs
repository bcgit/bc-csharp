namespace Org.BouncyCastle.Bcpg
{
    public sealed class X448PublicBcpgKey
        : OctetArrayBcpgKey
    {
        // https://www.rfc-editor.org/rfc/rfc9580#name-algorithm-specific-part-for-x4
        public const int length = 56;

        public X448PublicBcpgKey(BcpgInputStream bcpgIn)
            : base(length, bcpgIn)
        {
        }

        public X448PublicBcpgKey(byte[] key)
            : base(length, key)
        {
        }
    }
}