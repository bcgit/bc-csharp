namespace Org.BouncyCastle.Bcpg
{
    public sealed class Ed448PublicBcpgKey
        : OctetArrayBcpgKey
    {
        // https://www.rfc-editor.org/rfc/rfc9580#name-algorithm-specific-part-for-ed4
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
