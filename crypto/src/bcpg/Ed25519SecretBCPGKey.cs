namespace Org.BouncyCastle.Bcpg
{
    public sealed class Ed25519SecretBcpgKey
        : OctetArrayBcpgKey
    {
        // https://www.rfc-editor.org/rfc/rfc9580#name-algorithm-specific-part-for-ed2
        public const int length = 32;

        public Ed25519SecretBcpgKey(BcpgInputStream bcpgIn)
            : base(length, bcpgIn)
        {
        }

        public Ed25519SecretBcpgKey(byte[] key)
            : base(length, key)
        {
        }
    }
}