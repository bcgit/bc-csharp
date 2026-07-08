namespace Org.BouncyCastle.Bcpg
{
    /// <summary>Key class for unknown/unsupported OpenPGP key types.</summary>
    public class UnknownBcpgKey
        : OctetArrayBcpgKey
    {
        public UnknownBcpgKey(int length, BcpgInputStream bcpgIn)
            : base(length, bcpgIn)
        {
        }

        public UnknownBcpgKey(int length, byte[] key)
            : base(length, key)
        {
        }
    }
}
