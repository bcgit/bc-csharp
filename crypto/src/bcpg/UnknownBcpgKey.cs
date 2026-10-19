namespace Org.BouncyCastle.Bcpg
{
    /// <summary>Key class for unknown/unsupported OpenPGP key types.</summary>
    public class UnknownBcpgKey
        : OctetArrayBcpgKey
    {
        /// <summary>Create a new <see cref="UnknownBcpgKey"/>.</summary>
        /// <param name="length">The length in bytes.</param>
        /// <param name="bcpgIn">The bcpg in.</param>
        public UnknownBcpgKey(int length, BcpgInputStream bcpgIn)
            : base(length, bcpgIn)
        {
        }

        /// <summary>Create a new <see cref="UnknownBcpgKey"/>.</summary>
        /// <param name="length">The length in bytes.</param>
        /// <param name="key">The key.</param>
        public UnknownBcpgKey(int length, byte[] key)
            : base(length, key)
        {
        }
    }
}
