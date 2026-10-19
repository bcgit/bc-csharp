namespace Org.BouncyCastle.Bcpg
{
    /// <summary>
    /// Public key of type <see cref="PublicKeyAlgorithmTag.Ed25519"/>.
    /// </summary>
    /// <remarks>
    /// This type was introduced with RFC9580 and can be used with v4, v6 keys. Note however, that legacy
    /// implementations might not understand this key type yet. For a key type compatible with legacy v4
    /// implementations, see <see cref="EdDsaPublicBcpgKey"/> with <see cref="PublicKeyAlgorithmTag.EdDsa_Legacy"/>.
    /// <para>
    /// <see href="https://www.rfc-editor.org/rfc/rfc9580.html#name-algorithm-specific-part-for-ed2">
    /// OpenPGP - Algorithm-Specific Part for Ed25519 Keys
    /// </see>
    /// </para>
    /// </remarks>
    public sealed class Ed25519PublicBcpgKey
        : OctetArrayBcpgKey
    {
        /// <summary>The length in bytes of the key.</summary>
        public static readonly int Length = 32;

        /// <summary>Create a new <see cref="Ed25519PublicBcpgKey"/>.</summary>
        /// <param name="bcpgIn">The bcpg in.</param>
        public Ed25519PublicBcpgKey(BcpgInputStream bcpgIn)
            : base(Length, bcpgIn)
        {
        }

        /// <summary>Create a new <see cref="Ed25519PublicBcpgKey"/>.</summary>
        /// <param name="key">The key.</param>
        public Ed25519PublicBcpgKey(byte[] key)
            : base(Length, key)
        {
        }
    }
}
