namespace Org.BouncyCastle.Bcpg
{
    /// <summary>
    /// Public key of type <see cref="PublicKeyAlgorithmTag.Ed448"/>.
    /// </summary>
    /// <remarks>
    /// This type was introduced with RFC9580 and can be used with v4, v6 keys. Note however, that legacy
    /// implementations might not understand this key type yet. For a key type compatible with legacy v4
    /// implementations, see <see cref="EdDsaPublicBcpgKey"/> with <see cref="PublicKeyAlgorithmTag.EdDsa_Legacy"/>.
    /// <para>
    /// <see href="https://www.rfc-editor.org/rfc/rfc9580.html#name-algorithm-specific-part-for-ed4">
    /// OpenPGP - Algorithm-Specific Part for Ed448 Keys
    /// </see>
    /// </para>
    /// </remarks>
    public sealed class Ed448PublicBcpgKey
        : OctetArrayBcpgKey
    {
        /// <summary>The length in bytes of the key.</summary>
        public static readonly int Length = 57;

        /// <summary>Create a new <see cref="Ed448PublicBcpgKey"/>.</summary>
        /// <param name="bcpgIn">The stream to read the encoding from.</param>
        public Ed448PublicBcpgKey(BcpgInputStream bcpgIn)
            : base(Length, bcpgIn)
        {
        }

        /// <summary>Create a new <see cref="Ed448PublicBcpgKey"/>.</summary>
        /// <param name="key">The key.</param>
        public Ed448PublicBcpgKey(byte[] key)
            : base(Length, key)
        {
        }
    }
}
