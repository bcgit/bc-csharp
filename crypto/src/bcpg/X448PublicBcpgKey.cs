namespace Org.BouncyCastle.Bcpg
{
    /// <summary>
    /// Public key of type <see cref="PublicKeyAlgorithmTag.X448"/>.
    /// </summary>
    /// <remarks>
    /// This type was introduced with RFC9580 and can be used with v4, v6 keys. Note however, that legacy
    /// implementations might not understand this key type yet. For a key type compatible with legacy v4
    /// implementations, see <see cref="ECDHPublicBcpgKey"/> with <see cref="PublicKeyAlgorithmTag.ECDH"/>.
    /// <para>
    /// <see href="https://www.rfc-editor.org/rfc/rfc9580.html#name-algorithm-specific-part-for-x4">
    /// OpenPGP - Algorithm-Specific Part for X448 Keys
    /// </see>
    /// </para>
    /// </remarks>
    public sealed class X448PublicBcpgKey
        : OctetArrayBcpgKey
    {
        /// <summary>The length in bytes of the key.</summary>
        public static readonly int Length = 56;

        /// <summary>Create a new <see cref="X448PublicBcpgKey"/>.</summary>
        /// <param name="bcpgIn">The stream to read the encoding from.</param>
        public X448PublicBcpgKey(BcpgInputStream bcpgIn)
            : base(Length, bcpgIn)
        {
        }

        /// <summary>Create a new <see cref="X448PublicBcpgKey"/>.</summary>
        /// <param name="key">The key.</param>
        public X448PublicBcpgKey(byte[] key)
            : base(Length, key)
        {
        }
    }
}
