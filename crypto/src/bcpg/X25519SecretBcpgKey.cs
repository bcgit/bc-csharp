namespace Org.BouncyCastle.Bcpg
{
    /// <summary>
    /// Secret key of type <see cref="PublicKeyAlgorithmTag.X25519"/>.
    /// </summary>
    /// <remarks>
    /// This type was introduced with RFC9580 and can be used with v4, v6 keys. Note however, that legacy
    /// implementations might not understand this key type yet. For a key type compatible with legacy v4
    /// implementations, see <see cref="ECSecretBcpgKey"/> with <see cref="PublicKeyAlgorithmTag.ECDH"/>.
    /// <para>
    /// <see href="https://www.rfc-editor.org/rfc/rfc9580.html#name-algorithm-specific-part-for-x">
    /// OpenPGP - Algorithm-Specific Part for X25519 Keys
    /// </see>
    /// </para>
    /// </remarks>
    public sealed class X25519SecretBcpgKey
        : OctetArrayBcpgKey
    {
        public static readonly int Length = 32;

        /// <summary>Create a new <see cref="X25519SecretBcpgKey"/>.</summary>
        /// <param name="bcpgIn">The bcpg in.</param>
        public X25519SecretBcpgKey(BcpgInputStream bcpgIn)
            : base(Length, bcpgIn)
        {
        }

        /// <summary>Create a new <see cref="X25519SecretBcpgKey"/>.</summary>
        /// <param name="key">The key.</param>
        public X25519SecretBcpgKey(byte[] key)
            : base(Length, key)
        {
        }
    }
}
