namespace Org.BouncyCastle.Bcpg
{
    /// <summary>
    /// Secret key of type <see cref="PublicKeyAlgorithmTag.Ed448"/>.
    /// </summary>
    /// <remarks>
    /// This type was introduced with RFC9580 and can be used with v4, v6 keys. Note however, that legacy
    /// implementations might not understand this key type yet. For a key type compatible with legacy v4
    /// implementations, see <see cref="EdSecretBcpgKey"/> with <see cref="PublicKeyAlgorithmTag.EdDsa_Legacy"/>.
    /// <para>
    /// <see href="https://www.rfc-editor.org/rfc/rfc9580.html#name-algorithm-specific-part-for-ed4">
    /// OpenPGP - Algorithm-Specific Part for Ed448 Keys
    /// </see>
    /// </para>
    /// </remarks>
    public sealed class Ed448SecretBcpgKey
        : OctetArrayBcpgKey
    {
        public static readonly int Length = 57;

        public Ed448SecretBcpgKey(BcpgInputStream bcpgIn)
            : base(Length, bcpgIn)
        {
        }

        public Ed448SecretBcpgKey(byte[] key)
            : base(Length, key)
        {
        }
    }
}
