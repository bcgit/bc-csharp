namespace Org.BouncyCastle.Bcpg
{
    /// <summary>
    /// Secret key of type <see cref="PublicKeyAlgorithmTag.X448"/>.
    /// </summary>
    /// <remarks>
    /// This type was introduced with RFC9580 and can be used with v4, v6 keys. Note however, that legacy
    /// implementations might not understand this key type yet. For a key type compatible with legacy v4
    /// implementations, see <see cref="ECSecretBCPGKey"/> with <see cref="PublicKeyAlgorithmTag.ECDH"/>.
    /// <para>
    /// <see href="https://www.rfc-editor.org/rfc/rfc9580.html#name-algorithm-specific-part-for-x4">
    /// OpenPGP - Algorithm-Specific Part for X448 Keys
    /// </see>
    /// </para>
    /// </remarks>
    public sealed class X448SecretBcpgKey
        : OctetArrayBcpgKey
    {
        public static readonly int Length = 56;

        public X448SecretBcpgKey(BcpgInputStream bcpgIn)
            : base(Length, bcpgIn)
        {
        }

        public X448SecretBcpgKey(byte[] key)
            : base(Length, key)
        {
        }
    }
}
