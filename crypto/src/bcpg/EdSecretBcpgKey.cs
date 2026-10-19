using Org.BouncyCastle.Math;

namespace Org.BouncyCastle.Bcpg
{
    /// <summary>Base class for an EdDSA secret key.</summary>
    public sealed class EdSecretBcpgKey
        : BcpgObject, IBcpgKey
    {
        private readonly MPInteger m_x;

        /// <summary>Create a new <see cref="EdSecretBcpgKey"/>.</summary>
        /// <param name="bcpgIn">The stream to read the encoding from.</param>
        public EdSecretBcpgKey(BcpgInputStream bcpgIn)
        {
            m_x = new MPInteger(bcpgIn);
        }

        /// <summary>Create a new <see cref="EdSecretBcpgKey"/>.</summary>
        /// <param name="x">The first operand.</param>
        public EdSecretBcpgKey(BigInteger x)
        {
            m_x = new MPInteger(x);
        }

        /// <summary>Gets the x.</summary>
        public BigInteger X => m_x.Value;

        /// <inheritdoc/>
        public string Format => "PGP";

        /// <inheritdoc/>
        public override byte[] GetEncoded() => BcpgOutputStream.GetEncodedOrNull(m_x);

        /// <inheritdoc/>
        public override void Encode(BcpgOutputStream bcpgOut) => m_x.Encode(bcpgOut);
    }
}
