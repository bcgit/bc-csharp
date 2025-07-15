using Org.BouncyCastle.Math;

namespace Org.BouncyCastle.Bcpg
{
    /// <summary>Base class for an EdDSA secret key.</summary>
    public sealed class EdSecretBcpgKey
        : BcpgObject, IBcpgKey
    {
        private readonly MPInteger m_x;

        public EdSecretBcpgKey(BcpgInputStream bcpgIn)
        {
            m_x = new MPInteger(bcpgIn);
        }

        public EdSecretBcpgKey(BigInteger x)
        {
            m_x = new MPInteger(x);
        }

        public BigInteger X => m_x.Value;

        public string Format => "PGP";

        public override byte[] GetEncoded() => BcpgOutputStream.GetEncodedOrNull(m_x);

        public override void Encode(BcpgOutputStream bcpgOut) => m_x.Encode(bcpgOut);
    }
}
