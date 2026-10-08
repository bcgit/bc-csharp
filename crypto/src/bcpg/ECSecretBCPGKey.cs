using Org.BouncyCastle.Math;

namespace Org.BouncyCastle.Bcpg
{
    /// <summary>Base class for an EC Secret Key.</summary>
    public class ECSecretBcpgKey
        : BcpgObject, IBcpgKey
    {
        private readonly MPInteger m_x;

        public ECSecretBcpgKey(BcpgInputStream bcpgIn)
            : this(bcpgIn, strict: false)
        {
        }

        /// <param name="bcpgIn">The input.</param>
        /// <param name="strict">Reject an MPI that is not minimal, as RFC 9580 3.2 requires for version 6 keys.</param>
        internal ECSecretBcpgKey(BcpgInputStream bcpgIn, bool strict)
        {
            m_x = new MPInteger(bcpgIn, strict);
        }

        public ECSecretBcpgKey(BigInteger x)
        {
            m_x = new MPInteger(x);
        }

        public virtual BigInteger X => m_x.Value;

        /// <summary>The format, as a string, always "PGP".</summary>
        public string Format => "PGP";

        /// <summary>Return the standard PGP encoding of the key.</summary>
        public override byte[] GetEncoded() => BcpgOutputStream.GetEncodedOrNull(m_x);

        public override void Encode(BcpgOutputStream bcpgOut) => m_x.Encode(bcpgOut);
    }
}
