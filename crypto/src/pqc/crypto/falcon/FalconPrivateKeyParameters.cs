using Org.BouncyCastle.Utilities;


namespace Org.BouncyCastle.Pqc.Crypto.Falcon
{
    public sealed class FalconPrivateKeyParameters
        : FalconKeyParameters
    {
        private readonly byte[] m_pk;
        private readonly byte[] m_f;
        private readonly byte[] m_g;
        private readonly byte[] m_F;

        public FalconPrivateKeyParameters(FalconParameters parameters, byte[] f, byte[] g, byte[] F, byte[] pk_encoded)
            : base(true, parameters)
        {
            m_f = Arrays.CopyBuffer(f);
            m_g = Arrays.CopyBuffer(g);
            m_F = Arrays.CopyBuffer(F);
            m_pk = Arrays.CopyBuffer(pk_encoded);
        }

        public byte[] GetEncoded() => Arrays.ConcatenateAll(m_f, m_g, m_F);

        public byte[] GetPublicKey() => Arrays.InternalCopyBuffer(m_pk);

        /// <summary>Return the matching public key parameters.</summary>
        public FalconPublicKeyParameters GetPublicKeyParameters() => new FalconPublicKeyParameters(Parameters, m_pk);

        public byte[] GetSpolyLittleF() => Arrays.InternalCopyBuffer(m_f);

        public byte[] GetG() => Arrays.InternalCopyBuffer(m_g);

        public byte[] GetSpolyBigF() => Arrays.InternalCopyBuffer(m_F);
    }
}
