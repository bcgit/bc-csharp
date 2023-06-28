using Org.BouncyCastle.Utilities;

namespace Org.BouncyCastle.Pqc.Crypto.Bike
{
    public sealed class BikePrivateKeyParameters
        : BikeKeyParameters
    {
        internal readonly byte[] m_h0;
        internal readonly byte[] m_h1;
        internal readonly byte[] m_sigma;

        public BikePrivateKeyParameters(BikeParameters bikeParameters, byte[] h0, byte[] h1, byte[] sigma)
            : base(true, bikeParameters)
        {
            this.m_h0 = Arrays.Clone(h0);
            this.m_h1 = Arrays.Clone(h1);
            this.m_sigma = Arrays.Clone(sigma);
        }

        public byte[] GetEncoded() => Arrays.ConcatenateAll(m_h0, m_h1, m_sigma);

        public byte[] GetH0() => Arrays.Clone(m_h0);

        public byte[] GetH1() => Arrays.Clone(m_h1);

        public byte[] GetSigma() => Arrays.Clone(m_sigma);
    }
}
