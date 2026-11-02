using Org.BouncyCastle.Utilities;

namespace Org.BouncyCastle.Pqc.Crypto.Bike
{
    /// <summary>A BIKE private key.</summary>
    public sealed class BikePrivateKeyParameters
        : BikeKeyParameters
    {
        internal readonly byte[] m_h0;
        internal readonly byte[] m_h1;
        internal readonly byte[] m_sigma;

        /// <summary>Create a new <see cref="BikePrivateKeyParameters"/>.</summary>
        /// <param name="bikeParameters">The bike parameters.</param>
        /// <param name="h0">The h 0.</param>
        /// <param name="h1">The h 1.</param>
        /// <param name="sigma">The sigma.</param>
        public BikePrivateKeyParameters(BikeParameters bikeParameters, byte[] h0, byte[] h1, byte[] sigma)
            : base(true, bikeParameters)
        {
            this.m_h0 = Arrays.Clone(h0);
            this.m_h1 = Arrays.Clone(h1);
            this.m_sigma = Arrays.Clone(sigma);
        }

        /// <summary>Return the encoded.</summary>
        public byte[] GetEncoded() => Arrays.ConcatenateAll(m_h0, m_h1, m_sigma);

        /// <summary>Return the h 0.</summary>
        public byte[] GetH0() => Arrays.Clone(m_h0);

        /// <summary>Return the h 1.</summary>
        public byte[] GetH1() => Arrays.Clone(m_h1);

        /// <summary>Return the sigma.</summary>
        public byte[] GetSigma() => Arrays.Clone(m_sigma);
    }
}
