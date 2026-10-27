using System;

using Org.BouncyCastle.Utilities;

namespace Org.BouncyCastle.Crypto.Parameters
{
    /// <summary>Domain parameters for DSTU 4145-2002.</summary>
    public class Dstu4145Parameters
        : ECDomainParameters
    {
        private readonly byte[] m_dke;

        /// <summary>Create a new <see cref="Dstu4145Parameters"/>.</summary>
        /// <param name="ecParameters">The ec parameters.</param>
        /// <param name="dke">The dke.</param>
        public Dstu4145Parameters(ECDomainParameters ecParameters, byte[] dke)
            : base(ecParameters.Curve, ecParameters.G, ecParameters.N, ecParameters.H, ecParameters.GetSeed())
        {
            m_dke = CopyDke(dke);
        }

        /// <summary>Return the dke.</summary>
        public virtual byte[] GetDke() => CopyDke(m_dke);

        private static byte[] CopyDke(byte[] dke) => Arrays.Clone(dke);
    }
}
