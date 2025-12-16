using System;

using Org.BouncyCastle.Utilities;

namespace Org.BouncyCastle.Crypto.Parameters
{
    public class Dstu4145Parameters
        : ECDomainParameters
    {
        private readonly byte[] m_dke;

        public Dstu4145Parameters(ECDomainParameters ecParameters, byte[] dke)
            : base(ecParameters.Curve, ecParameters.G, ecParameters.N, ecParameters.H, ecParameters.GetSeed())
        {
            m_dke = CopyDke(dke);
        }

        public virtual byte[] GetDke() => CopyDke(m_dke);

        private static byte[] CopyDke(byte[] dke) => Arrays.Clone(dke);
    }
}
