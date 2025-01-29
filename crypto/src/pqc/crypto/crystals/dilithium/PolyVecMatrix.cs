using System.Diagnostics;

namespace Org.BouncyCastle.Pqc.Crypto.Crystals.Dilithium
{
    internal class PolyVecMatrix
    {
        private readonly PolyVec[] m_matrix;

        public PolyVecMatrix(DilithiumEngine engine)
        {
            int K = engine.K;
            int L = engine.L;

            m_matrix = new PolyVec[K];
            for (int i = 0; i < K; i++)
            {
                m_matrix[i] = new PolyVec(engine, L);
            }
        }

        public void ExpandMatrix(byte[] rho)
        {
            for (int i = 0; i < m_matrix.Length; ++i)
            {
                m_matrix[i].UniformBlocks(rho, i << 8);
            }
        }

        public void PointwiseMontgomery(PolyVec t, PolyVec v)
        {
            Debug.Assert(t.Length == m_matrix.Length);

            for (int i = 0; i < m_matrix.Length; ++i)
            {
                t[i].PointwiseAccountMontgomery(m_matrix[i], v);
            }
        }
    }
}
