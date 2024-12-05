using System.Diagnostics;

namespace Org.BouncyCastle.Pqc.Crypto.Crystals.Dilithium
{
    internal class PolyVecMatrix
    {
        private int K, L;
        internal PolyVec[] Matrix;

        public PolyVecMatrix(DilithiumEngine engine)
        {
            K = engine.K;
            L = engine.L;
            Matrix = new PolyVec[K];

            for (int i = 0; i < K; i++)
            {
                Matrix[i] = new PolyVec(engine, L);
            }
        }

        public void ExpandMatrix(byte[] rho)
        {
            int i, j;
            for (i = 0; i < K; ++i)
            {
                for (j = 0; j < L; ++j)
                {
                    Matrix[i].Vec[j].UniformBlocks(rho, (ushort)((ushort) (i << 8) + j));
                }
            }
        }

        public void PointwiseMontgomery(PolyVec t, PolyVec v)
        {
            Debug.Assert(t.Vec.Length == K);
            Debug.Assert(v.Vec.Length == L);

            int i;
            for (i = 0; i < K; ++i)
            {
                t.Vec[i].PointwiseAccountMontgomery(Matrix[i], v);
            }
        }
    }
}