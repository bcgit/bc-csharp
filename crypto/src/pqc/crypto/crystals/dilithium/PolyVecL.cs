namespace Org.BouncyCastle.Pqc.Crypto.Crystals.Dilithium
{
    internal class PolyVecL
    {
        internal readonly Poly[] Vec;
        private readonly int L;

        internal PolyVecL(DilithiumEngine engine)
        {
            L = engine.L;
            Vec = new Poly[L];
            for (int i = 0; i < L; i++)
            {
                Vec[i] = new Poly(engine);
            }
        }

        internal void UniformEta(byte[] seed, ushort nonce)
        {
            for (int i = 0; i < L; i++)
            {
                Vec[i].UniformEta(seed, nonce++);
            }
        }

        internal void CopyPolyVecL(PolyVecL OutPoly)
        {
            for (int i = 0; i < L; i++)
            {
                for (int j = 0; j < DilithiumEngine.N; j++)
                {
                    OutPoly.Vec[i].Coeffs[j] = Vec[i].Coeffs[j];
                }
            }
        }

        internal void InverseNttToMont()
        {
            for (int i = 0; i < L; i++)
            {
                Vec[i].InverseNttToMont();
            }
        }

        internal void Ntt()
        {
            for (int i = 0; i < L; i++)
            {
                Vec[i].PolyNtt();
            }
        }

        internal void UniformGamma1(byte[] seed, ushort nonce)
        {
            for (int i = 0; i < L; i++)
            {
                Vec[i].UniformGamma1(seed, (ushort)(L * nonce + i));
            }
        }

        internal void PointwisePolyMontgomery(Poly a, PolyVecL v)
        {
            for (int i = 0; i < L; ++i)
            {
                Vec[i].PointwiseMontgomery(a, v.Vec[i]);
            }
        }

        internal void AddPolyVecL(PolyVecL b)
        {
            for (int i = 0; i < L; i++)
            {
                Vec[i].AddPoly(b.Vec[i]);
            }
        }

        internal void Reduce()
        {
            for (int i = 0; i < L; i++)
            {
                Vec[i].ReducePoly();
            }
        }

        internal bool CheckNorm(int bound)
        {
            for (int i = 0; i < L; ++i)
            {
                if (Vec[i].CheckNorm(bound))
                    return true;
            }
            return false;
        }
    }
}
