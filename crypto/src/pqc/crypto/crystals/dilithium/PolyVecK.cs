namespace Org.BouncyCastle.Pqc.Crypto.Crystals.Dilithium
{
    internal class PolyVecK
    {
        internal readonly Poly[] Vec;
        private readonly int K;

        internal PolyVecK(DilithiumEngine engine)
        {
            K = engine.K;
            Vec = new Poly[K];
            for (int i = 0; i < K; i++)
            {
                Vec[i] = new Poly(engine);
            }
        }

        internal void UniformEta(byte[] seed, ushort nonce)
        {
            for (int i = 0; i < K; i++)
            {
                Vec[i].UniformEta(seed, nonce++);
            }
        }

        internal void Reduce()
        {
            for (int i = 0; i < K; i++)
            {
                Vec[i].ReducePoly();
            }
        }

        internal void Ntt()
        {
            for (int i= 0; i < K; ++i)
            {
                Vec[i].PolyNtt();
            }
        }

        internal void InverseNttToMont()
        {
            for (int i = 0; i < K; ++i)
            {
                Vec[i].InverseNttToMont();
            }
        }

        internal void AddPolyVecK(PolyVecK b)
        {
            for (int i = 0; i < K; ++i)
            {
                Vec[i].AddPoly(b.Vec[i]);
            }
        }

        internal void Subtract(PolyVecK v)
        {
            for (int i = 0; i < K; ++i)
            {
                Vec[i].Subtract(v.Vec[i]);
            }
        }

        internal void ConditionalAddQ()
        {
            for (int i = 0; i < K; ++i)
            {
                Vec[i].ConditionalAddQ();
            }
        }

        internal void Power2Round(PolyVecK v)
        {
            for (int i = 0; i < K; ++i)
            {
                Vec[i].Power2Round(v.Vec[i]);
            }
        }

        internal void Decompose(PolyVecK v)
        {
            for (int i = 0; i < K; ++i)
            {
                Vec[i].Decompose(v.Vec[i]);
            }
        }

        internal void PackW1(DilithiumEngine engine, byte[] r)
        {
            for (int i = 0; i < K; i++)
            {
                Vec[i].PackW1(r, i * engine.PolyW1PackedBytes);
            }
        }

        internal void PointwisePolyMontgomery(Poly a, PolyVecK v)
        {
            for (int i = 0; i < K; ++i)
            {
                Vec[i].PointwiseMontgomery(a, v.Vec[i]);
            }
        }

        internal bool CheckNorm(int bound)
        {
            for (int i = 0; i < K; ++i)
            {
                if (Vec[i].CheckNorm(bound))
                    return true;
            }
            return false;
        }

        internal int MakeHint(PolyVecK v0, PolyVecK v1)
        {
            int s = 0;
            for (int i = 0; i < K; ++i)
            {
                s += Vec[i].PolyMakeHint(v0.Vec[i], v1.Vec[i]);
            }
            return s;
        }

        internal void UseHint(PolyVecK a, PolyVecK h)
        {
            for (int i = 0; i < K; ++i)
            {
                Vec[i].PolyUseHint(a.Vec[i], h.Vec[i]);
            }
        }

        internal void ShiftLeft()
        {
            for (int i = 0; i < K; ++i)
            {
                Vec[i].ShiftLeft();
            }
        }
    }
}
