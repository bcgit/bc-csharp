using System.Diagnostics;

namespace Org.BouncyCastle.Pqc.Crypto.Crystals.Dilithium
{
    internal class PolyVec
    {
        internal readonly Poly[] Vec;

        internal PolyVec(DilithiumEngine engine, int length)
        {
            this.Vec = new Poly[length];
            for (int i = 0; i < length; i++)
            {
                Vec[i] = new Poly(engine);
            }
        }

        internal void Add(PolyVec v)
        {
            Debug.Assert(this.Vec.Length == v.Vec.Length);
            for (int i = 0; i < Vec.Length; ++i)
            {
                Vec[i].Add(v.Vec[i]);
            }
        }

        internal bool CheckNorm(int bound)
        {
            for (int i = 0; i < Vec.Length; ++i)
            {
                if (Vec[i].CheckNorm(bound))
                    return true;
            }
            return false;
        }

        internal void CopyTo(PolyVec z)
        {
            Debug.Assert(this.Vec.Length == z.Vec.Length);
            for (int i = 0; i < Vec.Length; i++)
            {
                for (int j = 0; j < DilithiumEngine.N; j++)
                {
                    z.Vec[i].Coeffs[j] = Vec[i].Coeffs[j];
                }
            }
        }

        internal void ConditionalAddQ()
        {
            for (int i = 0; i < Vec.Length; ++i)
            {
                Vec[i].ConditionalAddQ();
            }
        }

        internal void Decompose(PolyVec v)
        {
            Debug.Assert(this.Vec.Length == v.Vec.Length);
            for (int i = 0; i < Vec.Length; ++i)
            {
                Vec[i].Decompose(v.Vec[i]);
            }
        }

        internal void InverseNttToMont()
        {
            for (int i = 0; i < Vec.Length; ++i)
            {
                Vec[i].InverseNttToMont();
            }
        }

        internal int MakeHint(PolyVec v0, PolyVec v1)
        {
            Debug.Assert(this.Vec.Length == v0.Vec.Length);
            Debug.Assert(this.Vec.Length == v1.Vec.Length);
            int s = 0;
            for (int i = 0; i < Vec.Length; ++i)
            {
                s += Vec[i].PolyMakeHint(v0.Vec[i], v1.Vec[i]);
            }
            return s;
        }

        internal void Ntt()
        {
            for (int i = 0; i < Vec.Length; ++i)
            {
                Vec[i].PolyNtt();
            }
        }

        internal void PackW1(DilithiumEngine engine, byte[] r)
        {
            for (int i = 0; i < Vec.Length; i++)
            {
                Vec[i].PackW1(r, i * engine.PolyW1PackedBytes);
            }
        }

        internal void PointwisePolyMontgomery(Poly a, PolyVec v)
        {
            Debug.Assert(this.Vec.Length == v.Vec.Length);
            for (int i = 0; i < Vec.Length; ++i)
            {
                Vec[i].PointwiseMontgomery(a, v.Vec[i]);
            }
        }

        internal void Power2Round(PolyVec v)
        {
            Debug.Assert(this.Vec.Length == v.Vec.Length);
            for (int i = 0; i < Vec.Length; ++i)
            {
                Vec[i].Power2Round(v.Vec[i]);
            }
        }

        internal void Reduce()
        {
            for (int i = 0; i < Vec.Length; i++)
            {
                Vec[i].ReducePoly();
            }
        }

        internal void ShiftLeft()
        {
            for (int i = 0; i < Vec.Length; ++i)
            {
                Vec[i].ShiftLeft();
            }
        }

        internal void Subtract(PolyVec v)
        {
            Debug.Assert(this.Vec.Length == v.Vec.Length);
            for (int i = 0; i < Vec.Length; ++i)
            {
                Vec[i].Subtract(v.Vec[i]);
            }
        }

        internal void UniformEta(byte[] seed, ushort nonce)
        {
            for (int i = 0; i < Vec.Length; i++)
            {
                Vec[i].UniformEta(seed, nonce++);
            }
        }

        internal void UniformGamma1(byte[] seed, ushort nonce)
        {
            for (int i = 0; i < Vec.Length; i++)
            {
                Vec[i].UniformGamma1(seed, (ushort)(Vec.Length * nonce + i));
            }
        }

        internal void UseHint(PolyVec a, PolyVec h)
        {
            Debug.Assert(this.Vec.Length == a.Vec.Length);
            Debug.Assert(this.Vec.Length == h.Vec.Length);
            for (int i = 0; i < Vec.Length; ++i)
            {
                Vec[i].PolyUseHint(a.Vec[i], h.Vec[i]);
            }
        }
    }
}
