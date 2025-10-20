using System.Diagnostics;

namespace Org.BouncyCastle.Crypto.Signers.MLDsa
{
    internal class PolyVec
    {
        private readonly Poly[] m_vec;

        internal PolyVec(MLDsaEngine engine, int length)
        {
            m_vec = new Poly[length];
            for (int i = 0; i < length; i++)
            {
                m_vec[i] = new Poly(engine);
            }
        }

        internal Poly this[int index]
        {
            get
            {
                return m_vec[index];
            }
            set
            {
                m_vec[index] = value;
            }
        }

        internal void Add(PolyVec v)
        {
            Debug.Assert(m_vec.Length == v.m_vec.Length);
            for (int i = 0; i < m_vec.Length; ++i)
            {
                m_vec[i].Add(v.m_vec[i]);
            }
        }

        internal bool CheckNorm(int bound)
        {
            for (int i = 0; i < m_vec.Length; ++i)
            {
                if (m_vec[i].CheckNorm(bound))
                    return true;
            }
            return false;
        }

        internal void CopyTo(PolyVec z)
        {
            Debug.Assert(m_vec.Length == z.m_vec.Length);
            for (int i = 0; i < m_vec.Length; i++)
            {
                m_vec[i].CopyTo(z.m_vec[i]);
            }
        }

        internal void ConditionalAddQ()
        {
            for (int i = 0; i < m_vec.Length; ++i)
            {
                m_vec[i].ConditionalAddQ();
            }
        }

        internal void Decompose(PolyVec v)
        {
            Debug.Assert(m_vec.Length == v.m_vec.Length);
            for (int i = 0; i < m_vec.Length; ++i)
            {
                m_vec[i].Decompose(v.m_vec[i]);
            }
        }

        internal void InverseNttToMont()
        {
            for (int i = 0; i < m_vec.Length; ++i)
            {
                m_vec[i].InverseNttToMont();
            }
        }

        internal int Length => m_vec.Length;

        internal int MakeHint(PolyVec v0, PolyVec v1)
        {
            Debug.Assert(m_vec.Length == v0.m_vec.Length);
            Debug.Assert(m_vec.Length == v1.m_vec.Length);
            int s = 0;
            for (int i = 0; i < m_vec.Length; ++i)
            {
                s += m_vec[i].PolyMakeHint(v0.m_vec[i], v1.m_vec[i]);
            }
            return s;
        }

        internal void Ntt()
        {
            for (int i = 0; i < m_vec.Length; ++i)
            {
                m_vec[i].PolyNtt();
            }
        }

        internal void PackW1(MLDsaEngine engine, byte[] r, int rOff)
        {
            for (int i = 0; i < m_vec.Length; i++)
            {
                m_vec[i].PackW1(r, rOff + i * engine.PolyW1PackedBytes);
            }
        }

        internal void PointwisePolyMontgomery(Poly a, PolyVec v)
        {
            Debug.Assert(m_vec.Length == v.m_vec.Length);
            for (int i = 0; i < m_vec.Length; ++i)
            {
                m_vec[i].PointwiseMontgomery(a, v.m_vec[i]);
            }
        }

        internal void Power2Round(PolyVec v)
        {
            Debug.Assert(m_vec.Length == v.m_vec.Length);
            for (int i = 0; i < m_vec.Length; ++i)
            {
                m_vec[i].Power2Round(v.m_vec[i]);
            }
        }

        internal void Reduce()
        {
            for (int i = 0; i < m_vec.Length; i++)
            {
                m_vec[i].ReducePoly();
            }
        }

        internal void ShiftLeft()
        {
            for (int i = 0; i < m_vec.Length; ++i)
            {
                m_vec[i].ShiftLeft();
            }
        }

        internal void Subtract(PolyVec v)
        {
            Debug.Assert(m_vec.Length == v.m_vec.Length);
            for (int i = 0; i < m_vec.Length; ++i)
            {
                m_vec[i].Subtract(v.m_vec[i]);
            }
        }

        internal void UniformBlocks(byte[] rho, int t)
        {
            for (int i = 0; i < m_vec.Length; ++i)
            {
                m_vec[i].UniformBlocks(rho, (ushort)(t + i));
            }
        }

        internal void UniformEta(byte[] seed, ushort nonce)
        {
            for (int i = 0; i < m_vec.Length; i++)
            {
                m_vec[i].UniformEta(seed, nonce++);
            }
        }

        internal void UniformGamma1(byte[] seed, ushort nonce)
        {
            for (int i = 0; i < m_vec.Length; i++)
            {
                m_vec[i].UniformGamma1(seed, (ushort)(m_vec.Length * nonce + i));
            }
        }

        internal void UseHint(PolyVec a, PolyVec h)
        {
            Debug.Assert(m_vec.Length == a.m_vec.Length);
            Debug.Assert(m_vec.Length == h.m_vec.Length);
            for (int i = 0; i < m_vec.Length; ++i)
            {
                m_vec[i].PolyUseHint(a.m_vec[i], h.m_vec[i]);
            }
        }
    }
}
