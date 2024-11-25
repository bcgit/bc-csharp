using System;

using Org.BouncyCastle.Utilities;

namespace Org.BouncyCastle.Crypto.Kems.MLKem
{
    internal class IndCpa
    {
        private readonly MLKemEngine m_engine;
        private readonly Symmetric m_symmetric;

        internal IndCpa(MLKemEngine engine)
        {
            m_engine = engine;
            m_symmetric = engine.Symmetric;
        }

        private int GenerateMatrixNBlocks => ((12 * MLKemEngine.N / 8 * (1 << 12) / MLKemEngine.Q + m_symmetric.XofBlockBytes) / m_symmetric.XofBlockBytes);

#if NETCOREAPP2_1_OR_GREATER || NETSTANDARD2_1_OR_GREATER
        private void GenerateMatrix(PolyVec[] a, ReadOnlySpan<byte> seed, bool transposed)
#else
        private void GenerateMatrix(PolyVec[] a, byte[] seed, bool transposed)
#endif
        {
            int K = m_engine.K;

            byte[] buf = new byte[GenerateMatrixNBlocks * m_symmetric.XofBlockBytes + 2];
            for (int i = 0; i < K; i++)
            {
                for (int j = 0; j < K; j++)
                {
                    if (transposed)
                    {
                        m_symmetric.XofAbsorb(seed, (byte)i, (byte)j);
                    }
                    else
                    {
                        m_symmetric.XofAbsorb(seed, (byte)j, (byte)i);
                    }
#if NETCOREAPP2_1_OR_GREATER || NETSTANDARD2_1_OR_GREATER
                    m_symmetric.XofSqueezeBlocks(buf.AsSpan(0, GenerateMatrixNBlocks * m_symmetric.XofBlockBytes));
#else
                    m_symmetric.XofSqueezeBlocks(buf, 0, GenerateMatrixNBlocks * m_symmetric.XofBlockBytes);
#endif
                    int buflen = GenerateMatrixNBlocks * m_symmetric.XofBlockBytes;
                    int ctr = RejectionSampling(a[i].m_vec[j].m_coeffs, 0, MLKemEngine.N, buf, buflen);
                    while (ctr < MLKemEngine.N)
                    {
                        int off = buflen % 3;
                        for (int k = 0; k < off; k++)
                        {
                            buf[k] = buf[buflen - off + k];
                        }
#if NETCOREAPP2_1_OR_GREATER || NETSTANDARD2_1_OR_GREATER
                        m_symmetric.XofSqueezeBlocks(buf.AsSpan(off, m_symmetric.XofBlockBytes * 2));
#else
                        m_symmetric.XofSqueezeBlocks(buf, off, m_symmetric.XofBlockBytes * 2);
#endif
                        buflen = off + m_symmetric.XofBlockBytes;
                        ctr += RejectionSampling(a[i].m_vec[j].m_coeffs, ctr, MLKemEngine.N - ctr, buf, buflen);
                    }

                }
            }
        }

        private int RejectionSampling(short[] r, int off, int len, byte[] buf, int buflen)
        {
            int ctr = 0, pos = 0;
            while (ctr < len && pos + 3 <= buflen)
            {
                ushort val0 = (ushort) ((((ushort) (buf[pos + 0] & 0xFF) >> 0) | ((ushort)(buf[pos + 1] & 0xFF) << 8)) & 0xFFF);
                ushort val1 = (ushort) ((((ushort) (buf[pos + 1] & 0xFF) >> 4) | ((ushort)(buf[pos + 2] & 0xFF) << 4)) & 0xFFF);
                pos += 3;

                if (val0 < MLKemEngine.Q)
                {
                    r[off + ctr++] = (short)val0;
                }
                if (ctr < len && val1 < MLKemEngine.Q)
                {
                    r[off + ctr++] = (short)val1;
                }
            }
            return ctr;
        }

        internal void GenerateKeyPair(byte[] d, out byte[] pk, out byte[] sk)
        {
            int K = m_engine.K;

            byte[] buf = new byte[2 * MLKemEngine.SymBytes];
            byte nonce = 0;
            PolyVec[] Matrix = new PolyVec[K];
            PolyVec e = new PolyVec(m_engine), pkpv = new PolyVec(m_engine), skpv = new PolyVec(m_engine);

            m_symmetric.Hash_g(Arrays.Append(d, (byte)K), buf);

#if NETCOREAPP2_1_OR_GREATER || NETSTANDARD2_1_OR_GREATER
            var publicSeed = buf.AsSpan(0, MLKemEngine.SymBytes);
            var noiseSeed = buf.AsSpan(MLKemEngine.SymBytes, MLKemEngine.SymBytes);
#else
            byte[] publicSeed = Arrays.CopyOfRange(buf, 0, MLKemEngine.SymBytes);
            byte[] noiseSeed = Arrays.CopyOfRange(buf, MLKemEngine.SymBytes, 2 * MLKemEngine.SymBytes);
#endif

            for (int i = 0; i < K; i++)
            {
                Matrix[i] = new PolyVec(m_engine);
            }

            GenerateMatrix(Matrix, publicSeed, false);

            for (int i = 0; i < K; i++)
            {
                skpv.m_vec[i].GetNoiseEta1(noiseSeed, nonce++);
            }

            for (int i = 0; i < K; i++)
            {
                e.m_vec[i].GetNoiseEta1(noiseSeed, nonce++);
            }

            skpv.Ntt();
            e.Ntt();

            for (int i = 0; i < K; i++)
            {
                PolyVec.PointwiseAccountMontgomery(pkpv.m_vec[i], Matrix[i], skpv, m_engine);
                pkpv.m_vec[i].ToMont();
            }

            pkpv.Add(e);
            pkpv.Reduce();

            PackSecretKey(out sk, skpv);
            PackPublicKey(out pk, pkpv, publicSeed);
        }

        private void PackSecretKey(out byte[] sk, PolyVec skpv)
        {
            sk = new byte[m_engine.PolyVecBytes];
            skpv.ToBytes(sk);
        }

#if NETCOREAPP2_1_OR_GREATER || NETSTANDARD2_1_OR_GREATER
        private void PackPublicKey(out byte[] pk, PolyVec pkpv, ReadOnlySpan<byte> seed)
        {
            pk = new byte[m_engine.IndCpaPublicKeyBytes];
            pkpv.ToBytes(pk);
            seed[..MLKemEngine.SymBytes].CopyTo(pk.AsSpan(m_engine.PolyVecBytes));
        }

        private void UnpackSecretKey(PolyVec skpv, ReadOnlySpan<byte> sk)
        {
            skpv.FromBytes(sk);
        }

        private void UnpackPublicKey(PolyVec pkpv, Span<byte> seed, ReadOnlySpan<byte> pk)
        {
            pkpv.FromBytes(pk);
            pk.Slice(m_engine.PolyVecBytes, MLKemEngine.SymBytes).CopyTo(seed);
        }

        public void Encrypt(Span<byte> encapsulation, ReadOnlySpan<byte> m, ReadOnlySpan<byte> pk,
            ReadOnlySpan<byte> coins)
        {
            int K = m_engine.K;

            byte[] seed = new byte[MLKemEngine.SymBytes];
            byte nonce = 0;
            PolyVec sp = new PolyVec(m_engine), pkpv = new PolyVec(m_engine), ep = new PolyVec(m_engine),
                bp = new PolyVec(m_engine);
            PolyVec[] MatrixTransposed = new PolyVec[K];
            Poly v = new Poly(m_engine), k = new Poly(m_engine), epp = new Poly(m_engine);

            UnpackPublicKey(pkpv, seed, pk);

            k.FromMsg(m);

            for (int i = 0; i < K; i++)
            {
                MatrixTransposed[i] = new PolyVec(m_engine);
            }

            GenerateMatrix(MatrixTransposed, seed, true);

            for (int i = 0; i < K; i++)
            {
                sp.m_vec[i].GetNoiseEta1(coins, nonce++);
            }

            for (int i = 0; i < K; i++)
            {
                ep.m_vec[i].GetNoiseEta2(coins, nonce++);
            }
            epp.GetNoiseEta2(coins, nonce++);

            sp.Ntt();

            for (int i = 0; i < K; i++)
            {
                PolyVec.PointwiseAccountMontgomery(bp.m_vec[i], MatrixTransposed[i], sp, m_engine);
            }

            PolyVec.PointwiseAccountMontgomery(v, pkpv, sp, m_engine);

            bp.InverseNttToMont();

            v.PolyInverseNttToMont();

            bp.Add(ep);

            v.Add(epp);
            v.Add(k);

            bp.Reduce();
            v.PolyReduce();

            PackCipherText(encapsulation, bp, v);
        }

        private void PackCipherText(Span<byte> r, PolyVec b, Poly v)
        {
            b.CompressPolyVec(r);
            v.CompressPoly(r[m_engine.PolyVecCompressedBytes..]);
        }

        private void UnpackCipherText(PolyVec b, Poly v, ReadOnlySpan<byte> c)
        {
            b.DecompressPolyVec(c);
            v.DecompressPoly(c[m_engine.PolyVecCompressedBytes..]);
        }
#else
        private void PackPublicKey(out byte[] pk, PolyVec pkpv, byte[] seed)
        {
            pk = new byte[m_engine.IndCpaPublicKeyBytes];
            pkpv.ToBytes(pk);
            Array.Copy(seed, 0, pk, m_engine.PolyVecBytes, MLKemEngine.SymBytes);
        }

        private void UnpackSecretKey(PolyVec skpv, byte[] sk)
        {
            skpv.FromBytes(sk);
        }

        private void UnpackPublicKey(PolyVec pkpv, byte[] seed, byte[] pk)
        {
            pkpv.FromBytes(pk);
            Array.Copy(pk, m_engine.PolyVecBytes, seed, 0, MLKemEngine.SymBytes);
        }

        public void Encrypt(byte[] cBuf, int cOff, byte[] m, byte[] pk, byte[] coins)
        {
            int K = m_engine.K;

            byte[] seed = new byte[MLKemEngine.SymBytes];
            byte nonce = 0;
            PolyVec sp = new PolyVec(m_engine), pkpv = new PolyVec(m_engine), ep = new PolyVec(m_engine), bp = new PolyVec(m_engine);
            PolyVec[] MatrixTransposed = new PolyVec[K];
            Poly v = new Poly(m_engine), k = new Poly(m_engine), epp = new Poly(m_engine);

            UnpackPublicKey(pkpv, seed, pk);

            k.FromMsg(m);

            for (int i = 0; i < K; i++)
            {
                MatrixTransposed[i] = new PolyVec(m_engine);
            }

            GenerateMatrix(MatrixTransposed, seed, true);

            for (int i = 0; i < K; i++)
            {
                sp.m_vec[i].GetNoiseEta1(coins, nonce++);
            }

            for (int i = 0; i < K; i++)
            {
                ep.m_vec[i].GetNoiseEta2(coins, nonce++);
            }
            epp.GetNoiseEta2(coins, nonce++);

            sp.Ntt();

            for (int i = 0; i < K; i++)
            {
                PolyVec.PointwiseAccountMontgomery(bp.m_vec[i], MatrixTransposed[i], sp, m_engine);
            }

            PolyVec.PointwiseAccountMontgomery(v, pkpv, sp, m_engine);

            bp.InverseNttToMont();

            v.PolyInverseNttToMont();

            bp.Add(ep);

            v.Add(epp);
            v.Add(k);

            bp.Reduce();
            v.PolyReduce();

            PackCipherText(cBuf, cOff, bp, v);
        }

        private void PackCipherText(byte[] rBuf, int rOff, PolyVec b, Poly v)
        {
            b.CompressPolyVec(rBuf, rOff);
            v.CompressPoly(rBuf, rOff + m_engine.PolyVecCompressedBytes);
        }

        private void UnpackCipherText(PolyVec b, Poly v, byte[] cBuf, int cOff)
        {
            b.DecompressPolyVec(cBuf, cOff);
            v.DecompressPoly(cBuf, cOff + m_engine.PolyVecCompressedBytes);
        }
#endif

#if NETCOREAPP2_1_OR_GREATER || NETSTANDARD2_1_OR_GREATER
        internal void Decrypt(Span<byte> m, ReadOnlySpan<byte> encapsulation, ReadOnlySpan<byte> sk)
        {
            PolyVec bp = new PolyVec(m_engine), skpv = new PolyVec(m_engine);
            Poly v = new Poly(m_engine), mp = new Poly(m_engine);

            UnpackCipherText(bp, v, encapsulation);
            UnpackSecretKey(skpv, sk);

            bp.Ntt();

            PolyVec.PointwiseAccountMontgomery(mp, skpv, bp, m_engine);

            mp.PolyInverseNttToMont();
            mp.Subtract(v);
            mp.PolyReduce();
            mp.ToMsg(m);
        }

        internal byte[] PackPublicKey(PolyVec polyVec, ReadOnlySpan<byte> seed)
        {
            byte[] buf = new byte[m_engine.IndCpaPublicKeyBytes];
            polyVec.ToBytes(buf);
            seed[..MLKemEngine.SymBytes].CopyTo(buf.AsSpan(m_engine.PolyVecBytes));
            return buf;
        }

        internal byte[] UnpackPublicKey(PolyVec polyVec, ReadOnlySpan<byte> pk)
        {
            byte[] outputSeed = new byte[MLKemEngine.SymBytes];
            polyVec.FromBytes(pk);
            pk.Slice(m_engine.PolyVecBytes, MLKemEngine.SymBytes).CopyTo(outputSeed);
            return outputSeed;
        }
#else
        internal void Decrypt(byte[] m, byte[] cBuf, int cOff, byte[] sk)
        {
            PolyVec bp = new PolyVec(m_engine), skpv = new PolyVec(m_engine);
            Poly v = new Poly(m_engine), mp = new Poly(m_engine);

            UnpackCipherText(bp, v, cBuf, cOff);
            UnpackSecretKey(skpv, sk);

            bp.Ntt();

            PolyVec.PointwiseAccountMontgomery(mp, skpv, bp, m_engine);

            mp.PolyInverseNttToMont();
            mp.Subtract(v);
            mp.PolyReduce();
            mp.ToMsg(m);
        }

        internal byte[] PackPublicKey(PolyVec polyVec, byte[] seed)
        {
            byte[] buf = new byte[m_engine.IndCpaPublicKeyBytes];
            polyVec.ToBytes(buf);
            Array.Copy(seed, 0, buf, m_engine.PolyVecBytes, MLKemEngine.SymBytes);
            return buf;
        }

        internal byte[] UnpackPublicKey(PolyVec polyVec, byte[] pk)
        {
            byte[] outputSeed = new byte[MLKemEngine.SymBytes];
            polyVec.FromBytes(pk);
            Array.Copy(pk, m_engine.PolyVecBytes, outputSeed, 0, MLKemEngine.SymBytes);
            return outputSeed;
        }
#endif
    }
}
