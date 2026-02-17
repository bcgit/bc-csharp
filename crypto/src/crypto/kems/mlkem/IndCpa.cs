using System;

using Org.BouncyCastle.Crypto.Digests;
using Org.BouncyCastle.Crypto.Utilities;
#if !(NETCOREAPP2_1_OR_GREATER || NETSTANDARD2_1_OR_GREATER)
using Org.BouncyCastle.Utilities;
#endif

namespace Org.BouncyCastle.Crypto.Kems.MLKem
{
    internal sealed class IndCpa
    {
        private const int Shake128Rate = 168;

        private static readonly int NumMatrixBlocks =
            (((12 * MLKemEngine.N / 8) << 12) / MLKemEngine.Q + Shake128Rate) / Shake128Rate;

        private readonly MLKemEngine m_engine;

        internal IndCpa(MLKemEngine engine)
        {
            m_engine = engine;
        }

#if NETCOREAPP2_1_OR_GREATER || NETSTANDARD2_1_OR_GREATER
        private void GenerateMatrixA(PolyVec[] a, ReadOnlySpan<byte> seed, bool transpose)
#else
        private void GenerateMatrixA(PolyVec[] a, byte[] seed, bool transpose)
#endif
        {
            int K = m_engine.K;
            ShakeDigest xof = new ShakeDigest(128);

            byte[] buf = new byte[NumMatrixBlocks * Shake128Rate + 2];

#if NETCOREAPP2_1_OR_GREATER || NETSTANDARD2_1_OR_GREATER
            Span<byte> seedPlus = stackalloc byte[MLKemEngine.SymBytes + 2];
            seed[..MLKemEngine.SymBytes].CopyTo(seedPlus);
#else
            byte[] seedPlus = new byte[MLKemEngine.SymBytes + 2];
            Array.Copy(seed, 0, seedPlus, 0, MLKemEngine.SymBytes);
#endif

            for (int i = 0; i < K; i++)
            {
                for (int j = 0; j < K; j++)
                {
                    xof.Reset();

                    if (transpose)
                    {
                        seedPlus[MLKemEngine.SymBytes + 0] = (byte)i;
                        seedPlus[MLKemEngine.SymBytes + 1] = (byte)j;
                    }
                    else
                    {
                        seedPlus[MLKemEngine.SymBytes + 0] = (byte)j;
                        seedPlus[MLKemEngine.SymBytes + 1] = (byte)i;
                    }

#if NETCOREAPP2_1_OR_GREATER || NETSTANDARD2_1_OR_GREATER
                    xof.BlockUpdate(seedPlus);
#else
                    xof.BlockUpdate(seedPlus, 0, seedPlus.Length);
#endif

                    int bufLen = NumMatrixBlocks * Shake128Rate;
#if NETCOREAPP2_1_OR_GREATER || NETSTANDARD2_1_OR_GREATER
                    xof.Output(buf.AsSpan(0, bufLen));
#else
                    xof.Output(buf, 0, bufLen);
#endif

                    int ctr = RejectionSampling(a[i].m_vec[j].m_coeffs, 0, MLKemEngine.N, buf, bufLen);
                    while (ctr < MLKemEngine.N)
                    {
                        int off = bufLen % 3;
                        for (int k = 0; k < off; k++)
                        {
                            buf[k] = buf[bufLen - off + k];
                        }

#if NETCOREAPP2_1_OR_GREATER || NETSTANDARD2_1_OR_GREATER
                        xof.Output(buf.AsSpan(off, Shake128Rate * 2));
#else
                        xof.Output(buf, off, Shake128Rate * 2);
#endif

                        bufLen = off + Shake128Rate;
                        // Error in code Section Unsure
                        ctr += RejectionSampling(a[i].m_vec[j].m_coeffs, ctr, MLKemEngine.N - ctr, buf, bufLen);
                    }
                }
            }
        }

        private static int RejectionSampling(short[] r, int off, int len, byte[] buf, int bufLen)
        {
            int ctr = 0, pos = 0;
            while (ctr < len && pos + 3 <= bufLen)
            {
                uint t = Pack.LE_To_UInt24(buf, pos);
                ushort d1 = (ushort)(t & 0xFFF);
                ushort d2 = (ushort)(t >> 12);
                pos += 3;

                if (d1 < MLKemEngine.Q)
                {
                    r[off + ctr++] = (short)d1;
                }
                if (ctr < len && d2 < MLKemEngine.Q)
                {
                    r[off + ctr++] = (short)d2;
                }
            }
            return ctr;
        }

        internal void GenerateKeyPair(byte[] d, byte[] kp)
        {
            int K = m_engine.K;

#if NETCOREAPP2_1_OR_GREATER || NETSTANDARD2_1_OR_GREATER
            Span<byte> buf = stackalloc byte[2 * MLKemEngine.SymBytes];
#else
            byte[] buf = new byte[2 * MLKemEngine.SymBytes];
#endif

            PolyVec e = new PolyVec(K);
            PolyVec skpv = new PolyVec(K);

            {
                var G = new Sha3Digest(512);
#if NETCOREAPP2_1_OR_GREATER || NETSTANDARD2_1_OR_GREATER
                G.BlockUpdate(d.AsSpan(0, MLKemEngine.SymBytes));
                G.Update((byte)K);
                G.DoFinal(buf);
#else
                G.BlockUpdate(d, 0, MLKemEngine.SymBytes);
                G.Update((byte)K);
                G.DoFinal(buf, 0);
#endif
            }

            PolyVec[] matrixA = new PolyVec[K];
            for (int i = 0; i < K; i++)
            {
                matrixA[i] = new PolyVec(K);
            }
            GenerateMatrixA(matrixA, buf, transpose: false);

            var xof = new ShakeDigest(256);

            byte nonce = 0;
            if (m_engine.Eta1 == 2)
            {
                for (int i = 0; i < K; i++)
                {
#if NETCOREAPP2_1_OR_GREATER || NETSTANDARD2_1_OR_GREATER
                    skpv.m_vec[i].GetNoiseEta2(xof, buf[MLKemEngine.SymBytes..], nonce++);
#else
                    skpv.m_vec[i].GetNoiseEta2(xof, buf, MLKemEngine.SymBytes, nonce++);
#endif
                }

                for (int i = 0; i < K; i++)
                {
#if NETCOREAPP2_1_OR_GREATER || NETSTANDARD2_1_OR_GREATER
                    e.m_vec[i].GetNoiseEta2(xof, buf[MLKemEngine.SymBytes..], nonce++);
#else
                    e.m_vec[i].GetNoiseEta2(xof, buf, MLKemEngine.SymBytes, nonce++);
#endif
                }
            }
            else
            {
                for (int i = 0; i < K; i++)
                {
#if NETCOREAPP2_1_OR_GREATER || NETSTANDARD2_1_OR_GREATER
                    skpv.m_vec[i].GetNoiseEta3(xof, buf[MLKemEngine.SymBytes..], nonce++);
#else
                    skpv.m_vec[i].GetNoiseEta3(xof, buf, MLKemEngine.SymBytes, nonce++);
#endif
                }

                for (int i = 0; i < K; i++)
                {
#if NETCOREAPP2_1_OR_GREATER || NETSTANDARD2_1_OR_GREATER
                    e.m_vec[i].GetNoiseEta3(xof, buf[MLKemEngine.SymBytes..], nonce++);
#else
                    e.m_vec[i].GetNoiseEta3(xof, buf, MLKemEngine.SymBytes, nonce++);
#endif
                }
            }

            skpv.Ntt();
            e.Ntt();

            PolyVec pkpv = new PolyVec(K);
            for (int i = 0; i < K; i++)
            {
                PolyVec.PointwiseAccountMontgomery(pkpv.m_vec[i], matrixA[i], skpv);
                pkpv.m_vec[i].ToMont();
            }
            pkpv.Add(e);
            pkpv.Reduce();

#if NETCOREAPP2_1_OR_GREATER || NETSTANDARD2_1_OR_GREATER
            PackSecretKey(skpv, kp.AsSpan());
            PackPublicKey(pkpv, buf, kp.AsSpan(m_engine.IndCpaSecretKeyBytes));
#else
            PackSecretKey(skpv, kp, 0);
            PackPublicKey(pkpv, buf, kp, m_engine.IndCpaSecretKeyBytes);
#endif
        }

#if NETCOREAPP2_1_OR_GREATER || NETSTANDARD2_1_OR_GREATER
        internal void Decrypt(ReadOnlySpan<byte> encapsulation, ReadOnlySpan<byte> sk, Span<byte> m)
        {
            int K = m_engine.K;

            PolyVec bp = new PolyVec(K), skpv = new PolyVec(K);
            Poly v = new Poly(), mp = new Poly();

            UnpackCipherText(encapsulation, bp, v);
            UnpackSecretKey(sk, skpv);

            bp.Ntt();

            PolyVec.PointwiseAccountMontgomery(mp, skpv, bp);

            mp.PolyInverseNttToMont();
            mp.Subtract(v);
            mp.PolyReduce();
            mp.ToMsg(m);
        }

        internal void Encrypt(ReadOnlySpan<byte> pk, ReadOnlySpan<byte> msg, ReadOnlySpan<byte> coins,
            Span<byte> encapsulation)
        {
            int K = m_engine.K;

            byte[] seed = new byte[MLKemEngine.SymBytes];
            PolyVec sp = new PolyVec(K), pkpv = new PolyVec(K), ep = new PolyVec(K), bp = new PolyVec(K);
            Poly v = new Poly(), k = new Poly(), epp = new Poly();

            UnpackPublicKey(pk, pkpv, seed);

            k.FromMsg(msg);

            PolyVec[] matrixTransposed = new PolyVec[K];
            for (int i = 0; i < K; i++)
            {
                matrixTransposed[i] = new PolyVec(K);
            }
            GenerateMatrixA(matrixTransposed, seed, transpose: true);

            var xof = new ShakeDigest(256);

            byte nonce = 0;
            if (m_engine.Eta1 == 2)
            {
                for (int i = 0; i < K; i++)
                {
                    sp.m_vec[i].GetNoiseEta2(xof, coins, nonce++);
                }
            }
            else
            {
                for (int i = 0; i < K; i++)
                {
                    sp.m_vec[i].GetNoiseEta3(xof, coins, nonce++);
                }
            }

            for (int i = 0; i < K; i++)
            {
                ep.m_vec[i].GetNoiseEta2(xof, coins, nonce++);
            }
            epp.GetNoiseEta2(xof, coins, nonce++);

            sp.Ntt();

            for (int i = 0; i < K; i++)
            {
                PolyVec.PointwiseAccountMontgomery(bp.m_vec[i], matrixTransposed[i], sp);
            }

            PolyVec.PointwiseAccountMontgomery(v, pkpv, sp);

            bp.InverseNttToMont();

            v.PolyInverseNttToMont();

            bp.Add(ep);

            v.Add(epp);
            v.Add(k);

            bp.Reduce();
            v.PolyReduce();

            PackCipherText(bp, v, encapsulation);
        }

        private void PackCipherText(PolyVec b, Poly v, Span<byte> c)
        {
            b.CompressPolyVec(c);
            c = c[m_engine.PolyVecCompressedBytes..];

            if (m_engine.K == 4)
            {
                v.CompressPoly160(c);
            }
            else
            {
                v.CompressPoly128(c);
            }
        }

        private void PackPublicKey(PolyVec pkpv, ReadOnlySpan<byte> seed, Span<byte> pk)
        {
            pkpv.ToBytes(pk);
            seed[..MLKemEngine.SymBytes].CopyTo(pk[m_engine.PolyVecBytes..]);
        }

        private void PackSecretKey(PolyVec skpv, Span<byte> sk)
        {
            skpv.ToBytes(sk);
        }

        private void UnpackCipherText(ReadOnlySpan<byte> c, PolyVec b, Poly v)
        {
            b.DecompressPolyVec(c);
            c = c[m_engine.PolyVecCompressedBytes..];

            if (m_engine.K == 4)
            {
                v.DecompressPoly160(c);
            }
            else
            {
                v.DecompressPoly128(c);
            }
        }

        private void UnpackPublicKey(ReadOnlySpan<byte> pk, PolyVec pkpv, Span<byte> seed)
        {
            pkpv.FromBytes(pk);
            pk.Slice(m_engine.PolyVecBytes, MLKemEngine.SymBytes).CopyTo(seed);
        }

        private void UnpackSecretKey(ReadOnlySpan<byte> sk, PolyVec skpv)
        {
            skpv.FromBytes(sk);
        }
#else
        internal void Decrypt(byte[] c, int cOff, byte[] sk, byte[] m)
        {
            int K = m_engine.K;

            PolyVec bp = new PolyVec(K), skpv = new PolyVec(K);
            Poly v = new Poly(), mp = new Poly();

            UnpackCipherText(c, cOff, bp, v);
            UnpackSecretKey(sk, skpv);

            bp.Ntt();

            PolyVec.PointwiseAccountMontgomery(mp, skpv, bp);

            mp.PolyInverseNttToMont();
            mp.Subtract(v);
            mp.PolyReduce();
            mp.ToMsg(m);
        }

        internal void Encrypt(byte[] pk, int pkOff, byte[] msg, int msgOff, byte[] coins, int coinsOff,
            byte[] enc, int encOff)
        {
            int K = m_engine.K;

            byte[] seed = new byte[MLKemEngine.SymBytes];
            PolyVec sp = new PolyVec(K), pkpv = new PolyVec(K), ep = new PolyVec(K), bp = new PolyVec(K);
            Poly v = new Poly(), k = new Poly(), epp = new Poly();

            UnpackPublicKey(pk, pkOff, pkpv, seed);

            k.FromMsg(msg, msgOff);

            PolyVec[] matrixATransposed = new PolyVec[K];
            for (int i = 0; i < K; i++)
            {
                matrixATransposed[i] = new PolyVec(K);
            }
            GenerateMatrixA(matrixATransposed, seed, transpose: true);

            var xof = new ShakeDigest(256);

            byte nonce = 0;
            if (m_engine.Eta1 == 2)
            {
                for (int i = 0; i < K; i++)
                {
                    sp.m_vec[i].GetNoiseEta2(xof, coins, coinsOff, nonce++);
                }
            }
            else
            {
                for (int i = 0; i < K; i++)
                {
                    sp.m_vec[i].GetNoiseEta3(xof, coins, coinsOff, nonce++);
                }
            }

            for (int i = 0; i < K; i++)
            {
                ep.m_vec[i].GetNoiseEta2(xof, coins, coinsOff, nonce++);
            }
            epp.GetNoiseEta2(xof, coins, coinsOff, nonce++);

            sp.Ntt();

            for (int i = 0; i < K; i++)
            {
                PolyVec.PointwiseAccountMontgomery(bp.m_vec[i], matrixATransposed[i], sp);
            }

            PolyVec.PointwiseAccountMontgomery(v, pkpv, sp);

            bp.InverseNttToMont();

            v.PolyInverseNttToMont();

            bp.Add(ep);

            v.Add(epp);
            v.Add(k);

            bp.Reduce();
            v.PolyReduce();

            PackCipherText(bp, v, enc, encOff);
        }

        private void PackCipherText(PolyVec b, Poly v, byte[] c, int cOff)
        {
            b.CompressPolyVec(c, cOff);
            cOff += m_engine.PolyVecCompressedBytes;

            if (m_engine.K == 4)
            {
                v.CompressPoly160(c, cOff);
            }
            else
            {
                v.CompressPoly128(c, cOff);
            }
        }

        private void PackPublicKey(PolyVec pkpv, byte[] seed, byte[] pk, int pkOff)
        {
            pkpv.ToBytes(pk, pkOff);
            Array.Copy(seed, 0, pk, pkOff + m_engine.PolyVecBytes, MLKemEngine.SymBytes);
        }

        private void PackSecretKey(PolyVec skpv, byte[] sk, int skOff)
        {
            skpv.ToBytes(sk, skOff);
        }

        private void UnpackCipherText(byte[] c, int cOff, PolyVec b, Poly v)
        {
            b.DecompressPolyVec(c, cOff);
            cOff += m_engine.PolyVecCompressedBytes;

            if (m_engine.K == 4)
            {
                v.DecompressPoly160(c, cOff);
            }
            else
            {
                v.DecompressPoly128(c, cOff);
            }
        }

        private void UnpackPublicKey(byte[] pk, int pkOff, PolyVec pkpv, byte[] seed)
        {
            pkpv.FromBytes(pk, pkOff);
            Array.Copy(pk, pkOff + m_engine.PolyVecBytes, seed, 0, MLKemEngine.SymBytes);
        }

        private void UnpackSecretKey(byte[] sk, PolyVec skpv)
        {
            skpv.FromBytes(sk, 0);
        }
#endif
    }
}
