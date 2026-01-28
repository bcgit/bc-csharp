using System;

using Org.BouncyCastle.Crypto.Digests;
using Org.BouncyCastle.Crypto.Utilities;
using Org.BouncyCastle.Utilities;

namespace Org.BouncyCastle.Crypto.Kems.MLKem
{
    internal sealed class IndCpa
    {
        private const int Shake128Rate = 168;

        private static readonly int GenerateMatrixNBlocks =
            (((12 * MLKemEngine.N / 8) << 12) / MLKemEngine.Q + Shake128Rate) / Shake128Rate;

        private readonly MLKemEngine m_engine;

        internal IndCpa(MLKemEngine engine)
        {
            m_engine = engine;
        }

#if NETCOREAPP2_1_OR_GREATER || NETSTANDARD2_1_OR_GREATER
        private void GenerateMatrix(PolyVec[] a, ReadOnlySpan<byte> seed, bool transposed)
#else
        private void GenerateMatrix(PolyVec[] a, byte[] seed, bool transposed)
#endif
        {
            int K = m_engine.K;
            ShakeDigest xof = new ShakeDigest(128);

            byte[] buf = new byte[GenerateMatrixNBlocks * Shake128Rate + 2];
            for (int i = 0; i < K; i++)
            {
                for (int j = 0; j < K; j++)
                {
                    xof.Reset();

#if NETCOREAPP2_1_OR_GREATER || NETSTANDARD2_1_OR_GREATER
                    xof.BlockUpdate(seed);
#else
                    xof.BlockUpdate(seed, 0, seed.Length);
#endif

                    if (transposed)
                    {
                        xof.Update((byte)i);
                        xof.Update((byte)j);
                    }
                    else
                    {
                        xof.Update((byte)j);
                        xof.Update((byte)i);
                    }

                    int bufLen = GenerateMatrixNBlocks * Shake128Rate;
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

        internal void GenerateKeyPair(byte[] d, out byte[] pk, out byte[] sk)
        {
            int K = m_engine.K;

            byte[] buf = new byte[2 * MLKemEngine.SymBytes];
            byte nonce = 0;
            PolyVec[] Matrix = new PolyVec[K];
            PolyVec e = new PolyVec(m_engine), pkpv = new PolyVec(m_engine), skpv = new PolyVec(m_engine);

            MLKemEngine.G(Arrays.Append(d, (byte)K), buf);

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

            var xof = new ShakeDigest(256);

            for (int i = 0; i < K; i++)
            {
                skpv.m_vec[i].GetNoiseEta1(xof, noiseSeed, nonce++);
            }

            for (int i = 0; i < K; i++)
            {
                e.m_vec[i].GetNoiseEta1(xof, noiseSeed, nonce++);
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

            var xof = new ShakeDigest(256);

            for (int i = 0; i < K; i++)
            {
                sp.m_vec[i].GetNoiseEta1(xof, coins, nonce++);
            }

            for (int i = 0; i < K; i++)
            {
                ep.m_vec[i].GetNoiseEta2(xof, coins, nonce++);
            }
            epp.GetNoiseEta2(xof, coins, nonce++);

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

            var xof = new ShakeDigest(256);

            for (int i = 0; i < K; i++)
            {
                sp.m_vec[i].GetNoiseEta1(xof, coins, nonce++);
            }

            for (int i = 0; i < K; i++)
            {
                ep.m_vec[i].GetNoiseEta2(xof, coins, nonce++);
            }
            epp.GetNoiseEta2(xof, coins, nonce++);

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
