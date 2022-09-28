using System;

using Org.BouncyCastle.Crypto.Digests;
using Org.BouncyCastle.Utilities;

namespace Org.BouncyCastle.Pqc.Crypto.Crystals.Kyber
{
    internal class KyberIndCpa
    {
        private readonly KyberEngine m_engine;

        internal KyberIndCpa(KyberEngine engine)
        {
            m_engine = engine;
        }

        private int XofBlockBytes => Symmetric.Shake128Rate;

        private int GenerateMatrixNBlocks => ((12 * KyberEngine.N / 8 * (1 << 12) / KyberEngine.Q + XofBlockBytes) / XofBlockBytes);

        private void GenerateMatrix(PolyVec[] a, byte[] seed, bool transposed)
        {
            int K = m_engine.K;
            ShakeDigest shake128 = new ShakeDigest(128);
            byte[] buf = new byte[GenerateMatrixNBlocks * XofBlockBytes + 2];

            for (int i = 0; i < K; i++)
            {
                for (int j = 0; j < K; j++)
                {
                    if (transposed)
                    {
                        shake128 = Symmetric.Xof(seed, (byte) i, (byte) j);
                    }
                    else
                    {
                        shake128 = Symmetric.Xof(seed, (byte) j, (byte) i);
                    }
                    shake128.DoOutput(buf, 0, GenerateMatrixNBlocks * XofBlockBytes);
                    int buflen = GenerateMatrixNBlocks * XofBlockBytes;
                    int ctr = RejectionSampling(a[i].m_vec[j].Coeffs, 0, KyberEngine.N, buf, buflen);
                    while (ctr < KyberEngine.N)
                    {
                        int off = buflen % 3;
                        for (int k = 0; k < off; k++)
                        {
                            buf[k] = buf[buflen - off + k];
                        }
                        shake128.DoOutput(buf, off, XofBlockBytes * 2);
                        buflen = off + XofBlockBytes;
                        ctr += RejectionSampling(a[i].m_vec[j].Coeffs, ctr, KyberEngine.N - ctr, buf, buflen);
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

                if (val0 < KyberEngine.Q)
                {
                    r[off + ctr++] = (short)val0;
                }
                if (ctr < len && val1 < KyberEngine.Q)
                {
                    r[off + ctr++] = (short)val1;
                }
            }

            return ctr;
        }

        internal void GenerateKeyPair(byte[] pk, byte[] sk)
        {
            int K = m_engine.K;

            byte[] buf = new byte[2 * KyberEngine.SymBytes];
            byte nonce = 0;
            PolyVec[] Matrix = new PolyVec[K];
            PolyVec e = new PolyVec(m_engine), pkpv = new PolyVec(m_engine), skpv = new PolyVec(m_engine);
            Sha3Digest Sha3Digest512 = new Sha3Digest(512);

            m_engine.RandomBytes(buf, KyberEngine.SymBytes);
            
            Sha3Digest512.BlockUpdate(buf, 0, KyberEngine.SymBytes);
            Sha3Digest512.DoFinal(buf, 0);

            //Console.WriteLine(string.Format("buf = {0}", Convert.ToHexString(buf)));
            byte[] PublicSeed = Arrays.CopyOfRange(buf, 0, KyberEngine.SymBytes);
            byte[] NoiseSeed = Arrays.CopyOfRange(buf, KyberEngine.SymBytes, 2 * KyberEngine.SymBytes);

            for (int i = 0; i < K; i++)
            {
                Matrix[i] = new PolyVec(m_engine);
            }

            GenerateMatrix(Matrix, PublicSeed, false);

            for (int i = 0; i < K; i++) 
            {
                skpv.m_vec[i].GetNoiseEta1(NoiseSeed, nonce++);
            }

            for (int i = 0; i < K; i++)
            {
                e.m_vec[i].GetNoiseEta1(NoiseSeed, nonce++);
            }

            skpv.Ntt();
            e.Ntt();

            //Console.WriteLine("skpv = ");
            //for (int i = 0; i < K; i++)
            //{
            //    Console.Write(String.Format("{0} [", i));
            //    foreach (short coeff in skpv.Vec[i].Coeffs)
            //    {
            //        Console.Write(String.Format("{0}, ", coeff));
            //    }
            //    Console.Write("]\n");
            //}

            //for (int i = 0; i < K; i++)
            //{
            //    Console.Write("[");
            //    for (int j = 0; j < K; j++)
            //    {
            //        Console.Write("[");
            //        for (int k = 0; k < KyberEngine.N; k++)
            //        {
            //            Console.Write(String.Format("{0:G}, ", Matrix[i].Vec[j].Coeffs[k]));
            //        }
            //        Console.Write("], \n");
            //    }
            //    Console.Write("] \n");
            //}

            for (int i = 0; i < K; i++)
            {
                PolyVec.PointwiseAccountMontgomery(pkpv.m_vec[i], Matrix[i], skpv, m_engine);
                pkpv.m_vec[i].ToMont();
            }

            //Console.WriteLine("pkpv = ");
            //for (int i = 0; i < K; i++)
            //{
            //    Console.Write(String.Format("{0} [", i));
            //    foreach (short coeff in pkpv.Vec[i].Coeffs)
            //    {
            //        Console.Write(String.Format("{0}, ", coeff));
            //    }
            //    Console.Write("]\n");
            //}
            pkpv.Add(e);
            pkpv.Reduce();

            PackSecretKey(sk, skpv);
            PackPublicKey(pk, pkpv, PublicSeed);
        }

        private void PackSecretKey(byte[] sk, PolyVec skpv)
        {
            skpv.ToBytes(sk);
        }

        private void UnpackSecretKey(PolyVec skpv, byte[] sk)
        {
            skpv.FromBytes(sk);
        }

        private void PackPublicKey(byte[] pk, PolyVec pkpv, byte[] seed)
        {
            pkpv.ToBytes(pk);
            Array.Copy(seed, 0, pk, m_engine.PolyVecBytes, KyberEngine.SymBytes);
        }

        private void UnpackPublicKey(PolyVec pkpv, byte[] seed, byte[] pk)
        {
            pkpv.FromBytes(pk);
            Array.Copy(pk, m_engine.PolyVecBytes, seed, 0, KyberEngine.SymBytes);
        }

        internal void Encrypt(byte[] c, byte[] m, byte[] pk, byte[] coins)
        {
            int K = m_engine.K;

            byte[] seed = new byte[KyberEngine.SymBytes];
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

            PackCipherText(c, bp, v);
        }

        private void PackCipherText(byte[] r, PolyVec b, Poly v)
        {
            b.CompressPolyVec(r);
            v.CompressPoly(r, m_engine.PolyVecCompressedBytes);
        }

        private void UnpackCipherText(PolyVec b, Poly v, byte[] c)
        {
            b.DecompressPolyVec(c);
            v.DecompressPoly(c, m_engine.PolyVecCompressedBytes);
        }

        internal void Decrypt(byte[] m, byte[] c, byte[] sk)
        {
            PolyVec bp = new PolyVec(m_engine), skpv = new PolyVec(m_engine);
            Poly v = new Poly(m_engine), mp = new Poly(m_engine);

            UnpackCipherText(bp, v, c);
            UnpackSecretKey(skpv, sk);

            bp.Ntt();

            PolyVec.PointwiseAccountMontgomery(mp, skpv, bp, m_engine);

            mp.PolyInverseNttToMont();
            mp.Subtract(v);
            mp.PolyReduce();
            mp.ToMsg(m);
        }
    }
}
