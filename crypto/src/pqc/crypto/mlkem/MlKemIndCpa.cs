using System;

using Org.BouncyCastle.Utilities;

namespace Org.BouncyCastle.Pqc.Crypto.MLKem
{
    internal class MLKemIndCpa
    {
        private readonly MLKemEngine m_engine;
        private readonly Symmetric m_symmetric;
        internal MLKemIndCpa(MLKemEngine mEngine)
        {
            m_engine = mEngine;
            m_symmetric = mEngine.Symmetric;
        }
        
        private int GenerateMatrixNBlocks => ((12 * MLKemEngine.N / 8 * (1 << 12) / MLKemEngine.Q + m_symmetric.XofBlockBytes) / m_symmetric.XofBlockBytes);

        private void GenerateMatrix(PolyVec[] a, byte[] seed, bool transposed)
        {
            int K = m_engine.K;

            byte[] buf = new byte[GenerateMatrixNBlocks * m_symmetric.XofBlockBytes + 2];
            for (int i = 0; i < K; i++)
            {
                for (int j = 0; j < K; j++)
                {
                    if (transposed)
                    {
                        m_symmetric.XofAbsorb(seed, (byte) i, (byte) j);
                    }
                    else
                    {
                        m_symmetric.XofAbsorb(seed, (byte) j, (byte) i);
                    }
                    m_symmetric.XofSqueezeBlocks(buf, 0, GenerateMatrixNBlocks * m_symmetric.XofBlockBytes);
                    int buflen = GenerateMatrixNBlocks * m_symmetric.XofBlockBytes;
                    int ctr = RejectionSampling(a[i].m_vec[j].m_coeffs, 0, MLKemEngine.N, buf, buflen);
                    while (ctr < MLKemEngine.N)
                    {
                        int off = buflen % 3;
                        for (int k = 0; k < off; k++)
                        {
                            buf[k] = buf[buflen - off + k];
                        }
                        m_symmetric.XofSqueezeBlocks(buf, off, m_symmetric.XofBlockBytes * 2);
                        buflen = off + m_symmetric.XofBlockBytes;
                        ctr += RejectionSampling(a[i].m_vec[j].m_coeffs, ctr, MLKemEngine.N - ctr, buf, buflen);
                    }

                }
            }
            return;
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

        //      /// <summary>
        //      /// Generates IndCpa Key Pair
        //      /// </summary>
        //      /// <returns> KeyPair where each key is represented as bytes</returns>
        //internal byte[][] GenerateKeyPair(byte[] d)
        //      {
        //          PolyVec secretKey = new PolyVec(m_engine),
        //          publicKey = new PolyVec(m_engine),
        //          e = new PolyVec(m_engine);
        //          // (p, sigma) <- G(d || k)
        //	byte[] buf = new byte[64];
        //	byte[] k = new byte[1];

        //          k[0] = (byte)m_engine.K;
        //          m_symmetric.Hash_g(buf, Arrays.Concatenate(d, k));
        //	byte[] publicSeed = new byte[32]; // p input docs
        //	byte[] noiseSeed = new byte[32]; // sigma input docs


        //          Array.Copy(buf, 0, publicSeed, 0, 32);
        //          Array.Copy(buf, 32, noiseSeed, 0, 32);
        //          byte count = (byte)0;
        //          // Helper.PrintByteArray(buf);
        //          PolyVec[] aMatrix = new PolyVec[m_engine.K];
        //          int i;
        //          for (i = 0; i < m_engine.K; i++)
        //          {
        //              aMatrix[i] = new PolyVec(m_engine);
        //          }

        //          GenerateMatrix(aMatrix, publicSeed, false);
        //          for (i = 0; i < m_engine.K; i++)
        //          {
        //              secretKey.m_vec[i].GetNoiseEta1(noiseSeed, count);
        //              count = (byte)(count + (byte)1);
        //          }
        //          for (i = 0; i < m_engine.K; i++)
        //          {
        //              e.m_vec[i].GetNoiseEta1(noiseSeed, count);
        //              count = (byte)(count + (byte)1);
        //          }
        //          secretKey.Ntt();
        //          e.Ntt();
        //          for (i = 0; i < m_engine.K; i++)
        //          {

        //              PolyVec.PointwiseAccountMontgomery(publicKey.m_vec[i], aMatrix[i], secretKey, m_engine);
        //              publicKey.m_vec[i].PolyInverseNttToMont();
        //          }

        //          publicKey.Add(e);
        //          publicKey.Reduce();
        //          return new byte[][] { PackPublicKey(publicKey, publicSeed), PackSecretKey(secretKey) };
        //      }

        internal void GenerateKeyPair(byte[] d, out byte[] pk, out byte[] sk)
        {
            int K = m_engine.K;

            byte[] buf = new byte[2 * MLKemEngine.SymBytes];
            byte nonce = 0;
            PolyVec[] Matrix = new PolyVec[K];
            PolyVec e = new PolyVec(m_engine), pkpv = new PolyVec(m_engine), skpv = new PolyVec(m_engine);

            m_symmetric.Hash_g(buf, Arrays.Append(d, (byte) K));

            byte[] PublicSeed = Arrays.CopyOfRange(buf, 0, MLKemEngine.SymBytes);
            byte[] NoiseSeed = Arrays.CopyOfRange(buf, MLKemEngine.SymBytes, 2 * MLKemEngine.SymBytes);

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

            for (int i = 0; i < K; i++)
            {
                PolyVec.PointwiseAccountMontgomery(pkpv.m_vec[i], Matrix[i], skpv, m_engine);
                pkpv.m_vec[i].ToMont();
            }

            pkpv.Add(e);
            pkpv.Reduce();

            PackSecretKey(out sk, skpv);
            PackPublicKey(out pk, pkpv, PublicSeed);
        }

        internal void GenerateKeyPair(out byte[] pk, out byte[] sk)
        {
            int K = m_engine.K;

            byte[] buf = new byte[2 * MLKemEngine.SymBytes];
            byte nonce = 0;
            PolyVec[] Matrix = new PolyVec[K];
            PolyVec e = new PolyVec(m_engine), pkpv = new PolyVec(m_engine), skpv = new PolyVec(m_engine);

            byte[] d = new byte[32];
            m_engine.RandomBytes(d, 32);
            
            m_symmetric.Hash_g(buf, d);

            byte[] PublicSeed = Arrays.CopyOfRange(buf, 0, MLKemEngine.SymBytes);
            byte[] NoiseSeed = Arrays.CopyOfRange(buf, MLKemEngine.SymBytes, 2 * MLKemEngine.SymBytes);

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
            
            for (int i = 0; i < K; i++)
            {
                PolyVec.PointwiseAccountMontgomery(pkpv.m_vec[i], Matrix[i], skpv, m_engine);
                pkpv.m_vec[i].ToMont();
            }
            
            pkpv.Add(e);
            pkpv.Reduce();

            PackSecretKey(out sk, skpv);
            PackPublicKey(out pk, pkpv, PublicSeed);
        }

        private void PackSecretKey(out byte[] sk, PolyVec skpv)
        {
            sk = new byte[m_engine.PolyVecBytes];
            skpv.ToBytes(sk);
        }

        private void UnpackSecretKey(PolyVec skpv, byte[] sk)
        {
            skpv.FromBytes(sk);
        }

        private void PackPublicKey(out byte[] pk, PolyVec pkpv, byte[] seed)
        {
            pk = new byte[m_engine.IndCpaPublicKeyBytes];
            pkpv.ToBytes(pk);
            Array.Copy(seed, 0, pk, m_engine.PolyVecBytes, MLKemEngine.SymBytes);
        }

        private void UnpackPublicKey(PolyVec pkpv, byte[] seed, byte[] pk)
        {
            pkpv.FromBytes(pk);
            Array.Copy(pk, m_engine.PolyVecBytes, seed, 0, MLKemEngine.SymBytes);
        }

        public void Encrypt(byte[] c, byte[] m, byte[] pk, byte[] coins)
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
    }
}
