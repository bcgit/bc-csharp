
using System;

namespace Org.BouncyCastle.Pqc.Crypto.Crystals.Kyber
{
    internal class Poly
    {
        private KyberEngine m_engine;
        public short[] m_coeffs = new short[KyberEngine.N];
        private Symmetric m_symmetric;
        public Poly(KyberEngine mEngine)
        {
            m_engine = mEngine;
            m_symmetric = mEngine.Symmetric;
        }
        
        internal short[] Coeffs => m_coeffs;

        internal void GetNoiseEta1(byte[] seed, byte nonce)
        {
            byte[] buf = new byte[m_engine.Eta1 * KyberEngine.N / 4];
            m_symmetric.Prf(buf, seed, nonce);
            Cbd.Eta(this, buf, m_engine.Eta1);
        }

        internal void GetNoiseEta2(byte[] seed, byte nonce)
        {
            byte[] buf = new byte[KyberEngine.Eta2 * KyberEngine.N / 4];
            m_symmetric.Prf(buf, seed, nonce);
            Cbd.Eta(this, buf, KyberEngine.Eta2);
        }

        internal void PolyNtt()
        {
            Ntt.NTT(Coeffs);
            PolyReduce();
        }

        internal void PolyInverseNttToMont()
        {
            Ntt.InvNTT(Coeffs);
        }

        internal static void BaseMultMontgomery(Poly r, Poly a, Poly b)
        {
            for (int i = 0; i < KyberEngine.N/4; i++)
            {
                Ntt.BaseMult(r.Coeffs, 4 * i,
                    a.Coeffs[4 * i], a.Coeffs[4 * i + 1],
                    b.Coeffs[4 * i], b.Coeffs[4 * i + 1],
                    Ntt.Zetas[64 + i]);
                Ntt.BaseMult(r.Coeffs, 4 * i + 2,
                    a.Coeffs[4 * i + 2], a.Coeffs[4 * i + 3],
                    b.Coeffs[4 * i + 2], b.Coeffs[4 * i + 3],
                    (short) (-1  * Ntt.Zetas[64 + i]));
            }
        }

        internal void ToMont()
        {
            const short f = (short) ((1UL << 32) % KyberEngine.Q);
            for (int i = 0; i < KyberEngine.N; i++)
            {
                Coeffs[i] = Reduce.MontgomeryReduce(Coeffs[i] * f);
            }
        }

        internal void Add(Poly a)
        {
            for (int i = 0; i < KyberEngine.N; i++)
            {
                Coeffs[i] += a.Coeffs[i];
            }
        }

        internal void Subtract(Poly a)
        {
            for (int i = 0; i < KyberEngine.N; i++)
            {
                Coeffs[i] = (short) (a.Coeffs[i] - Coeffs[i]);
            }
        }

        internal void PolyReduce()
        {
            for (int i = 0; i < KyberEngine.N; i++)
            {
                Coeffs[i] = Reduce.BarrettReduce(Coeffs[i]);
            }
        }

        internal void CompressPoly(byte[] r, int off)
        {
            byte[] t = new byte[8];
            int count = 0;
            CondSubQ();

            if (m_engine.PolyCompressedBytes == 128)
            {
                for (int i = 0; i < KyberEngine.N / 8; i++)
                {
                    for (int j = 0; j < 8; j++)
                    {
                        t[j] =
                            (byte)(((((Coeffs[8 * i + j]) << 4)
                                +
                                (KyberEngine.Q / 2)
                            ) / KyberEngine.Q)
                                & 15);
                    }

                    r[off + count + 0] = (byte)(t[0] | (t[1] << 4));
                    r[off + count + 1] = (byte)(t[2] | (t[3] << 4));
                    r[off + count + 2] = (byte)(t[4] | (t[5] << 4));
                    r[off + count + 3] = (byte)(t[6] | (t[7] << 4));
                    count += 4;
                }
            }
            else if (m_engine.PolyCompressedBytes == 160)
            {
                for (int i = 0; i < KyberEngine.N / 8; i++)
                {
                    for (int j = 0; j < 8; j++)
                    {
                        t[j] =
                            (byte)((((Coeffs[8 * i + j] << 5)
                                +
                                (KyberEngine.Q / 2)
                            ) / KyberEngine.Q
                            ) & 31
                            );
                    }
                    r[off + count + 0] = (byte)((t[0] >> 0) | (t[1] << 5));
                    r[off + count + 1] = (byte)((t[1] >> 3) | (t[2] << 2) | (t[3] << 7));
                    r[off + count + 2] = (byte)((t[3] >> 1) | (t[4] << 4));
                    r[off + count + 3] = (byte)((t[4] >> 4) | (t[5] << 1) | (t[6] << 6));
                    r[off + count + 4] = (byte)((t[6] >> 2) | (t[7] << 3));
                    count += 5;
                }
            }
            else
            {
                throw new ArgumentException("PolyCompressedBytes is neither 128 or 160!");
            }
        }

        internal void DecompressPoly(byte[] CompressedCipherText, int off)
        {
            int count = off;

            if (m_engine.PolyCompressedBytes == 128)
            {
                for (int i = 0; i < KyberEngine.N / 2; i++)
                {
                    Coeffs[2 * i + 0]  = (short)((((short)((CompressedCipherText[count] & 0xFF) & 15) * KyberEngine.Q) + 8) >> 4);
                    Coeffs[2 * i + 1] = (short)((((short)((CompressedCipherText[count] & 0xFF) >> 4) * KyberEngine.Q) + 8) >> 4);
                    count += 1;
                }
            }
            else if (m_engine.PolyCompressedBytes == 160)
            {
                byte[] t = new byte[8];
                for (int i = 0; i < KyberEngine.N / 8; i++)
                {
                    t[0] = (byte)((CompressedCipherText[count + 0] & 0xFF) >> 0);
                    t[1] = (byte)(((CompressedCipherText[count + 0] & 0xFF) >> 5) | ((CompressedCipherText[count + 1] & 0xFF) << 3));
                    t[2] = (byte)((CompressedCipherText[count + 1] & 0xFF) >> 2);
                    t[3] = (byte)(((CompressedCipherText[count + 1] & 0xFF) >> 7) | ((CompressedCipherText[count + 2] & 0xFF) << 1));
                    t[4] = (byte)(((CompressedCipherText[count + 2] & 0xFF) >> 4) | ((CompressedCipherText[count + 3] & 0xFF) << 4));
                    t[5] = (byte)((CompressedCipherText[count + 3] & 0xFF) >> 1);
                    t[6] = (byte)(((CompressedCipherText[count + 3] & 0xFF) >> 6) | ((CompressedCipherText[count + 4] & 0xFF) << 2));
                    t[7] = (byte)((CompressedCipherText[count + 4] & 0xFF) >> 3);
                    count += 5;
                    for (int j = 0; j < 8; j++)
                    {
                        Coeffs[8 * i + j] = (short)(((t[j] & 31) * KyberEngine.Q + 16) >> 5);
                    }
                }
            }
            else
            {
                throw new ArgumentException("PolyCompressedBytes is neither 128 or 160!");
            }
        }
        
        internal void ToBytes(byte[] r, int off)
        {
            CondSubQ();

            for (int i = 0; i < KyberEngine.N/2; i++)
            {
                ushort t0 = (ushort) Coeffs[2 * i];
                ushort t1 = (ushort) Coeffs[2 * i + 1];
                r[off + 3 * i + 0] = (byte) (ushort) (t0 >> 0);
                r[off + 3 * i + 1] = (byte)((t0 >> 8) | (ushort) (t1 << 4));
                r[off + 3 * i + 2] = (byte) (ushort) (t1 >> 4);
            }
        }

        internal void FromBytes(byte[] a, int off)
        {
            for (int i = 0; i < KyberEngine.N / 2; i++)
            {
                Coeffs[2 * i] = (short) ((((a[off + 3 * i + 0] & 0xFF) >> 0) | (ushort)((a[off + 3 * i + 1] & 0xFF) << 8)) & 0xFFF);
                Coeffs[2 * i + 1] = (short) ((((a[off + 3 * i + 1] & 0xFF) >> 4) | (ushort)((a[off + 3 * i + 2] & 0xFF) << 4)) & 0xFFF);
            }
        }

        internal void ToMsg(byte[] msg)
        {
            CondSubQ();

            for (int i = 0; i < KyberEngine.N / 8; i++)
            {
                msg[i] = 0;
                for (int j = 0; j < 8; j++)
                {
                    short t = (short)(((((short)(Coeffs[8 * i + j] << 1) + KyberEngine.Q / 2) / KyberEngine.Q) & 1));
                    msg[i] |= (byte)(t << j);
                }
            }
        }

        internal void FromMsg(byte[] m)
        {
            if (m.Length != KyberEngine.N / 8)
            {
                throw new ArgumentException("KYBER_INDCPA_MSGBYTES must be equal to KYBER_N/8 bytes!");
            }
            for (int i = 0; i < KyberEngine.N / 8; i++)
            {
                for (int j = 0; j < 8; j++)
                {
                    short mask = (short)((-1) * (short)(((m[i] & 0xFF) >> j) & 1));
                    Coeffs[8 * i + j] = (short)(mask & ((KyberEngine.Q + 1) / 2));
                }
            }
        }

        internal void CondSubQ()
        {
            for (int i = 0; i < KyberEngine.N; i++)
            {
                Coeffs[i] = Reduce.CondSubQ(Coeffs[i]);
            }
        }
    }
}
