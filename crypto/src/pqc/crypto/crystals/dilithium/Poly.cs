using System;
using System.Diagnostics;

using Org.BouncyCastle.Crypto.Digests;

namespace Org.BouncyCastle.Pqc.Crypto.Crystals.Dilithium
{
    internal class Poly
    {
        private const int N = DilithiumEngine.N;

        private readonly DilithiumEngine Engine;
        private readonly int PolyUniformNBlocks;
        private readonly Symmetric Symmetric;

        internal readonly int[] Coeffs;

        public Poly(DilithiumEngine engine)
        {
            Engine = engine;
            Symmetric = engine.Symmetric;
            PolyUniformNBlocks = (768 + Symmetric.Stream128BlockBytes - 1) / Symmetric.Stream128BlockBytes;

            Coeffs = new int[N];
        }

        public void UniformBlocks(byte[] seed, ushort nonce)
        {
            int i, ctr, off,
                buflen = PolyUniformNBlocks * Symmetric.Stream128BlockBytes;
            byte[] buf = new byte[buflen + 2];
            
            Symmetric.Stream128Init(seed, nonce);

            Symmetric.Stream128SqueezeBlocks(buf, 0, buflen);

            ctr = RejectUniform(Coeffs, 0, N, buf, buflen);

            while (ctr < N)
            {
                off = buflen % 3;
                for (i = 0; i < off; ++i)
                {
                    buf[i] = buf[buflen - off + i];
                }
                Symmetric.Stream128SqueezeBlocks(buf, off, Symmetric.Stream128BlockBytes);
                buflen = Symmetric.Stream128BlockBytes + off;
                ctr += RejectUniform(Coeffs, ctr, N - ctr, buf, buflen);
            }
        }

        private static int RejectUniform(int[] coeffs, int off, int len, byte[] buf, int buflen)
        {
            int ctr = 0, pos = 0;
            while (ctr < len && pos + 3 <= buflen)
            {
                uint t;
                t = (uint)(buf[pos++] & 0xFF);
                t |= (uint)(buf[pos++] & 0xFF) << 8;
                t |= (uint)(buf[pos++] & 0xFF) << 16;
                t &= 0x7FFFFF;

                if (t < DilithiumEngine.Q)
                {
                    coeffs[off + ctr++] = (int)t;
                }
            }
            return ctr;
        }

        public void UniformEta(byte[] seed, ushort nonce)
        {
            int PolyUniformEtaNBlocks, eta = Engine.Eta;
            if (eta == 2)
            {
                PolyUniformEtaNBlocks = ((136 + Symmetric.Stream256BlockBytes - 1) / Symmetric.Stream256BlockBytes);
            }
            else if (eta == 4)
            {
                PolyUniformEtaNBlocks = ((227 + Symmetric.Stream256BlockBytes - 1) / Symmetric.Stream256BlockBytes);
            }
            else
            {
                throw new ArgumentException("Wrong Dilithium Eta!");
            }

            int buflen = PolyUniformEtaNBlocks * Symmetric.Stream256BlockBytes;

            byte[] buf = new byte[buflen];

            Symmetric.Stream256Init(seed, nonce);
            Symmetric.Stream256SqueezeBlocks(buf, 0, buflen);
            int ctr = RejectEta(Coeffs, 0, N, buf, buflen, eta);

            while (ctr < N)
            {
                Symmetric.Stream256SqueezeBlocks(buf, 0, Symmetric.Stream256BlockBytes);
                ctr += RejectEta(Coeffs, ctr, N - ctr, buf, Symmetric.Stream256BlockBytes, eta);
            }
        }

        private static int RejectEta(int[] coeffs, int off, int len, byte[] buf, int buflen, int eta)
        {
            int ctr = 0, pos = 0;

            while (ctr < len && pos < buflen)
            {
                byte b = buf[pos++];
                uint t0 = (uint)b & 0x0F;
                uint t1 = (uint)b >> 4;
                if (eta == 2)
                {
                    if (t0 < 15)
                    {
                        t0 = t0 - (205 * t0 >> 10) * 5;
                        coeffs[off + ctr++] = (int)(2 - t0);
                    }
                    if (t1 < 15 && ctr < len)
                    {
                        t1 = t1 - (205 * t1 >> 10) * 5;
                        coeffs[off + ctr++] = (int)(2 - t1);
                    }
                }
                else if (eta == 4)
                {
                    if (t0 < 9)
                    {
                        coeffs[off + ctr++] = (int)(4 - t0);
                    }
                    if (t1 < 9 && ctr < len)
                    {
                        coeffs[off + ctr++] = (int)(4 - t1);
                    }
                }
            }
            return ctr;
        }

        public void PointwiseMontgomery(Poly v, Poly w)
        {
            for (int i = 0; i < N; ++i)
            {
                Coeffs[i] = Reduce.MontgomeryReduce((long)((long)v.Coeffs[i] * (long)w.Coeffs[i]));
            }
        }

        public void PointwiseAccountMontgomery(PolyVec u, PolyVec v)
        {
            Debug.Assert(u.Vec.Length == Engine.L);
            Debug.Assert(v.Vec.Length == Engine.L);

            Poly t = new Poly(Engine);

            PointwiseMontgomery(u.Vec[0], v.Vec[0]);

            for (int i = 1; i < Engine.L; ++i)
            {
                t.PointwiseMontgomery(u.Vec[i], v.Vec[i]);
                Add(t);
            }
        }

        public void Add(Poly a)
        {
            for (int i = 0; i < N; i++)
            {
                Coeffs[i] += a.Coeffs[i];
            }
        }

        public void Subtract(Poly b)
        {
            for (int i = 0; i < N; ++i)
            {
                Coeffs[i] -= b.Coeffs[i];
            }
        }

        public void ReducePoly()
        {
            for (int i = 0; i < N; ++i)
            {
                Coeffs[i] = Reduce.Reduce32(Coeffs[i]);
            }
        }

        public void PolyNtt()
        {
            Ntt.NTT(Coeffs);
        }

        public void InverseNttToMont()
        {
            Ntt.InverseNttToMont(Coeffs);
        }

        public void ConditionalAddQ()
        {
            for (int i = 0; i < N; ++i)
            {
                Coeffs[i] = Reduce.ConditionalAddQ(Coeffs[i]);
            }
        }

        public void Power2Round(Poly a)
        {
            for (int i = 0; i < N; ++i)
            {
                int[] Power2Round = Rounding.Power2Round(Coeffs[i]);
                Coeffs[i] = Power2Round[0];
                a.Coeffs[i] = Power2Round[1];
            }
        }

        public void PolyT0Pack(byte[] r, int off)
        {
            int[] t = new int[8];
            for (int i = 0; i < N / 8; ++i)
            {
                t[0] = (1 << (DilithiumEngine.D - 1)) - Coeffs[8 * i + 0];
                t[1] = (1 << (DilithiumEngine.D - 1)) - Coeffs[8 * i + 1];
                t[2] = (1 << (DilithiumEngine.D - 1)) - Coeffs[8 * i + 2];
                t[3] = (1 << (DilithiumEngine.D - 1)) - Coeffs[8 * i + 3];
                t[4] = (1 << (DilithiumEngine.D - 1)) - Coeffs[8 * i + 4];
                t[5] = (1 << (DilithiumEngine.D - 1)) - Coeffs[8 * i + 5];
                t[6] = (1 << (DilithiumEngine.D - 1)) - Coeffs[8 * i + 6];
                t[7] = (1 << (DilithiumEngine.D - 1)) - Coeffs[8 * i + 7];

                r[off + 13 * i + 0] = (byte)(t[0]);

                r[off + 13 * i + 1] = (byte)(t[0] >> 8);
                r[off + 13 * i + 1] = (byte)(r[off + 13 * i + 1] | (byte)(t[1] << 5));
                r[off + 13 * i + 2] = (byte)(t[1] >> 3);
                r[off + 13 * i + 3] = (byte)(t[1] >> 11);
                r[off + 13 * i + 3] = (byte)(r[off + 13 * i + 3] | (byte)(t[2] << 2));
                r[off + 13 * i + 4] = (byte)(t[2] >> 6);
                r[off + 13 * i + 4] = (byte)(r[off + 13 * i + 4] | (byte)(t[3] << 7));
                r[off + 13 * i + 5] = (byte)(t[3] >> 1);
                r[off + 13 * i + 6] = (byte)(t[3] >> 9);
                r[off + 13 * i + 6] = (byte)(r[off + 13 * i + 6] | (byte)(t[4] << 4));
                r[off + 13 * i + 7] = (byte)(t[4] >> 4);
                r[off + 13 * i + 8] = (byte)(t[4] >> 12);
                r[off + 13 * i + 8] = (byte)(r[off + 13 * i + 8] | (byte)(t[5] << 1));
                r[off + 13 * i + 9] = (byte)(t[5] >> 7);
                r[off + 13 * i + 9] = (byte)(r[off + 13 * i + 9] | (byte)(t[6] << 6));
                r[off + 13 * i + 10] = (byte)(t[6] >> 2);
                r[off + 13 * i + 11] = (byte)(t[6] >> 10);
                r[off + 13 * i + 11] = (byte)(r[off + 13 * i + 11] | (byte)(t[7] << 3));
                r[off + 13 * i + 12] = (byte)(t[7] >> 5);
            }
        }

        public void PolyT0Unpack(byte[] a, int off)
        {
            for (int i = 0; i < N / 8; ++i)
            {
                Coeffs[8 * i + 0] =
                    (
                        (a[off + 13 * i + 0] & 0xFF) |
                            ((a[off + 13 * i + 1] & 0xFF) << 8)
                    ) & 0x1FFF;
                Coeffs[8 * i + 1] =
                    (
                        (((a[off + 13 * i + 1] & 0xFF) >> 5) |
                            ((a[off + 13 * i + 2] & 0xFF) << 3)) |
                            ((a[off + 13 * i + 3] & 0xFF) << 11)
                    ) & 0x1FFF;

                Coeffs[8 * i + 2] =
                    (
                        (((a[off + 13 * i + 3] & 0xFF) >> 2) |
                            ((a[off + 13 * i + 4] & 0xFF) << 6))
                    ) & 0x1FFF;

                Coeffs[8 * i + 3] =
                    (
                        (((a[off + 13 * i + 4] & 0xFF) >> 7) |
                            ((a[off + 13 * i + 5] & 0xFF) << 1)) |
                            ((a[off + 13 * i + 6] & 0xFF) << 9)
                    ) & 0x1FFF;

                Coeffs[8 * i + 4] =
                    (
                        (((a[off + 13 * i + 6] & 0xFF) >> 4) |
                            ((a[off + 13 * i + 7] & 0xFF) << 4)) |
                            ((a[off + 13 * i + 8] & 0xFF) << 12)
                    ) & 0x1FFF;

                Coeffs[8 * i + 5] =
                    (
                        (((a[off + 13 * i + 8] & 0xFF) >> 1) |
                            ((a[off + 13 * i + 9] & 0xFF) << 7))
                    ) & 0x1FFF;

                Coeffs[8 * i + 6] =
                    (
                        (((a[off + 13 * i + 9] & 0xFF) >> 6) |
                            ((a[off + 13 * i + 10] & 0xFF) << 2)) |
                            ((a[off + 13 * i + 11] & 0xFF) << 10)
                    ) & 0x1FFF;

                Coeffs[8 * i + 7] =
                    (
                        ((a[off + 13 * i + 11] & 0xFF) >> 3 |
                            ((a[off + 13 * i + 12] & 0xFF) << 5))
                    ) & 0x1FFF;


                Coeffs[8 * i + 0] = (1 << (DilithiumEngine.D - 1)) - Coeffs[8 * i + 0];
                Coeffs[8 * i + 1] = (1 << (DilithiumEngine.D - 1)) - Coeffs[8 * i + 1];
                Coeffs[8 * i + 2] = (1 << (DilithiumEngine.D - 1)) - Coeffs[8 * i + 2];
                Coeffs[8 * i + 3] = (1 << (DilithiumEngine.D - 1)) - Coeffs[8 * i + 3];
                Coeffs[8 * i + 4] = (1 << (DilithiumEngine.D - 1)) - Coeffs[8 * i + 4];
                Coeffs[8 * i + 5] = (1 << (DilithiumEngine.D - 1)) - Coeffs[8 * i + 5];
                Coeffs[8 * i + 6] = (1 << (DilithiumEngine.D - 1)) - Coeffs[8 * i + 6];
                Coeffs[8 * i + 7] = (1 << (DilithiumEngine.D - 1)) - Coeffs[8 * i + 7];
            }
        }

        public void PolyT1Pack(byte[] buf, int bufOff)
        {
            for (int i = 0; i < N / 4; ++i)
            {
                buf[bufOff + 0] = (byte)(Coeffs[4 * i + 0] >> 0);
                buf[bufOff + 1] = (byte)((Coeffs[4 * i + 0] >> 8) | (Coeffs[4 * i + 1] << 2));
                buf[bufOff + 2] = (byte)((Coeffs[4 * i + 1] >> 6) | (Coeffs[4 * i + 2] << 4));
                buf[bufOff + 3] = (byte)((Coeffs[4 * i + 2] >> 4) | (Coeffs[4 * i + 3] << 6));
                buf[bufOff + 4] = (byte)(Coeffs[4 * i + 3] >> 2);
                bufOff += 5;
            }
        }

        public void PolyT1Unpack(byte[] a, int aOff)
        {
            for (int i = 0; i < N / 4; ++i)
            {
                int a0 = a[aOff + 0];
                int a1 = a[aOff + 1];
                int a2 = a[aOff + 2];
                int a3 = a[aOff + 3];
                int a4 = a[aOff + 4];
                aOff += 5;

                Coeffs[4 * i + 0] = ((a0 >> 0) | (a1 << 8)) & 0x3FF;
                Coeffs[4 * i + 1] = ((a1 >> 2) | (a2 << 6)) & 0x3FF;
                Coeffs[4 * i + 2] = ((a2 >> 4) | (a3 << 4)) & 0x3FF;
                Coeffs[4 * i + 3] = ((a3 >> 6) | (a4 << 2));
            }
        }

        public void PolyEtaPack(byte[] r, int off)
        {
            int eta = Engine.Eta;
            if (eta == 2)
            {
                for (int i = 0; i < N / 8; ++i)
                {
                    byte t0 = (byte)(eta - Coeffs[8 * i + 0]);
                    byte t1 = (byte)(eta - Coeffs[8 * i + 1]);
                    byte t2 = (byte)(eta - Coeffs[8 * i + 2]);
                    byte t3 = (byte)(eta - Coeffs[8 * i + 3]);
                    byte t4 = (byte)(eta - Coeffs[8 * i + 4]);
                    byte t5 = (byte)(eta - Coeffs[8 * i + 5]);
                    byte t6 = (byte)(eta - Coeffs[8 * i + 6]);
                    byte t7 = (byte)(eta - Coeffs[8 * i + 7]);

                    r[off + 3 * i + 0] = (byte)((t0 >> 0) | (t1 << 3) | (t2 << 6));
                    r[off + 3 * i + 1] = (byte)((t2 >> 2) | (t3 << 1) | (t4 << 4) | (t5 << 7));
                    r[off + 3 * i + 2] = (byte)((t5 >> 1) | (t6 << 2) | (t7 << 5));
                }
            }
            else if (eta == 4)
            {
                for (int i = 0; i < N / 2; ++i)
                {
                    byte t0 = (byte)(eta - Coeffs[2 * i + 0]);
                    byte t1 = (byte)(eta - Coeffs[2 * i + 1]);
                    r[off + i] = (byte)(t0 | t1 << 4);
                }
            }
            else
            {
                throw new ArgumentException("Eta needs to be 2 or 4!");
            }
        }

        public void PolyEtaUnpack(byte[] a, int off)
        {
            int eta = Engine.Eta;
            if (eta == 2)
            {
                for (int i = 0; i < N / 8; ++i)
                {
                    Coeffs[8 * i + 0] = (((a[off + 3 * i + 0] & 0xFF) >> 0) & 7);
                    Coeffs[8 * i + 1] = ((((a[off + 3 * i + 0] & 0xFF) >> 3)) & 7);
                    Coeffs[8 * i + 2] = (((a[off + 3 * i + 0] & 0xFF) >> 6) | ((a[off + 3 * i + 1] & 0xFF) << 2) & 7);
                    Coeffs[8 * i + 3] = ((((a[off + 3 * i + 1] & 0xFF) >> 1)) & 7);
                    Coeffs[8 * i + 4] = ((((a[off + 3 * i + 1] & 0xFF) >> 4)) & 7);
                    Coeffs[8 * i + 5] = (((a[off + 3 * i + 1] & 0xFF) >> 7) | ((a[off + 3 * i + 2] & 0xFF) << 1) & 7);
                    Coeffs[8 * i + 6] = ((((a[off + 3 * i + 2] & 0xFF) >> 2)) & 7);
                    Coeffs[8 * i + 7] = ((((a[off + 3 * i + 2] & 0xFF) >> 5)) & 7);

                    Coeffs[8 * i + 0] = eta - Coeffs[8 * i + 0];
                    Coeffs[8 * i + 1] = eta - Coeffs[8 * i + 1];
                    Coeffs[8 * i + 2] = eta - Coeffs[8 * i + 2];
                    Coeffs[8 * i + 3] = eta - Coeffs[8 * i + 3];
                    Coeffs[8 * i + 4] = eta - Coeffs[8 * i + 4];
                    Coeffs[8 * i + 5] = eta - Coeffs[8 * i + 5];
                    Coeffs[8 * i + 6] = eta - Coeffs[8 * i + 6];
                    Coeffs[8 * i + 7] = eta - Coeffs[8 * i + 7];
                }
            }
            else if (eta == 4)
            {
                for (int i = 0; i < N / 2; ++i)
                {
                    Coeffs[2 * i + 0] = ((a[off + i] & 0xFF) & 0x0F);
                    Coeffs[2 * i + 1] = ((a[off + i] & 0xFF) >> 4);
                    Coeffs[2 * i + 0] = eta - Coeffs[2 * i + 0];
                    Coeffs[2 * i + 1] = eta - Coeffs[2 * i + 1];
                }
            }
        }

        public void UniformGamma1(byte[] seed, ushort nonce)
        {
            byte[] buf = new byte[Engine.PolyUniformGamma1NBytes * Symmetric.Stream256BlockBytes];
            Symmetric.Stream256Init(seed, nonce);
            Symmetric.Stream256SqueezeBlocks(buf, 0, buf.Length);
            UnpackZ(buf);
        }

        public void PackZ(byte[] r, int offset)
        {
            if (Engine.Gamma1 == (1 << 17))
            {
                for (int i = 0; i < N / 4; ++i)
                {
                    uint t0 = (uint)(Engine.Gamma1 - Coeffs[4 * i + 0]);
                    uint t1 = (uint)(Engine.Gamma1 - Coeffs[4 * i + 1]);
                    uint t2 = (uint)(Engine.Gamma1 - Coeffs[4 * i + 2]);
                    uint t3 = (uint)(Engine.Gamma1 - Coeffs[4 * i + 3]);

                    r[offset + 9 * i + 0] = (byte)t0;
                    r[offset + 9 * i + 1] = (byte)(t0 >> 8);
                    r[offset + 9 * i + 2] = (byte)((byte)(t0 >> 16) | (t1 << 2));
                    r[offset + 9 * i + 3] = (byte)(t1 >> 6);
                    r[offset + 9 * i + 4] = (byte)((byte)(t1 >> 14) | (t2 << 4));
                    r[offset + 9 * i + 5] = (byte)(t2 >> 4);
                    r[offset + 9 * i + 6] = (byte)((byte)(t2 >> 12) | (t3 << 6));
                    r[offset + 9 * i + 7] = (byte)(t3 >> 2);
                    r[offset + 9 * i + 8] = (byte)(t3 >> 10);
                }
            }
            else if (Engine.Gamma1 == (1 << 19))
            {
                for (int i = 0; i < N / 2; ++i)
                {
                    uint t0 = (uint)(Engine.Gamma1 - Coeffs[2 * i + 0]);
                    uint t1 = (uint)(Engine.Gamma1 - Coeffs[2 * i + 1]);

                    r[offset + 5 * i + 0] = (byte)t0;
                    r[offset + 5 * i + 1] = (byte)(t0 >> 8);
                    r[offset + 5 * i + 2] = (byte)((byte)(t0 >> 16) | (t1 << 4));
                    r[offset + 5 * i + 3] = (byte)(t1 >> 4);
                    r[offset + 5 * i + 4] = (byte)(t1 >> 12);
                }
            }
            else
            {
                throw new ArgumentException("Wrong Dilithium Gamma1!");
            }
        }

        public void UnpackZ(byte[] a)
        {
            if (Engine.Gamma1 == (1 << 17))
            {
                for (int i = 0; i < N / 4; ++i)
                {
                    Coeffs[4 * i + 0] =
                        (
                            (((a[9 * i + 0] & 0xFF)) |
                                ((a[9 * i + 1] & 0xFF) << 8)) |
                                ((a[9 * i + 2] & 0xFF) << 16)
                        ) & 0x3FFFF;
                    Coeffs[4 * i + 1] =
                        (
                            (((a[9 * i + 2] & 0xFF) >> 2) |
                                ((a[9 * i + 3] & 0xFF) << 6)) |
                                ((a[9 * i + 4] & 0xFF) << 14)
                        ) & 0x3FFFF;
                    Coeffs[4 * i + 2] =
                        (
                            (((a[9 * i + 4] & 0xFF) >> 4) |
                                ((a[9 * i + 5] & 0xFF) << 4)) |
                                ((a[9 * i + 6] & 0xFF) << 12)
                        ) & 0x3FFFF;
                    Coeffs[4 * i + 3] =
                        (
                            (((a[9 * i + 6] & 0xFF) >> 6) |
                                ((a[9 * i + 7] & 0xFF) << 2)) |
                                ((a[9 * i + 8] & 0xFF) << 10)
                        ) & 0x3FFFF;


                    Coeffs[4 * i + 0] = Engine.Gamma1 - Coeffs[4 * i + 0];
                    Coeffs[4 * i + 1] = Engine.Gamma1 - Coeffs[4 * i + 1];
                    Coeffs[4 * i + 2] = Engine.Gamma1 - Coeffs[4 * i + 2];
                    Coeffs[4 * i + 3] = Engine.Gamma1 - Coeffs[4 * i + 3];
                }
            }
            else if (Engine.Gamma1 == (1 << 19))
            {
                for (int i = 0; i < N / 2; ++i)
                {
                    Coeffs[2 * i + 0] =
                        (
                            (((a[5 * i + 0] & 0xFF)) |
                                ((a[5 * i + 1] & 0xFF) << 8)) |
                                ((a[5 * i + 2] & 0xFF) << 16)
                        ) & 0xFFFFF;
                    Coeffs[2 * i + 1] =
                        (
                            (((a[5 * i + 2] & 0xFF) >> 4) |
                                ((a[5 * i + 3] & 0xFF) << 4)) |
                                ((a[5 * i + 4] & 0xFF) << 12)
                        ) & 0xFFFFF;

                    Coeffs[2 * i + 0] = Engine.Gamma1 - Coeffs[2 * i + 0];
                    Coeffs[2 * i + 1] = Engine.Gamma1 - Coeffs[2 * i + 1];
                }
            }
            else
            {
                throw new ArgumentException("Wrong Dilithiumn Gamma1!");
            }
        }

        public void Decompose(Poly a)
        {
            for (int i = 0; i < N; ++i)
            {
                int[] decomp = Rounding.Decompose(Coeffs[i], Engine.Gamma2);
                a.Coeffs[i] = decomp[0];
                Coeffs[i] = decomp[1];
            }
        }

        public void PackW1(byte[] r, int off)
        {
            if (Engine.Gamma2 == (DilithiumEngine.Q - 1) / 88)
            {
                for (int i = 0; i < N / 4; ++i)
                {
                    r[off + 3 * i + 0] = (byte)(((byte)Coeffs[4 * i + 0]) | (Coeffs[4 * i + 1] << 6));
                    r[off + 3 * i + 1] = (byte)((byte)(Coeffs[4 * i + 1] >> 2) | (Coeffs[4 * i + 2] << 4));
                    r[off + 3 * i + 2] = (byte)((byte)(Coeffs[4 * i + 2] >> 4) | (Coeffs[4 * i + 3] << 2));
                }
            }
            else if (Engine.Gamma2 == (DilithiumEngine.Q - 1) / 32)
            {
                for (int i = 0; i < N / 2; ++i)
                {
                    r[off + i] = (byte)(Coeffs[2 * i + 0] | (Coeffs[2 * i + 1] << 4));
                }
            }
        }

        public void Challenge(byte[] seed)
        {
            int i, b, pos;
            ulong signs;
            byte[] buf = new byte[Symmetric.Stream256BlockBytes];

            ShakeDigest ShakeDigest256 = new ShakeDigest(256);
            ShakeDigest256.BlockUpdate(seed, 0, Engine.CTilde);
            ShakeDigest256.Output(buf, 0, Symmetric.Stream256BlockBytes);

            signs = 0;
            for (i = 0; i < 8; ++i)
            {
                signs |= (ulong)(buf[i] & 0xFF) << 8 * i;
            }

            pos = 8;

            for (i = 0; i < N; ++i)
            {
                Coeffs[i] = 0;
            }

            for (i = N - Engine.Tau; i < N; ++i)
            {
                do
                {
                    if (pos >= Symmetric.Stream256BlockBytes)
                    {
                        ShakeDigest256.Output(buf, 0, Symmetric.Stream256BlockBytes);
                        pos = 0;
                    }
                    b = (buf[pos++] & 0xFF);
                }
                while (b > i);

                Coeffs[i] = Coeffs[b];
                Coeffs[b] = (int)(1 - 2 * (signs & 1));
                signs = signs >> 1;
            }
        }

        public bool CheckNorm(int B)
        {
            if (B > (DilithiumEngine.Q - 1) / 8)
                return true;

            for (int i = 0; i < N; ++i)
            {
                int t = Coeffs[i] >> 31;
                t = Coeffs[i] - (t & 2 * Coeffs[i]);

                if (t >= B)
                    return true;
            }
            return false;
        }
        public int PolyMakeHint(Poly a0, Poly a1)
        {
            int s = 0;
            for (int i = 0; i < N; ++i)
            {
                Coeffs[i] = Rounding.MakeHint(a0.Coeffs[i], a1.Coeffs[i], Engine);
                s += Coeffs[i];
            }
            return s;
        }

        public void PolyUseHint(Poly a, Poly h)
        {
            for (int i = 0; i < N; ++i)
            {
                Coeffs[i] = Rounding.UseHint(a.Coeffs[i], h.Coeffs[i], Engine.Gamma2);
            }
        }

        public void ShiftLeft()
        {
            for (int i = 0; i < N; ++i)
            {
                Coeffs[i] <<= DilithiumEngine.D;
            }
        }
    }
}
