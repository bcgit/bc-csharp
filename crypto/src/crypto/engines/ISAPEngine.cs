using System;
using System.Drawing;
using System.IO;
#if NETSTANDARD1_0_OR_GREATER || NETCOREAPP1_0_OR_GREATER
using System.Runtime.CompilerServices;
#endif

using Org.BouncyCastle.Crypto.Modes;
using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.Crypto.Utilities;
using Org.BouncyCastle.Utilities;

namespace Org.BouncyCastle.Crypto.Engines
{
    /**
     * ISAP AEAD v2, https://isap.iaik.tugraz.at/
     * https://csrc.nist.gov/CSRC/media/Projects/lightweight-cryptography/documents/constist-round/updated-spec-doc/isap-spec-const.pdf
     * <p>
     * ISAP AEAD v2 with reference to C Reference Impl from: https://github.com/isap-lwc/isap-code-package
     * </p>
     */
    public sealed class IsapEngine
        : IAeadCipher
    {
        public enum IsapType
        {
            ISAP_A_128A,
            ISAP_K_128A,
            ISAP_A_128,
            ISAP_K_128
        }

        private const int CRYPTO_KEYBYTES = 16;
        private const int CRYPTO_NPUBBYTES = 16;
        private const int ISAP_STATE_SZ = 40;

        private string algorithmName;
        private bool forEncryption;
        private bool initialised;
        private byte[] mac;
        private MemoryStream aadData = new MemoryStream();
        private MemoryStream message = new MemoryStream();
        private MemoryStream outputStream = new MemoryStream();
        private ISAP_AEAD ISAPAEAD;
        private int ISAP_rH;
        private int ISAP_rH_SZ;

        public IsapEngine(IsapType isapType)
        {
            switch (isapType)
            {
            case IsapType.ISAP_A_128A:
                ISAPAEAD = new ISAPAEAD_A_128A();
                ISAP_rH = 64;
                algorithmName = "ISAP-A-128A AEAD";
                break;
            case IsapType.ISAP_K_128A:
                ISAPAEAD = new ISAPAEAD_K_128A();
                ISAP_rH = 144;
                algorithmName = "ISAP-K-128A AEAD";
                break;
            case IsapType.ISAP_A_128:
                ISAPAEAD = new ISAPAEAD_A_128();
                ISAP_rH = 64;
                algorithmName = "ISAP-A-128 AEAD";
                break;
            case IsapType.ISAP_K_128:
                ISAPAEAD = new ISAPAEAD_K_128();
                ISAP_rH = 144;
                algorithmName = "ISAP-K-128 AEAD";
                break;
            }
            ISAP_rH_SZ = (ISAP_rH + 7) >> 3;
        }

        public int GetKeyBytesSize()
        {
            return CRYPTO_KEYBYTES;
        }

        public int GetIVBytesSize()
        {
            return CRYPTO_NPUBBYTES;
        }

        public string AlgorithmName => algorithmName;

        private abstract class ISAP_AEAD
        {
            protected byte[] k;
            protected byte[] npub;
            protected int ISAP_rH;
            protected int ISAP_rH_SZ;

#if NETCOREAPP2_1_OR_GREATER || NETSTANDARD2_1_OR_GREATER
            public abstract void isap_enc(ReadOnlySpan<byte> m, Span<byte> c);
#else
            public abstract void isap_enc(byte[] m, int mOff, int mlen, byte[] c, int cOff);
#endif

            public abstract void init(byte[] k, byte[] npub, int ISAP_rH, int ISAP_rH_SZ);

            public abstract void isap_mac(byte[] ad, int adlen, byte[] c, int clen, byte[] tag, int tagOff);

            public abstract void reset();
        }

        private abstract class ISAPAEAD_A : ISAP_AEAD
        {
            protected ulong[] k64;
            protected ulong[] npub64;
            protected ulong ISAP_IV1_64;
            protected ulong ISAP_IV2_64;
            protected ulong ISAP_IV3_64;
            protected ulong x0, x1, x2, x3, x4, t0, t1, t2, t3, t4;

            public override void init(byte[] k, byte[] npub, int ISAP_rH, int ISAP_rH_SZ)
            {
                this.k = k;
                this.npub = npub;
                this.ISAP_rH = ISAP_rH;
                this.ISAP_rH_SZ = ISAP_rH_SZ;
                npub64 = new ulong[(npub.Length + 7) / 8];
                Pack.BE_To_UInt64(npub, 0, npub64, 0, npub64.Length);
                k64 = new ulong[(k.Length + 7) / 8];
                Pack.BE_To_UInt64(k, 0, k64, 0, k64.Length);
                reset();
            }

            protected abstract void PX1();

            protected abstract void PX2();

            protected void ABSORB_MAC(byte[] src, int len)
            {
                int off = 0;
                while (len >= 8)
                {
                    x0 ^= Pack.BE_To_UInt64(src, off);
                    off += 8;
                    len -= 8;
                    P12();
                }
                if (len > 0)
                {
                    x0 ^= Pack.BE_To_UInt64_High(src, off, len);
                }
                x0 ^= 0x8000000000000000UL >> (len << 3);
                P12();
            }

            public override void isap_mac(byte[] ad, int adlen, byte[] c, int clen, byte[] tag, int tagOff)
            {
                // Init State
                x0 = npub64[0];
                x1 = npub64[1];
                x2 = ISAP_IV1_64;
                x3 = x4 = 0;
                P12();
                ABSORB_MAC(ad, adlen);
                // Domain seperation
                x4 ^= 1L;
                ABSORB_MAC(c, clen);
                // Derive K*
                Pack.UInt64_To_BE(x0, tag, 0);
                Pack.UInt64_To_BE(x1, tag, 8);
                ulong tmp_x2 = x2, tmp_x3 = x3, tmp_x4 = x4;
                isap_rk(ISAP_IV2_64, tag, CRYPTO_KEYBYTES);
                x2 = tmp_x2;
                x3 = tmp_x3;
                x4 = tmp_x4;
                // Squeeze tag
                P12();
                Pack.UInt64_To_BE(x0, tag, tagOff);
                Pack.UInt64_To_BE(x1, tag, tagOff + 8);
            }

            public void isap_rk(ulong iv64, byte[] y, int ylen)
            {
                // Init state
                x0 = k64[0];
                x1 = k64[1];
                x2 = iv64;
                x3 = x4 = 0;
                P12();
                // Absorb Y
                for (int i = 0; i < (ylen << 3) - 1; i++)
                {
                    x0 ^= (((((ulong)y[i >> 3] >> (7 - (i & 7))) & 0x01UL) << 7) & 0xFFUL) << 56;
                    PX2();
                }
                x0 ^= (((y[ylen - 1]) & 0x01UL) << 7) << 56;
                P12();
            }

#if NETCOREAPP2_1_OR_GREATER || NETSTANDARD2_1_OR_GREATER
            public override void isap_enc(ReadOnlySpan<byte> m, Span<byte> c)
            {
                while (m.Length >= 8)
                {
                    ulong t = Pack.BE_To_UInt64(m);
                    t ^= x0;
                    Pack.UInt64_To_BE(t, c);
                    m = m[8..];
                    c = c[8..];
                    PX1();
                }
                if (!m.IsEmpty)
                {
                    ulong t = Pack.BE_To_UInt64_High(m);
                    t ^= x0;
                    Pack.UInt64_To_BE_High(t, c[..m.Length]);
                }
            }
#else
            public override void isap_enc(byte[] m, int mOff, int mlen, byte[] c, int cOff)
            {
                while (mlen >= 8)
                {
                    ulong t = Pack.BE_To_UInt64(m, mOff);
                    t ^= x0;
                    Pack.UInt64_To_BE(t, c, cOff);
                    mOff += 8;
                    mlen -= 8;
                    cOff += 8;
                    PX1();
                }
                if (mlen > 0)
                {
                    ulong t = Pack.BE_To_UInt64_High(m, mOff, mlen);
                    t ^= x0;
                    Pack.UInt64_To_BE_High(t, c, cOff, mlen);
                }
            }
#endif

            public override void reset()
            {
                // Init state
                isap_rk(ISAP_IV3_64, npub, CRYPTO_NPUBBYTES);
                x3 = npub64[0];
                x4 = npub64[1];
                PX1();
            }

#if NETSTANDARD1_0_OR_GREATER || NETCOREAPP1_0_OR_GREATER
            [MethodImpl(MethodImplOptions.AggressiveInlining)]
#endif
            protected void ROUND(ulong C)
            {
                t0 = x0 ^ x1 ^ x2 ^ x3 ^ C ^ (x1 & (x0 ^ x2 ^ x4 ^ C));
                t1 = x0 ^ x2 ^ x3 ^ x4 ^ C ^ ((x1 ^ x2 ^ C) & (x1 ^ x3));
                t2 = x1 ^ x2 ^ x4 ^ C ^ (x3 & x4);
                t3 = x0 ^ x1 ^ x2 ^ C ^ ((~x0) & (x3 ^ x4));
                t4 = x1 ^ x3 ^ x4 ^ ((x0 ^ x4) & x1);
                x0 = t0 ^ Longs.RotateRight(t0, 19) ^ Longs.RotateRight(t0, 28);
                x1 = t1 ^ Longs.RotateRight(t1, 39) ^ Longs.RotateRight(t1, 61);
                x2 = ~(t2 ^ Longs.RotateRight(t2, 1) ^ Longs.RotateRight(t2, 6));
                x3 = t3 ^ Longs.RotateRight(t3, 10) ^ Longs.RotateRight(t3, 17);
                x4 = t4 ^ Longs.RotateRight(t4, 7) ^ Longs.RotateRight(t4, 41);
            }

            public void P12()
            {
                ROUND(0xf0);
                ROUND(0xe1);
                ROUND(0xd2);
                ROUND(0xc3);
                ROUND(0xb4);
                ROUND(0xa5);
                P6();
            }

            protected void P6()
            {
                ROUND(0x96);
                ROUND(0x87);
                ROUND(0x78);
                ROUND(0x69);
                ROUND(0x5a);
                ROUND(0x4b);
            }
        }

        private class ISAPAEAD_A_128A : ISAPAEAD_A
        {
            public ISAPAEAD_A_128A()
            {
                ISAP_IV1_64 = 108156764297430540UL;
                ISAP_IV2_64 = 180214358335358476UL;
                ISAP_IV3_64 = 252271952373286412UL;
            }

            protected override void PX1()
            {
                P6();
            }

            protected override void PX2()
            {
                ROUND(0x4b);
            }
        }

        private class ISAPAEAD_A_128 : ISAPAEAD_A
        {
            public ISAPAEAD_A_128()
            {
                ISAP_IV1_64 = 108156764298152972L;
                ISAP_IV2_64 = 180214358336080908L;
                ISAP_IV3_64 = 252271952374008844L;
            }

            protected override void PX1()
            {
                P12();
            }

            protected override void PX2()
            {
                P12();
            }
        }

        private abstract class ISAPAEAD_K : ISAP_AEAD
        {
            const int ISAP_STATE_SZ_CRYPTO_NPUBBYTES = ISAP_STATE_SZ - CRYPTO_NPUBBYTES;
            protected ushort[] ISAP_IV1_16;
            protected ushort[] ISAP_IV2_16;
            protected ushort[] ISAP_IV3_16;
            protected ushort[] k16;
            protected ushort[] iv16;
            private readonly int[] KeccakF400RoundConstants = {
                0x0001, 0x8082, 0x808a, 0x8000, 0x808b, 0x0001, 0x8081, 0x8009, 0x008a, 0x0088, 0x8009, 0x000a, 0x808b,
                0x008b, 0x8089, 0x8003, 0x8002, 0x0080, 0x800a, 0x000a };
            protected ushort[] SX = new ushort[25];
            protected ushort[] E = new ushort[25];
            protected ushort[] C = new ushort[5];

            public override void init(byte[] k, byte[] npub, int ISAP_rH, int ISAP_rH_SZ)
            {
                this.k = k;
                this.npub = npub;
                this.ISAP_rH = ISAP_rH;
                this.ISAP_rH_SZ = ISAP_rH_SZ;
                k16 = new ushort[k.Length >> 1];
                Pack.LE_To_UInt16(k, 0, k16);
                iv16 = new ushort[npub.Length >> 1];
                Pack.LE_To_UInt16(npub, 0, iv16);
                reset();
            }

            public override void reset()
            {
                // Init state
                SX = new ushort[25];
                E = new ushort[25];
                C = new ushort[5];
                isap_rk(ISAP_IV3_16, npub, CRYPTO_NPUBBYTES, SX, ISAP_STATE_SZ_CRYPTO_NPUBBYTES, C);
                Array.Copy(iv16, 0, SX, 17, 8);
                PermuteRoundsKX(SX, E, C);
            }

            protected abstract void PermuteRoundsHX(ushort[] SX, ushort[] E, ushort[] C);

            protected abstract void PermuteRoundsKX(ushort[] SX, ushort[] E, ushort[] C);

            protected abstract void PermuteRoundsBX(ushort[] SX, ushort[] E, ushort[] C);

            protected void ABSORB_MAC(ushort[] SX, byte[] src, int len, ushort[] E, ushort[] C)
            {
                int rem_bytes = len;
                int idx = 0;
                while (rem_bytes > ISAP_rH_SZ)
                {
                    byteToushortXor(src, SX, ISAP_rH_SZ >> 1);
                    idx += ISAP_rH_SZ;
                    rem_bytes -= ISAP_rH_SZ;
                    PermuteRoundsHX(SX, E, C);
                }
                if (rem_bytes == ISAP_rH_SZ)
                {
                    byteToushortXor(src, SX, ISAP_rH_SZ >> 1);
                    PermuteRoundsHX(SX, E, C);
                    SX[0] ^= 0x80;
                    PermuteRoundsHX(SX, E, C);
                }
                else
                {
                    for (int i = 0; i < rem_bytes; i++)
                    {
                        SX[i >> 1] ^= (ushort)((src[idx++] & 0xFFU) << ((i & 1) << 3));
                    }
                    SX[rem_bytes >> 1] ^= (ushort)(0x80U << ((rem_bytes & 1) << 3));
                    PermuteRoundsHX(SX, E, C);
                }
            }

            public void isap_rk(ushort[] iv16, byte[] y, int ylen, ushort[] out16, int outlen, ushort[] C)
            {
                // Init state
                ushort[] SX = new ushort[25];
                ushort[] E = new ushort[25];
                Array.Copy(k16, 0, SX, 0, 8);
                Array.Copy(iv16, 0, SX, 8, 4);
                PermuteRoundsKX(SX, E, C);
                // Absorb all bits of Y
                for (int i = 0; i < (ylen << 3) - 1; i++)
                {
                    SX[0] ^= (ushort)(((y[i >> 3] >> (7 - (i & 7))) & 0x01) << 7);
                    PermuteRoundsBX(SX, E, C);
                }
                SX[0] ^= (ushort)(((y[ylen - 1]) & 0x01) << 7);
                PermuteRoundsKX(SX, E, C);
                // Extract K*
                Array.Copy(SX, 0, out16, 0, outlen == ISAP_STATE_SZ_CRYPTO_NPUBBYTES ? 17 : 8);
            }

            public override void isap_mac(byte[] ad, int adlen, byte[] c, int clen, byte[] tag, int tagOff)
            {
                SX = new ushort[25];
                // Init state
                Array.Copy(iv16, 0, SX, 0, 8);
                Array.Copy(ISAP_IV1_16, 0, SX, 8, 4);
                PermuteRoundsHX(SX, E, C);
                // Absorb AD
                ABSORB_MAC(SX, ad, adlen, E, C);
                // Domain seperation
                SX[24] ^= 0x0100;
                // Absorb C
                ABSORB_MAC(SX, c, clen, E, C);
                // Derive K*
                Pack.UInt16_To_LE(SX, 0, 8, tag, tagOff);
                isap_rk(ISAP_IV2_16, tag, CRYPTO_KEYBYTES, SX, CRYPTO_KEYBYTES, C);
                // Squeeze tag
                PermuteRoundsHX(SX, E, C);
                Pack.UInt16_To_LE(SX, 0, 8, tag, tagOff);
            }

#if NETCOREAPP2_1_OR_GREATER || NETSTANDARD2_1_OR_GREATER
            public override void isap_enc(ReadOnlySpan<byte> m, Span<byte> c)
            {
                int off = 0, len = m.Length;

                // Squeeze key stream
                while (len >= ISAP_rH_SZ)
                {
                    // Squeeze full lane and continue
                    for (int i = 0; i < ISAP_rH_SZ; ++i)
                    {
                        c[off] = (byte)((SX[i >> 1] >> ((i & 1) << 3)) ^ m[off]);
                        ++off;
                    }
                    len -= ISAP_rH_SZ;
                    PermuteRoundsKX(SX, E, C);
                }
                // Squeeze partial lane and stop
                for (int i = 0; i < len; ++i)
                {
                    c[off] = (byte)((SX[i >> 1] >> ((i & 1) << 3)) ^ m[off]);
                    ++off;
                }
            }
#else
            public override void isap_enc(byte[] m, int mOff, int mlen, byte[] c, int cOff)
            {
                // Squeeze key stream
                while (mlen >= ISAP_rH_SZ)
                {
                    // Squeeze full lane and continue
                    for (int i = 0; i < ISAP_rH_SZ; ++i)
                    {
                        c[cOff++] = (byte)((SX[i >> 1] >> ((i & 1) << 3)) ^ m[mOff++]);
                    }
                    mlen -= ISAP_rH_SZ;
                    PermuteRoundsKX(SX, E, C);
                }
                // Squeeze partial lane and stop
                for (int i = 0; i < mlen; ++i)
                {
                    c[cOff++] = (byte)((SX[i >> 1] >> ((i & 1) << 3)) ^ m[mOff++]);
                }
            }
#endif

            private void byteToushortXor(byte[] input, ushort[] output, int outLen)
            {
                for (int i = 0; i < outLen; ++i)
                {
                    output[i] ^= Pack.LE_To_UInt16(input, (i << 1));
                }
            }

            protected void rounds12X(ushort[] SX, ushort[] E, ushort[] C)
            {
                prepareThetaX(SX, C);
                rounds_8_18(SX, E, C);
            }

            protected void rounds_4_18(ushort[] SX, ushort[] E, ushort[] C)
            {
                thetaRhoPiChiIotaPrepareTheta(4, SX, E, C);
                thetaRhoPiChiIotaPrepareTheta(5, E, SX, C);
                thetaRhoPiChiIotaPrepareTheta(6, SX, E, C);
                thetaRhoPiChiIotaPrepareTheta(7, E, SX, C);
                rounds_8_18(SX, E, C);
            }

            protected void rounds_8_18(ushort[] SX, ushort[] E, ushort[] C)
            {
                thetaRhoPiChiIotaPrepareTheta(8, SX, E, C);
                thetaRhoPiChiIotaPrepareTheta(9, E, SX, C);
                thetaRhoPiChiIotaPrepareTheta(10, SX, E, C);
                thetaRhoPiChiIotaPrepareTheta(11, E, SX, C);
                rounds_12_18(SX, E, C);
            }

            protected void rounds_12_18(ushort[] SX, ushort[] E, ushort[] C)
            {
                thetaRhoPiChiIotaPrepareTheta(12, SX, E, C);
                thetaRhoPiChiIotaPrepareTheta(13, E, SX, C);
                thetaRhoPiChiIotaPrepareTheta(14, SX, E, C);
                thetaRhoPiChiIotaPrepareTheta(15, E, SX, C);
                thetaRhoPiChiIotaPrepareTheta(16, SX, E, C);
                thetaRhoPiChiIotaPrepareTheta(17, E, SX, C);
                thetaRhoPiChiIotaPrepareTheta(18, SX, E, C);
                thetaRhoPiChiIota(E, SX, C);
            }

            protected void prepareThetaX(ushort[] SX, ushort[] C)
            {
                C[0] = (ushort)(SX[0] ^ SX[5] ^ SX[10] ^ SX[15] ^ SX[20]);
                C[1] = (ushort)(SX[1] ^ SX[6] ^ SX[11] ^ SX[16] ^ SX[21]);
                C[2] = (ushort)(SX[2] ^ SX[7] ^ SX[12] ^ SX[17] ^ SX[22]);
                C[3] = (ushort)(SX[3] ^ SX[8] ^ SX[13] ^ SX[18] ^ SX[23]);
                C[4] = (ushort)(SX[4] ^ SX[9] ^ SX[14] ^ SX[19] ^ SX[24]);
            }

            protected void thetaRhoPiChiIotaPrepareTheta(int i, ushort[] A, ushort[] E, ushort[] C)
            {
                ushort Da = (ushort)(C[4] ^ Shorts.RotateLeft(C[1], 1));
                ushort De = (ushort)(C[0] ^ Shorts.RotateLeft(C[2], 1));
                ushort Di = (ushort)(C[1] ^ Shorts.RotateLeft(C[3], 1));
                ushort Do = (ushort)(C[2] ^ Shorts.RotateLeft(C[4], 1));
                ushort Du = (ushort)(C[3] ^ Shorts.RotateLeft(C[0], 1));

                ushort Ba = A[0] ^= Da;
                A[6] ^= De;
                ushort Be = Shorts.RotateLeft(A[6], 12);
                A[12] ^= Di;
                ushort Bi = Shorts.RotateLeft(A[12], 11);
                A[18] ^= Do;
                ushort Bo = Shorts.RotateLeft(A[18], 5);
                A[24] ^= Du;
                ushort Bu = Shorts.RotateLeft(A[24], 14);
                C[0] = E[0] = (ushort)(Ba ^ ((~Be) & Bi) ^ KeccakF400RoundConstants[i]);
                C[1] = E[1] = (ushort)(Be ^ ((~Bi) & Bo));
                C[2] = E[2] = (ushort)(Bi ^ ((~Bo) & Bu));
                C[3] = E[3] = (ushort)(Bo ^ ((~Bu) & Ba));
                C[4] = E[4] = (ushort)(Bu ^ ((~Ba) & Be));

                A[3] ^= Do;
                Ba = Shorts.RotateLeft(A[3], 12);
                A[9] ^= Du;
                Be = Shorts.RotateLeft(A[9], 4);
                A[10] ^= Da;
                Bi = Shorts.RotateLeft(A[10], 3);
                A[16] ^= De;
                Bo = Shorts.RotateLeft(A[16], 13);
                A[22] ^= Di;
                Bu = Shorts.RotateLeft(A[22], 13);
                E[5] = (ushort)(Ba ^ ((~Be) & Bi));
                C[0] ^= E[5];
                E[6] = (ushort)(Be ^ ((~Bi) & Bo));
                C[1] ^= E[6];
                E[7] = (ushort)(Bi ^ ((~Bo) & Bu));
                C[2] ^= E[7];
                E[8] = (ushort)(Bo ^ ((~Bu) & Ba));
                C[3] ^= E[8];
                E[9] = (ushort)(Bu ^ ((~Ba) & Be));
                C[4] ^= E[9];

                A[1] ^= De;
                Ba = Shorts.RotateLeft(A[1], 1);
                A[7] ^= Di;
                Be = Shorts.RotateLeft(A[7], 6);
                A[13] ^= Do;
                Bi = Shorts.RotateLeft(A[13], 9);
                A[19] ^= Du;
                Bo = Shorts.RotateLeft(A[19], 8);
                A[20] ^= Da;
                Bu = Shorts.RotateLeft(A[20], 2);
                E[10] = (ushort)(Ba ^ ((~Be) & Bi));
                C[0] ^= E[10];
                E[11] = (ushort)(Be ^ ((~Bi) & Bo));
                C[1] ^= E[11];
                E[12] = (ushort)(Bi ^ ((~Bo) & Bu));
                C[2] ^= E[12];
                E[13] = (ushort)(Bo ^ ((~Bu) & Ba));
                C[3] ^= E[13];
                E[14] = (ushort)(Bu ^ ((~Ba) & Be));
                C[4] ^= E[14];

                A[4] ^= Du;
                Ba = Shorts.RotateLeft(A[4], 11);
                A[5] ^= Da;
                Be = Shorts.RotateLeft(A[5], 4);
                A[11] ^= De;
                Bi = Shorts.RotateLeft(A[11], 10);
                A[17] ^= Di;
                Bo = Shorts.RotateLeft(A[17], 15);
                A[23] ^= Do;
                Bu = Shorts.RotateLeft(A[23], 8);
                E[15] = (ushort)(Ba ^ ((~Be) & Bi));
                C[0] ^= E[15];
                E[16] = (ushort)(Be ^ ((~Bi) & Bo));
                C[1] ^= E[16];
                E[17] = (ushort)(Bi ^ ((~Bo) & Bu));
                C[2] ^= E[17];
                E[18] = (ushort)(Bo ^ ((~Bu) & Ba));
                C[3] ^= E[18];
                E[19] = (ushort)(Bu ^ ((~Ba) & Be));
                C[4] ^= E[19];

                A[2] ^= Di;
                Ba = Shorts.RotateLeft(A[2], 14);
                A[8] ^= Do;
                Be = Shorts.RotateLeft(A[8], 7);
                A[14] ^= Du;
                Bi = Shorts.RotateLeft(A[14], 7);
                A[15] ^= Da;
                Bo = Shorts.RotateLeft(A[15], 9);
                A[21] ^= De;
                Bu = Shorts.RotateLeft(A[21], 2);
                E[20] = (ushort)(Ba ^ ((~Be) & Bi));
                C[0] ^= E[20];
                E[21] = (ushort)(Be ^ ((~Bi) & Bo));
                C[1] ^= E[21];
                E[22] = (ushort)(Bi ^ ((~Bo) & Bu));
                C[2] ^= E[22];
                E[23] = (ushort)(Bo ^ ((~Bu) & Ba));
                C[3] ^= E[23];
                E[24] = (ushort)(Bu ^ ((~Ba) & Be));
                C[4] ^= E[24];
            }

            protected void thetaRhoPiChiIota(ushort[] A, ushort[] E, ushort[] C)
            {
                ushort Da = (ushort)(C[4] ^ Shorts.RotateLeft(C[1], 1));
                ushort De = (ushort)(C[0] ^ Shorts.RotateLeft(C[2], 1));
                ushort Di = (ushort)(C[1] ^ Shorts.RotateLeft(C[3], 1));
                ushort Do = (ushort)(C[2] ^ Shorts.RotateLeft(C[4], 1));
                ushort Du = (ushort)(C[3] ^ Shorts.RotateLeft(C[0], 1));

                ushort Ba = A[0] ^= Da;
                A[6] ^= De;
                ushort Be = Shorts.RotateLeft(A[6], 12);
                A[12] ^= Di;
                ushort Bi = Shorts.RotateLeft(A[12], 11);
                A[18] ^= Do;
                ushort Bo = Shorts.RotateLeft(A[18], 5);
                A[24] ^= Du;
                ushort Bu = Shorts.RotateLeft(A[24], 14);
                E[0] = (ushort)(Ba ^ ((~Be) & Bi) ^ KeccakF400RoundConstants[19]);
                E[1] = (ushort)(Be ^ ((~Bi) & Bo));
                E[2] = (ushort)(Bi ^ ((~Bo) & Bu));
                E[3] = (ushort)(Bo ^ ((~Bu) & Ba));
                E[4] = (ushort)(Bu ^ ((~Ba) & Be));

                A[3] ^= Do;
                Ba = Shorts.RotateLeft(A[3], 12);
                A[9] ^= Du;
                Be = Shorts.RotateLeft(A[9], 4);
                A[10] ^= Da;
                Bi = Shorts.RotateLeft(A[10], 3);
                A[16] ^= De;
                Bo = Shorts.RotateLeft(A[16], 13);
                A[22] ^= Di;
                Bu = Shorts.RotateLeft(A[22], 13);
                E[5] = (ushort)(Ba ^ ((~Be) & Bi));
                E[6] = (ushort)(Be ^ ((~Bi) & Bo));
                E[7] = (ushort)(Bi ^ ((~Bo) & Bu));
                E[8] = (ushort)(Bo ^ ((~Bu) & Ba));
                E[9] = (ushort)(Bu ^ ((~Ba) & Be));

                A[1] ^= De;
                Ba = Shorts.RotateLeft(A[1], 1);
                A[7] ^= Di;
                Be = Shorts.RotateLeft(A[7], 6);
                A[13] ^= Do;
                Bi = Shorts.RotateLeft(A[13], 9);
                A[19] ^= Du;
                Bo = Shorts.RotateLeft(A[19], 8);
                A[20] ^= Da;
                Bu = Shorts.RotateLeft(A[20], 2);
                E[10] = (ushort)(Ba ^ ((~Be) & Bi));
                E[11] = (ushort)(Be ^ ((~Bi) & Bo));
                E[12] = (ushort)(Bi ^ ((~Bo) & Bu));
                E[13] = (ushort)(Bo ^ ((~Bu) & Ba));
                E[14] = (ushort)(Bu ^ ((~Ba) & Be));

                A[4] ^= Du;
                Ba = Shorts.RotateLeft(A[4], 11);
                A[5] ^= Da;
                Be = Shorts.RotateLeft(A[5], 4);
                A[11] ^= De;
                Bi = Shorts.RotateLeft(A[11], 10);
                A[17] ^= Di;
                Bo = Shorts.RotateLeft(A[17], 15);
                A[23] ^= Do;
                Bu = Shorts.RotateLeft(A[23], 8);
                E[15] = (ushort)(Ba ^ ((~Be) & Bi));
                E[16] = (ushort)(Be ^ ((~Bi) & Bo));
                E[17] = (ushort)(Bi ^ ((~Bo) & Bu));
                E[18] = (ushort)(Bo ^ ((~Bu) & Ba));
                E[19] = (ushort)(Bu ^ ((~Ba) & Be));

                A[2] ^= Di;
                Ba = Shorts.RotateLeft(A[2], 14);
                A[8] ^= Do;
                Be = Shorts.RotateLeft(A[8], 7);
                A[14] ^= Du;
                Bi = Shorts.RotateLeft(A[14], 7);
                A[15] ^= Da;
                Bo = Shorts.RotateLeft(A[15], 9);
                A[21] ^= De;
                Bu = Shorts.RotateLeft(A[21], 2);
                E[20] = (ushort)(Ba ^ ((~Be) & Bi));
                E[21] = (ushort)(Be ^ ((~Bi) & Bo));
                E[22] = (ushort)(Bi ^ ((~Bo) & Bu));
                E[23] = (ushort)(Bo ^ ((~Bu) & Ba));
                E[24] = (ushort)(Bu ^ ((~Ba) & Be));
            }
        }

        private class ISAPAEAD_K_128A : ISAPAEAD_K
        {
            public ISAPAEAD_K_128A()
            {
                ISAP_IV1_16 = new ushort[]{ 32769, 400, 272, 2056 };
                ISAP_IV2_16 = new ushort[]{ 32770, 400, 272, 2056 };
                ISAP_IV3_16 = new ushort[]{ 32771, 400, 272, 2056 };
            }

            protected override void PermuteRoundsHX(ushort[] SX, ushort[] E, ushort[] C)
            {
                prepareThetaX(SX, C);
                rounds_4_18(SX, E, C);
            }

            protected override void PermuteRoundsKX(ushort[] SX, ushort[] E, ushort[] C)
            {
                prepareThetaX(SX, C);
                rounds_12_18(SX, E, C);
            }

            protected override void PermuteRoundsBX(ushort[] SX, ushort[] E, ushort[] C)
            {
                prepareThetaX(SX, C);
                thetaRhoPiChiIotaPrepareTheta(19, SX, E, C);
                Array.Copy(E, 0, SX, 0, E.Length);
            }
        }

        private class ISAPAEAD_K_128
            : ISAPAEAD_K
        {
            public ISAPAEAD_K_128()
            {
                ISAP_IV1_16 = new ushort[]{ 32769, 400, 3092, 3084 };
                ISAP_IV2_16 = new ushort[]{ 32770, 400, 3092, 3084 };
                ISAP_IV3_16 = new ushort[]{ 32771, 400, 3092, 3084 };
            }

            protected override void PermuteRoundsHX(ushort[] SX, ushort[] E, ushort[] C)
            {
                prepareThetaX(SX, C);
                thetaRhoPiChiIotaPrepareTheta(0, SX, E, C);
                thetaRhoPiChiIotaPrepareTheta(1, E, SX, C);
                thetaRhoPiChiIotaPrepareTheta(2, SX, E, C);
                thetaRhoPiChiIotaPrepareTheta(3, E, SX, C);
                rounds_4_18(SX, E, C);
            }

            protected override void PermuteRoundsKX(ushort[] SX, ushort[] E, ushort[] C)
            {
                rounds12X(SX, E, C);
            }

            protected override void PermuteRoundsBX(ushort[] SX, ushort[] E, ushort[] C)
            {
                rounds12X(SX, E, C);
            }
        }

        public void Init(bool forEncryption, ICipherParameters param)
        {
            this.forEncryption = forEncryption;
            if (!(param is ParametersWithIV withIV))
                throw new ArgumentException("ISAP AEAD init parameters must include an IV");

            byte[] iv = withIV.GetIV();
            if (iv == null || iv.Length != 16)
                throw new ArgumentException("ISAP AEAD requires exactly 12 bytes of IV");

            if (!(withIV.Parameters is KeyParameter key))
                throw new ArgumentException("ISAP AEAD init parameters must include a key");

            byte[] keyBytes = key.GetKey();
            if (keyBytes.Length != 16)
                throw new ArgumentException("ISAP AEAD key must be 128 bits ulong");

            /*
             * Initialize variables.
             */
            initialised = true;
            ISAPAEAD.init(keyBytes, iv, ISAP_rH, ISAP_rH_SZ);
            Reset();
        }

        public void ProcessAadByte(byte input)
        {
            aadData.WriteByte(input);
        }

        public void ProcessAadBytes(byte[] inBytes, int inOff, int len)
        {
            Check.DataLength(inBytes, inOff, len, "input buffer too short");

            aadData.Write(inBytes, inOff, len);
        }

#if NETCOREAPP2_1_OR_GREATER || NETSTANDARD2_1_OR_GREATER
        public void ProcessAadBytes(ReadOnlySpan<byte> input)
        {
            aadData.Write(input);
        }
#endif

        public int ProcessByte(byte input, byte[] outBytes, int outOff)
        {
#if NETCOREAPP2_1_OR_GREATER || NETSTANDARD2_1_OR_GREATER
            return ProcessByte(input, Spans.FromNullable(outBytes, outOff));
#else
            return ProcessBytes(new byte[]{ input }, 0, 1, outBytes, outOff);
#endif
        }

#if NETCOREAPP2_1_OR_GREATER || NETSTANDARD2_1_OR_GREATER
        public int ProcessByte(byte input, Span<byte> output)
        {
            Span<byte> singleByte = stackalloc byte[1]{ input };

            return ProcessBytes(singleByte, output);
        }
#endif

        public int ProcessBytes(byte[] inBytes, int inOff, int len, byte[] outBytes, int outOff)
        {
            Check.DataLength(inBytes, inOff, len, "input buffer too short");

#if NETCOREAPP2_1_OR_GREATER || NETSTANDARD2_1_OR_GREATER
            return ProcessBytes(inBytes.AsSpan(inOff, len), Spans.FromNullable(outBytes, outOff));
#else
            if (!initialised)
                throw new ArgumentException("Need to call Init function before encryption/decryption");

            message.Write(inBytes, inOff, len);

            if (forEncryption)
            {
                int msgLen = Convert.ToInt32(message.Length);
                if (msgLen >= ISAP_rH_SZ)
                {
                    int outLen = msgLen / ISAP_rH_SZ * ISAP_rH_SZ;
                    Check.OutputLength(outBytes, outOff, outLen, "output buffer is too short");
                    byte[] enc_input = message.GetBuffer();
                    ISAPAEAD.isap_enc(enc_input, 0, outLen, outBytes, outOff);
                    outputStream.Write(outBytes, outOff, outLen);
                    int enc_input_len = msgLen;
                    message.SetLength(0);
                    message.Write(enc_input, outLen, enc_input_len - outLen);
                    return outLen;
                }
            }
            return 0;
#endif
        }

#if NETCOREAPP2_1_OR_GREATER || NETSTANDARD2_1_OR_GREATER
        public int ProcessBytes(ReadOnlySpan<byte> input, Span<byte> output)
        {
            if (!initialised)
                throw new ArgumentException("Need to call Init function before encryption/decryption");

            message.Write(input);

            if (forEncryption)
            {
                int msgLen = Convert.ToInt32(message.Length);
                if (msgLen >= ISAP_rH_SZ)
                {
                    int outLen = msgLen / ISAP_rH_SZ * ISAP_rH_SZ;
                    Check.OutputLength(output, outLen, "output buffer is too short");
                    byte[] enc_input = message.GetBuffer();
                    ISAPAEAD.isap_enc(enc_input.AsSpan(0, outLen), output);
                    outputStream.Write(output[..outLen]);
                    int enc_input_len = msgLen;
                    message.SetLength(0);
                    message.Write(enc_input, outLen, enc_input_len - outLen);
                    return outLen;
                }
            }
            return 0;
        }
#endif

        public int DoFinal(byte[] outBytes, int outOff)
        {
#if NETCOREAPP2_1_OR_GREATER || NETSTANDARD2_1_OR_GREATER
            return DoFinal(outBytes.AsSpan(outOff));
#else
            if (!initialised)
                throw new ArgumentException("Need call init function before encryption/decryption");

            byte[] aad = aadData.GetBuffer();
            byte[] msg = message.GetBuffer();

            int aadLen = Convert.ToInt32(aadData.Length);
            int msgLen = Convert.ToInt32(message.Length);
            int outLen;
            if (forEncryption)
            {
                outLen = msgLen + 16;
                Check.OutputLength(outBytes, outOff, outLen, "output buffer is too short");
                ISAPAEAD.isap_enc(msg, 0, msgLen, outBytes, outOff);
                outputStream.Write(outBytes, outOff, msgLen);
                outOff += msgLen;
                byte[] c = outputStream.GetBuffer();
                mac = new byte[16];
                ISAPAEAD.isap_mac(aad, aadLen, c, Convert.ToInt32(outputStream.Length), mac, 0);
                Array.Copy(mac, 0, outBytes, outOff, 16);
            }
            else
            {
                outLen = msgLen - 16;
                Check.OutputLength(outBytes, outOff, outLen, "output buffer is too short");
                mac = new byte[16];
                ISAPAEAD.isap_mac(aad, aadLen, msg, outLen, mac, 0);
                ISAPAEAD.reset();
                if (!Arrays.FixedTimeEquals(16, mac, 0, msg, outLen))
                    throw new ArgumentException("Mac does not match");
                ISAPAEAD.isap_enc(msg, 0, outLen, outBytes, outOff);
            }
            return outLen;
#endif
        }

#if NETCOREAPP2_1_OR_GREATER || NETSTANDARD2_1_OR_GREATER
        public int DoFinal(Span<byte> output)
        {
            if (!initialised)
                throw new ArgumentException("Need call init function before encryption/decryption");

            byte[] aad = aadData.GetBuffer();
            byte[] msg = message.GetBuffer();

            int aadLen = Convert.ToInt32(aadData.Length);
            int msgLen = Convert.ToInt32(message.Length);
            int outLen;
            if (forEncryption)
            {
                outLen = msgLen + 16;
                Check.OutputLength(output, outLen, "output buffer is too short");
                ISAPAEAD.isap_enc(msg.AsSpan(0, msgLen), output);
                outputStream.Write(output[..msgLen]);
                output = output[msgLen..];
                byte[] c = outputStream.GetBuffer();
                mac = new byte[16];
                ISAPAEAD.isap_mac(aad, aadLen, c, Convert.ToInt32(outputStream.Length), mac, 0);
                mac.CopyTo(output);
            }
            else
            {
                outLen = msgLen - 16;
                Check.OutputLength(output, outLen, "output buffer is too short");
                mac = new byte[16];
                ISAPAEAD.isap_mac(aad, aadLen, msg, outLen, mac, 0);
                ISAPAEAD.reset();
                if (!Arrays.FixedTimeEquals(16, mac, 0, msg, outLen))
                    throw new ArgumentException("Mac does not match");
                ISAPAEAD.isap_enc(msg.AsSpan(0, outLen), output);
            }
            return outLen;
        }
#endif

        public byte[] GetMac()
        {
            return mac;
        }

        public int GetUpdateOutputSize(int len)
        {
            if (!forEncryption)
                return 0;

            int totalData = Convert.ToInt32(message.Length + len);
            return totalData - totalData % ISAP_rH_SZ;
        }

        public int GetOutputSize(int len)
        {
            int totalData = Convert.ToInt32(message.Length + len);

            if (forEncryption)
                return totalData + 16;

            return System.Math.Max(0, totalData - 16);
        }

        public void Reset()
        {
            if (!initialised)
                throw new ArgumentException("Need call init function before encryption/decryption");

            aadData.SetLength(0);
            ISAPAEAD.reset();
            message.SetLength(0);
            outputStream.SetLength(0);
        }
    }
}
