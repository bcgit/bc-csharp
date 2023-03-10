using System;
using System.IO;

using Org.BouncyCastle.Crypto.Utilities;
using Org.BouncyCastle.Utilities;

namespace Org.BouncyCastle.Crypto.Digests
{
    public sealed class XoodyakDigest
        : IDigest
    {
        private enum MODE
        {
            ModeHash,
            ModeKeyed
        }

        private const int Rkin = 44;

        private static readonly uint[] RC = { 0x00000058U, 0x00000038U, 0x000003C0U, 0x000000D0U, 0x00000120U,
            0x00000014U, 0x00000060U, 0x0000002CU, 0x00000380U, 0x000000F0U, 0x000001A0U, 0x00000012U };

        private byte[] state;
        private int phase;
        private MODE mode;
        private int Rabsorb;
        private const int f_bPrime = 48;
        private const int Rkout = 24;
        private const int PhaseDown = 1;
        private const int PhaseUp = 2;
        private const int NLANES = 12;
        private const int NROWS = 3;
        private const int NCOLUMNS = 4;
        private const int MAXROUNDS = 12;
        private const int TAGLEN = 16;
        private const int Rhash = 16;
        private readonly MemoryStream buffer = new MemoryStream();

        public XoodyakDigest()
        {
            state = new byte[48];
            Reset();
        }

        public string AlgorithmName => "Xoodyak Hash";

        public int GetDigestSize() => 32;

        public int GetByteLength() => Rabsorb;

        public void Update(byte input)
        {
            buffer.WriteByte(input);
        }

        public void BlockUpdate(byte[] input, int inOff, int inLen)
        {
            Check.DataLength(input, inOff, inLen, "input buffer too short");

            buffer.Write(input, inOff, inLen);
        }

#if NETCOREAPP2_1_OR_GREATER || NETSTANDARD2_1_OR_GREATER
        public void BlockUpdate(ReadOnlySpan<byte> input)
        {
            buffer.Write(input);
        }
#endif

        public int DoFinal(byte[] output, int outOff)
        {
            Check.OutputLength(output, outOff, 32, "output buffer is too short");

            byte[] input = buffer.GetBuffer();
            int inLen = (int)buffer.Length;
            int inOff = 0;
            uint Cd = 0x03;
            int splitLen;
            do
            {
                if (phase != PhaseUp)
                {
                    Up(null, 0, 0, 0);
                }
                splitLen = System.Math.Min(inLen, Rabsorb);
                Down(input, inOff, splitLen, Cd);
                Cd = 0;
                inOff += splitLen;
                inLen -= splitLen;
            }
            while (inLen != 0);
            Up(output, outOff, TAGLEN, 0x40);
            Down(null, 0, 0, 0);
            Up(output, outOff + TAGLEN, TAGLEN, 0);
            return 32;

            // TODO Reset?
        }

#if NETCOREAPP2_1_OR_GREATER || NETSTANDARD2_1_OR_GREATER
        public int DoFinal(Span<byte> output)
        {
            byte[] rv = new byte[32];
            int rlt = DoFinal(rv, 0);
            rv.AsSpan(0, 32).CopyTo(output);
            return rlt;
        }
#endif

        public void Reset()
        {
            Array.Clear(state, 0, state.Length);
            phase = PhaseUp;
            mode = MODE.ModeHash;
            Rabsorb = Rhash;
            buffer.SetLength(0);
        }

        private void Up(byte[] Yi, int YiOff, int YiLen, uint Cu)
        {
            if (mode != MODE.ModeHash)
            {
                state[f_bPrime - 1] ^= (byte)Cu;
            }
            uint[] a = new uint[NLANES];
            Pack.LE_To_UInt32(state, 0, a, 0, a.Length);
            uint x, y;
            uint[] b = new uint[NLANES];
            uint[] p = new uint[NCOLUMNS];
            uint[] e = new uint[NCOLUMNS];
            for (int i = 0; i < MAXROUNDS; ++i)
            {
                /* Theta: Column Parity Mixer */
                for (x = 0; x < NCOLUMNS; ++x)
                {
                    p[x] = a[index(x, 0)] ^ a[index(x, 1)] ^ a[index(x, 2)];
                }
                for (x = 0; x < NCOLUMNS; ++x)
                {
                    y = p[(x + 3) & 3];
                    e[x] = Integers.RotateLeft(y, 5) ^ Integers.RotateLeft(y, 14);
                }
                for (x = 0; x < NCOLUMNS; ++x)
                {
                    for (y = 0; y < NROWS; ++y)
                    {
                        a[index(x, y)] ^= e[x];
                    }
                }
                /* Rho-west: plane shift */
                for (x = 0; x < NCOLUMNS; ++x)
                {
                    b[index(x, 0)] = a[index(x, 0)];
                    b[index(x, 1)] = a[index(x + 3, 1)];
                    b[index(x, 2)] = Integers.RotateLeft(a[index(x, 2)], 11);
                }
                /* Iota: round ant */
                b[0] ^= RC[i];
                /* Chi: non linear layer */
                for (x = 0; x < NCOLUMNS; ++x)
                {
                    for (y = 0; y < NROWS; ++y)
                    {
                        a[index(x, y)] = b[index(x, y)] ^ (~b[index(x, y + 1)] & b[index(x, y + 2)]);
                    }
                }
                /* Rho-east: plane shift */
                for (x = 0; x < NCOLUMNS; ++x)
                {
                    b[index(x, 0)] = a[index(x, 0)];
                    b[index(x, 1)] = Integers.RotateLeft(a[index(x, 1)], 1);
                    b[index(x, 2)] = Integers.RotateLeft(a[index(x + 2, 2)], 8);
                }
                Array.Copy(b, 0, a, 0, NLANES);
            }
            Pack.UInt32_To_LE(a, 0, a.Length, state, 0);
            phase = PhaseUp;
            if (Yi != null)
            {
                Array.Copy(state, 0, Yi, YiOff, YiLen);
            }
        }

        void Down(byte[] Xi, int XiOff, int XiLen, uint Cd)
        {
            for (int i = 0; i < XiLen; i++)
            {
                state[i] ^= Xi[XiOff++];
            }
            state[XiLen] ^= 0x01;
            state[f_bPrime - 1] ^= (byte)((mode == MODE.ModeHash) ? (Cd & 0x01) : Cd);
            phase = PhaseDown;
        }

        private uint index(uint x, uint y)
        {
            return (((y % NROWS) * NCOLUMNS) + ((x) % NCOLUMNS));
        }
    }
}
