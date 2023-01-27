using System;
using System.IO;
using Org.BouncyCastle.Crypto.Utilities;

namespace Org.BouncyCastle.Crypto.Digests
{
    public class XoodyakDigest : IDigest
    {
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
        private const int NCOLUMS = 4;
        private const int MAXROUNDS = 12;
        private const int TAGLEN = 16;
        private const int Rhash = 16;
        const int Rkin = 44;
        private readonly uint[] RC = {0x00000058, 0x00000038, 0x000003C0, 0x000000D0, 0x00000120, 0x00000014, 0x00000060,
        0x0000002C, 0x00000380, 0x000000F0, 0x000001A0, 0x00000012};
        private MemoryStream buffer = new MemoryStream();
        enum MODE
        {
            ModeHash,
            ModeKeyed
        }

        public XoodyakDigest()
        {
            state = new byte[48];
            Reset();
        }

        public string AlgorithmName => "Xoodyak Hash";

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
            uint[] p = new uint[NCOLUMS];
            uint[] e = new uint[NCOLUMS];
            for (int i = 0; i < MAXROUNDS; ++i)
            {
                /* Theta: Column Parity Mixer */
                for (x = 0; x < NCOLUMS; ++x)
                {
                    p[x] = a[index(x, 0)] ^ a[index(x, 1)] ^ a[index(x, 2)];
                }
                for (x = 0; x < NCOLUMS; ++x)
                {
                    y = p[(x + 3) & 3];
                    e[x] = ROTL32(y, 5) ^ ROTL32(y, 14);
                }
                for (x = 0; x < NCOLUMS; ++x)
                {
                    for (y = 0; y < NROWS; ++y)
                    {
                        a[index(x, y)] ^= e[x];
                    }
                }
                /* Rho-west: plane shift */
                for (x = 0; x < NCOLUMS; ++x)
                {
                    b[index(x, 0)] = a[index(x, 0)];
                    b[index(x, 1)] = a[index(x + 3, 1)];
                    b[index(x, 2)] = ROTL32(a[index(x, 2)], 11);
                }
                /* Iota: round ant */
                b[0] ^= RC[i];
                /* Chi: non linear layer */
                for (x = 0; x < NCOLUMS; ++x)
                {
                    for (y = 0; y < NROWS; ++y)
                    {
                        a[index(x, y)] = b[index(x, y)] ^ (~b[index(x, y + 1)] & b[index(x, y + 2)]);
                    }
                }
                /* Rho-east: plane shift */
                for (x = 0; x < NCOLUMS; ++x)
                {
                    b[index(x, 0)] = a[index(x, 0)];
                    b[index(x, 1)] = ROTL32(a[index(x, 1)], 1);
                    b[index(x, 2)] = ROTL32(a[index(x + 2, 2)], 8);
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
            return (((y % NROWS) * NCOLUMS) + ((x) % NCOLUMS));
        }

        private uint ROTL32(uint a, int offset)
        {
            return (a << (offset & 31)) ^ (a >> ((32 - (offset)) & 31));
        }

        public void BlockUpdate(byte[] input, int inOff, int inLen)
        {
            if (inOff + inLen > input.Length)
            {
                throw new DataLengthException("input buffer too short");
            }
            buffer.Write(input, inOff, inLen);
        }

        public int DoFinal(byte[] output, int outOff)
        {
            if (32 + outOff > output.Length)
            {
                throw new OutputLengthException("output buffer is too short");
            }
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
        }

        public int GetByteLength()
        {
            throw new NotImplementedException();
        }

        public int GetDigestSize()
        {
            return 32;
        }

        public void Reset()
        {
            for (int i = 0; i < state.Length; ++i)
            {
                state[i] = 0;
            }
            phase = PhaseUp;
            mode = MODE.ModeHash;
            Rabsorb = Rhash;
            buffer.SetLength(0);
        }

        public void Update(byte input)
        {
            buffer.Write(new byte[] { input }, 0, 1);
        }
#if NETCOREAPP2_1_OR_GREATER || NETSTANDARD2_1_OR_GREATER
        public int DoFinal(Span<byte> output)
        {
            byte[] rv = new byte[32];
            int rlt = DoFinal(rv, 0);
            rv.AsSpan(0, 32).CopyTo(output);
            return rlt;
        }

        public void BlockUpdate(ReadOnlySpan<byte> input)
        {
            buffer.Write(input.ToArray(), 0, input.Length);
        }
#endif
    }
}
