using System;

using Org.BouncyCastle.Crypto.Utilities;
using Org.BouncyCastle.Utilities;

namespace Org.BouncyCastle.Crypto.Digests
{
    public sealed class XoodyakDigest
        : IDigest
    {
        private static readonly uint[] RC = { 0x00000058U, 0x00000038U, 0x000003C0U, 0x000000D0U, 0x00000120U,
            0x00000014U, 0x00000060U, 0x0000002CU, 0x00000380U, 0x000000F0U, 0x000001A0U, 0x00000012U };

        private const int f_bPrime = 48;
        private const int MAXROUNDS = 12;
        private const int TAGLEN = 16;
        private const int Rabsorb = 16;

        private readonly byte[] m_state = new byte[48];
        private readonly byte[] m_buf = new byte[Rabsorb];
        private int m_bufPos = 0;
        private bool m_updated = false;

        public XoodyakDigest()
        {
            Reset();
        }

        public string AlgorithmName => "Xoodyak Hash";

        public int GetDigestSize() => 32;

        public int GetByteLength() => Rabsorb;

        public void Update(byte input)
        {
            m_buf[m_bufPos] = input;
            if (++m_bufPos == Rabsorb)
            {
#if NETCOREAPP2_1_OR_GREATER || NETSTANDARD2_1_OR_GREATER
                Down(m_buf);
#else
                Down(m_buf, 0, Rabsorb);
#endif
                Up();
                m_updated = true;
                m_bufPos = 0;
            }
        }

        public void BlockUpdate(byte[] input, int inOff, int inLen)
        {
            Check.DataLength(input, inOff, inLen, "input buffer too short");

#if NETCOREAPP2_1_OR_GREATER || NETSTANDARD2_1_OR_GREATER
            BlockUpdate(input.AsSpan(inOff, inLen));
#else
            if (inLen < 1)
                return;

            int available = Rabsorb - m_bufPos;
            if (inLen < available)
            {
                Array.Copy(input, inOff, m_buf, m_bufPos, inLen);
                m_bufPos += inLen;
                return;
            }

            int inPos = 0;
            if (m_bufPos > 0)
            {
                Array.Copy(input, inOff, m_buf, m_bufPos, available);
                inPos += available;

                Down(m_buf, 0, Rabsorb);
                Up();
                m_updated = true;
            }

            int remaining;
            while ((remaining = inLen - inPos) >= Rabsorb)
            {
                Down(input, inOff + inPos, Rabsorb);
                Up();
                m_updated = true;

                inPos += Rabsorb;
            }

            Array.Copy(input, inOff + inPos, m_buf, 0, remaining);
            m_bufPos = remaining;
#endif
        }

#if NETCOREAPP2_1_OR_GREATER || NETSTANDARD2_1_OR_GREATER
        public void BlockUpdate(ReadOnlySpan<byte> input)
        {
            int available = Rabsorb - m_bufPos;
            if (input.Length < available)
            {
                input.CopyTo(m_buf.AsSpan(m_bufPos));
                m_bufPos += input.Length;
                return;
            }

            if (m_bufPos > 0)
            {
                input[..available].CopyTo(m_buf.AsSpan(m_bufPos));
                input = input[available..];

                Down(m_buf);
                Up();
                m_updated = true;
            }

            while (input.Length >= Rabsorb)
            {
                Down(input[..Rabsorb]);
                Up();
                m_updated = true;

                input = input[Rabsorb..];
            }

            input.CopyTo(m_buf);
            m_bufPos = input.Length;
        }
#endif

        public int DoFinal(byte[] output, int outOff)
        {
#if NETCOREAPP2_1_OR_GREATER || NETSTANDARD2_1_OR_GREATER
            return DoFinal(output.AsSpan(outOff));
#else
            Check.OutputLength(output, outOff, 32, "output buffer too short");

            if (m_bufPos > 0 || !m_updated)
            {
                Down(m_buf, 0, m_bufPos);
                Up();
            }

            Array.Copy(m_state, 0, output, outOff, TAGLEN);

            m_state[0] ^= 0x01;
            Up();

            Array.Copy(m_state, 0, output, outOff + TAGLEN, TAGLEN);

            Reset();
            return 32;
#endif
        }

#if NETCOREAPP2_1_OR_GREATER || NETSTANDARD2_1_OR_GREATER
        public int DoFinal(Span<byte> output)
        {
            Check.OutputLength(output, 32, "output buffer too short");

            if (m_bufPos > 0 || !m_updated)
            {
                Down(m_buf.AsSpan(0, m_bufPos));
                Up();
            }

            m_state.AsSpan(0, TAGLEN).CopyTo(output);

            m_state[0] ^= 0x01;
            Up();

            m_state.AsSpan(0, TAGLEN).CopyTo(output[TAGLEN..]);

            Reset();
            return 32;
        }
#endif

        public void Reset()
        {
            Arrays.Fill(m_state, 0);
            Arrays.Fill(m_buf, 0);
            m_bufPos = 0;
            m_updated = false;

            m_state[f_bPrime - 1] ^= 0x01;
        }

        private void Up()
        {
            uint a0 = Pack.LE_To_UInt32(m_state, 0);
            uint a1 = Pack.LE_To_UInt32(m_state, 4);
            uint a2 = Pack.LE_To_UInt32(m_state, 8);
            uint a3 = Pack.LE_To_UInt32(m_state, 12);
            uint a4 = Pack.LE_To_UInt32(m_state, 16);
            uint a5 = Pack.LE_To_UInt32(m_state, 20);
            uint a6 = Pack.LE_To_UInt32(m_state, 24);
            uint a7 = Pack.LE_To_UInt32(m_state, 28);
            uint a8 = Pack.LE_To_UInt32(m_state, 32);
            uint a9 = Pack.LE_To_UInt32(m_state, 36);
            uint a10 = Pack.LE_To_UInt32(m_state, 40);
            uint a11 = Pack.LE_To_UInt32(m_state, 44);

            for (int i = 0; i < MAXROUNDS; ++i)
            {
                /* Theta: Column Parity Mixer */
                uint p0 = a0 ^ a4 ^ a8;
                uint p1 = a1 ^ a5 ^ a9;
                uint p2 = a2 ^ a6 ^ a10;
                uint p3 = a3 ^ a7 ^ a11;

                uint e0 = Integers.RotateLeft(p3, 5) ^ Integers.RotateLeft(p3, 14);
                uint e1 = Integers.RotateLeft(p0, 5) ^ Integers.RotateLeft(p0, 14);
                uint e2 = Integers.RotateLeft(p1, 5) ^ Integers.RotateLeft(p1, 14);
                uint e3 = Integers.RotateLeft(p2, 5) ^ Integers.RotateLeft(p2, 14);

                a0 ^= e0;
                a4 ^= e0;
                a8 ^= e0;

                a1 ^= e1;
                a5 ^= e1;
                a9 ^= e1;

                a2 ^= e2;
                a6 ^= e2;
                a10 ^= e2;

                a3 ^= e3;
                a7 ^= e3;
                a11 ^= e3;

                /* Rho-west: plane shift */
                uint b0 = a0;
                uint b1 = a1;
                uint b2 = a2;
                uint b3 = a3;

                uint b4 = a7;
                uint b5 = a4;
                uint b6 = a5;
                uint b7 = a6;

                uint b8 = Integers.RotateLeft(a8, 11);
                uint b9 = Integers.RotateLeft(a9, 11);
                uint b10 = Integers.RotateLeft(a10, 11);
                uint b11 = Integers.RotateLeft(a11, 11);

                /* Iota: round ant */
                b0 ^= RC[i];

                /* Chi: non linear layer */
                a0 = b0 ^ (~b4 & b8);
                a1 = b1 ^ (~b5 & b9);
                a2 = b2 ^ (~b6 & b10);
                a3 = b3 ^ (~b7 & b11);

                a4 = b4 ^ (~b8 & b0);
                a5 = b5 ^ (~b9 & b1);
                a6 = b6 ^ (~b10 & b2);
                a7 = b7 ^ (~b11 & b3);

                b8 ^= (~b0 & b4);
                b9 ^= (~b1 & b5);
                b10 ^= (~b2 & b6);
                b11 ^= (~b3 & b7);

                /* Rho-east: plane shift */
                a4 = Integers.RotateLeft(a4, 1);
                a5 = Integers.RotateLeft(a5, 1);
                a6 = Integers.RotateLeft(a6, 1);
                a7 = Integers.RotateLeft(a7, 1);

                a8 = Integers.RotateLeft(b10, 8);
                a9 = Integers.RotateLeft(b11, 8);
                a10 = Integers.RotateLeft(b8, 8);
                a11 = Integers.RotateLeft(b9, 8);
            }

            Pack.UInt32_To_LE(a0, m_state, 0);
            Pack.UInt32_To_LE(a1, m_state, 4);
            Pack.UInt32_To_LE(a2, m_state, 8);
            Pack.UInt32_To_LE(a3, m_state, 12);
            Pack.UInt32_To_LE(a4, m_state, 16);
            Pack.UInt32_To_LE(a5, m_state, 20);
            Pack.UInt32_To_LE(a6, m_state, 24);
            Pack.UInt32_To_LE(a7, m_state, 28);
            Pack.UInt32_To_LE(a8, m_state, 32);
            Pack.UInt32_To_LE(a9, m_state, 36);
            Pack.UInt32_To_LE(a10, m_state, 40);
            Pack.UInt32_To_LE(a11, m_state, 44);
        }

#if NETCOREAPP2_1_OR_GREATER || NETSTANDARD2_1_OR_GREATER
        private void Down(ReadOnlySpan<byte> X)
        {
            for (int i = 0; i < X.Length; i++)
            {
                m_state[i] ^= X[i];
            }
            m_state[X.Length] ^= 0x01;
        }
#else
        private void Down(byte[] Xi, int XiOff, int XiLen)
        {
            for (int i = 0; i < XiLen; i++)
            {
                m_state[i] ^= Xi[XiOff++];
            }
            m_state[XiLen] ^= 0x01;
        }
#endif
    }
}
