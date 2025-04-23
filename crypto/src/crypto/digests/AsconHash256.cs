using System;
#if NETSTANDARD1_0_OR_GREATER || NETCOREAPP1_0_OR_GREATER
using System.Runtime.CompilerServices;
#endif

using Org.BouncyCastle.Crypto.Utilities;
using Org.BouncyCastle.Utilities;

namespace Org.BouncyCastle.Crypto.Digests
{
    /// <summary>
    /// Ascon-Hash256 was introduced in NIST Special Publication (SP) 800-232 (Initial Public Draft).
    /// </summary>
    /// <remarks>
    /// Additional details and the specification can be found in:
    /// <a href="https://csrc.nist.gov/pubs/sp/800/232/ipd">NIST SP 800-232 (Initial Public Draft)</a>.
    /// For reference source code and implementation details, please see:
    /// <a href="https://github.com/ascon/ascon-c">Reference, highly optimized, masked C and
    /// ASM implementations of Ascon (NIST SP 800-232)</a>.
    /// </remarks>
    public sealed class AsconHash256
        : IDigest
    {
        private const int Rate = 8;

        private readonly byte[] m_buf = new byte[8];

        private ulong S0, S1, S2, S3, S4;
        private int m_bufPos = 0;

        public AsconHash256()
        {
            Reset();
        }

        public string AlgorithmName => "Ascon-Hash256";

        public int GetDigestSize() => 32;

        public int GetByteLength() => Rate;

        public void Update(byte input)
        {
            m_buf[m_bufPos] = input;
            if (++m_bufPos == Rate)
            {
                S0 ^= Pack.LE_To_UInt64(m_buf, 0);
                P12();
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

            int available = Rate - m_bufPos;
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
                S0 ^= Pack.LE_To_UInt64(m_buf, 0);
                P12();
            }

            int remaining;
            while ((remaining = inLen - inPos) >= Rate)
            {
                S0 ^= Pack.LE_To_UInt64(input, inOff + inPos);
                P12();
                inPos += Rate;
            }

            Array.Copy(input, inOff + inPos, m_buf, 0, remaining);
            m_bufPos = remaining;
#endif
        }

#if NETCOREAPP2_1_OR_GREATER || NETSTANDARD2_1_OR_GREATER
        public void BlockUpdate(ReadOnlySpan<byte> input)
        {
            int available = Rate - m_bufPos;
            if (input.Length < available)
            {
                input.CopyTo(m_buf.AsSpan(m_bufPos));
                m_bufPos += input.Length;
                return;
            }

            if (m_bufPos > 0)
            {
                input[..available].CopyTo(m_buf.AsSpan(m_bufPos));
                S0 ^= Pack.LE_To_UInt64(m_buf);
                P12();
                input = input[available..];
            }

            while (input.Length >= Rate)
            {
                S0 ^= Pack.LE_To_UInt64(input);
                P12();
                input = input[Rate..];
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

            PadAndAbsorb();

            Pack.UInt64_To_LE(S0, output, outOff);

            for (int i = 0; i < 3; ++i)
            {
                outOff += 8;

                P12();
                Pack.UInt64_To_LE(S0, output, outOff);
            }

            Reset();
            return 32;
#endif
        }

#if NETCOREAPP2_1_OR_GREATER || NETSTANDARD2_1_OR_GREATER
        public int DoFinal(Span<byte> output)
        {
            Check.OutputLength(output, 32, "output buffer too short");

            PadAndAbsorb();

            Pack.UInt64_To_LE(S0, output);

            for (int i = 0; i < 3; ++i)
            {
                output = output[8..];

                P12();
                Pack.UInt64_To_LE(S0, output);
            }

            Reset();
            return 32;
        }
#endif

        public void Reset()
        {
            //S0 = 0x0000080100cc0002UL;
            //S1 = 0UL;
            //S2 = 0UL;
            //S3 = 0UL;
            //S4 = 0UL;
            //P12();

            S0 = 0x9b1e5494e934d681UL;
            S1 = 0x4bc3a01e333751d2UL;
            S2 = 0xae65396c6b34b81aUL;
            S3 = 0x3c7fd4a4d56a4db3UL;
            S4 = 0x1a5c464906c5976dUL;

            Array.Clear(m_buf, 0, m_buf.Length);
            m_bufPos = 0;
        }

        private void PadAndAbsorb()
        {
            int finalBits = m_bufPos << 3;
            S0 ^= Pack.LE_To_UInt64(m_buf, 0) & (0x00FFFFFFFFFFFFFFUL >> (56 - finalBits));
            S0 ^= 0x01UL << finalBits;

            P12();
        }

        private void P12()
        {
            Round(0xf0UL);
            Round(0xe1UL);
            Round(0xd2UL);
            Round(0xc3UL);
            Round(0xb4UL);
            Round(0xa5UL);
            Round(0x96UL);
            Round(0x87UL);
            Round(0x78UL);
            Round(0x69UL);
            Round(0x5aUL);
            Round(0x4bUL);
        }

#if NETSTANDARD1_0_OR_GREATER || NETCOREAPP1_0_OR_GREATER
        [MethodImpl(MethodImplOptions.AggressiveInlining)]
#endif
        private void Round(ulong c)
        {
            ulong SX = S2 ^ c;
            ulong t0 = S0 ^ S1 ^ SX ^ S3 ^ (S1 & (S0 ^ SX ^ S4));
            ulong t1 = S0 ^ SX ^ S3 ^ S4 ^ ((S1 ^ SX) & (S1 ^ S3));
            ulong t2 = S1 ^ SX ^ S4 ^ (S3 & S4);
            ulong t3 = S0 ^ S1 ^ SX ^ (~S0 & (S3 ^ S4));
            ulong t4 = S1 ^ S3 ^ S4 ^ ((S0 ^ S4) & S1);
            S0 = t0 ^ Longs.RotateRight(t0, 19) ^ Longs.RotateRight(t0, 28);
            S1 = t1 ^ Longs.RotateRight(t1, 39) ^ Longs.RotateRight(t1, 61);
            S2 = ~(t2 ^ Longs.RotateRight(t2, 1) ^ Longs.RotateRight(t2, 6));
            S3 = t3 ^ Longs.RotateRight(t3, 10) ^ Longs.RotateRight(t3, 17);
            S4 = t4 ^ Longs.RotateRight(t4, 7) ^ Longs.RotateRight(t4, 41);
        }
    }
}
