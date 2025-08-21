using System;
#if NETSTANDARD1_0_OR_GREATER || NETCOREAPP1_0_OR_GREATER
using System.Runtime.CompilerServices;
#endif

using Org.BouncyCastle.Crypto.Utilities;
using Org.BouncyCastle.Utilities;

namespace Org.BouncyCastle.Crypto.Digests
{
    /// <summary>Ascon-CXOF128, from NIST Special Publication (SP) 800-232.</summary>
    /// <remarks>
    /// Additional details and the specification can be found in:
    /// <a href="https://csrc.nist.gov/pubs/sp/800/232/final">NIST SP 800-232</a>.
    /// For reference source code and implementation details, please see:
    /// <a href="https://github.com/ascon/ascon-c">Reference, highly optimized, masked C and
    /// ASM implementations of Ascon (NIST SP 800-232)</a>.
    /// </remarks>
    public sealed class AsconCXof128
        : IXof
    {
        private const int Rate = 8;

        private readonly byte[] m_buf = new byte[8];
        private readonly ulong Z0, Z1, Z2, Z3, Z4;

        private ulong S0, S1, S2, S3, S4;
        private int m_bufPos = 0;
        private bool m_squeezing = false;

        public AsconCXof128()
            : this(Array.Empty<byte>())
        {
        }

        public AsconCXof128(byte[] z)
            : this(z, 0, z.Length)
        {
        }

        public AsconCXof128(byte[] z, int zOff, int zLen)
        {
            Arrays.ValidateSegment(z, zOff, zLen);

            if (zLen > 256)
                throw new ArgumentOutOfRangeException(nameof(zLen), "customization string too long");

            InitState(z, zOff, zLen);

            // NOTE: Cache the initialized state
            Z0 = S0;
            Z1 = S1;
            Z2 = S2;
            Z3 = S3;
            Z4 = S4;
        }

        public string AlgorithmName => "Ascon-CXOF128";

        public int GetDigestSize() => 32;

        public int GetByteLength() => Rate;

        public void Update(byte input)
        {
            if (m_squeezing)
                throw new InvalidOperationException("attempt to absorb while squeezing");

            m_buf[m_bufPos] = input;
            if (++m_bufPos == Rate)
            {
                S0 ^= Pack.LE_To_UInt64(m_buf, 0);
                m_bufPos = 0;
                P12();
            }
        }

        public void BlockUpdate(byte[] input, int inOff, int inLen)
        {
            Check.DataLength(input, inOff, inLen, "input buffer too short");

#if NETCOREAPP2_1_OR_GREATER || NETSTANDARD2_1_OR_GREATER
            BlockUpdate(input.AsSpan(inOff, inLen));
#else
            if (m_squeezing)
                throw new InvalidOperationException("attempt to absorb while squeezing");

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
                S0 ^= Pack.LE_To_UInt64(m_buf, 0);
                inPos = available;
                //m_bufPos = Rate;
                P12();
            }

            int remaining;
            while ((remaining = inLen - inPos) >= Rate)
            {
                S0 ^= Pack.LE_To_UInt64(input, inOff + inPos);
                inPos += Rate;
                P12();
            }

            Array.Copy(input, inOff + inPos, m_buf, 0, remaining);
            m_bufPos = remaining;
#endif
        }

#if NETCOREAPP2_1_OR_GREATER || NETSTANDARD2_1_OR_GREATER
        public void BlockUpdate(ReadOnlySpan<byte> input)
        {
            if (m_squeezing)
                throw new InvalidOperationException("attempt to absorb while squeezing");

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
                input = input[available..];
                //m_bufPos = Rate;
                P12();
            }

            while (input.Length >= Rate)
            {
                S0 ^= Pack.LE_To_UInt64(input);
                input = input[Rate..];
                P12();
            }

            input.CopyTo(m_buf);
            m_bufPos = input.Length;
        }
#endif

        public int DoFinal(byte[] output, int outOff)
        {
            return OutputFinal(output, outOff, GetDigestSize());
        }

#if NETCOREAPP2_1_OR_GREATER || NETSTANDARD2_1_OR_GREATER
        public int DoFinal(Span<byte> output)
        {
            int digestSize = GetDigestSize();

            Check.OutputLength(output, digestSize, "output buffer is too short");

            return OutputFinal(output[..digestSize]);
        }
#endif

        public void Reset()
        {
            S0 = Z0;
            S1 = Z1;
            S2 = Z2;
            S3 = Z3;
            S4 = Z4;

            Array.Clear(m_buf, 0, m_buf.Length);
            m_bufPos = 0;
            m_squeezing = false;
        }

        public int OutputFinal(byte[] output, int outOff, int outLen)
        {
            Check.OutputLength(output, outOff, outLen, "output buffer is too short");

#if NETCOREAPP2_1_OR_GREATER || NETSTANDARD2_1_OR_GREATER
            return OutputFinal(output.AsSpan(outOff, outLen));
#else
            int length = Output(output, outOff, outLen);

            Reset();

            return length;
#endif
        }

#if NETCOREAPP2_1_OR_GREATER || NETSTANDARD2_1_OR_GREATER
        public int OutputFinal(Span<byte> output)
        {
            int length = Output(output);

            Reset();

            return length;
        }
#endif

        public int Output(byte[] output, int outOff, int outLen)
        {
            Check.OutputLength(output, outOff, outLen, "output buffer is too short");

#if NETCOREAPP2_0_OR_GREATER || NETSTANDARD2_1_OR_GREATER
            return Output(output.AsSpan(outOff, outLen));
#else
            int result = outLen;

            if (!m_squeezing)
            {
                PadAndAbsorb();
                m_squeezing = true;
                m_bufPos = 8;
            }
            else if (m_bufPos < 8)
            {
                int available = 8 - m_bufPos;
                if (outLen <= available)
                {
                    Array.Copy(m_buf, m_bufPos, output, outOff, outLen);
                    m_bufPos += outLen;
                    return result;
                }

                Array.Copy(m_buf, m_bufPos, output, outOff, available);
                outOff += available;
                outLen -= available;
                m_bufPos = 8;
            }

            while (outLen >= 8)
            {
                P12();
                Pack.UInt64_To_LE(S0, output, outOff);
                outOff += 8;
                outLen -= 8;
            }

            if (outLen > 0)
            {
                P12();
                Pack.UInt64_To_LE(S0, m_buf);
                Array.Copy(m_buf, 0, output, outOff, outLen);
                m_bufPos = outLen;
            }

            return result;
#endif
        }

#if NETCOREAPP2_0_OR_GREATER || NETSTANDARD2_1_OR_GREATER
        public int Output(Span<byte> output)
        {
            int result = output.Length;

            if (!m_squeezing)
            {
                PadAndAbsorb();
                m_squeezing = true;
                m_bufPos = 8;
            }
            else if (m_bufPos < 8)
            {
                int available = 8 - m_bufPos;
                if (output.Length <= available)
                {
                    output.CopyFrom(m_buf.AsSpan(m_bufPos));
                    m_bufPos += output.Length;
                    return result;
                }

                output[..available].CopyFrom(m_buf.AsSpan(m_bufPos));
                output = output[available..];
                m_bufPos = 8;
            }

            while (output.Length >= 8)
            {
                P12();
                Pack.UInt64_To_LE(S0, output);
                output = output[8..];
            }

            if (!output.IsEmpty)
            {
                P12();
                Pack.UInt64_To_LE(S0, m_buf);
                output.CopyFrom(m_buf);
                m_bufPos = output.Length;
            }

            return result;
        }
#endif

        private void InitState(byte[] z, int zOff, int zLen)
        {
            //S0 = 0x0000080000cc0004UL;
            //S1 = 0UL;
            //S2 = 0UL;
            //S3 = 0UL;
            //S4 = 0UL;
            //P12();

            if (zLen == 0)
            {
                //P12();
                //PadAndAbsorb();
                //P12();

                S0 = 0x500cccc894e3c9e8UL;
                S1 = 0x5bed06f28f71248dUL;
                S2 = 0x3b03a0f930afd512UL;
                S3 = 0x112ef093aa5c698bUL;
                S4 = 0x00c8356340a347f0UL;
            }
            else
            {
                S0 = 0x675527c2a0e8de03UL;
                S1 = 0x43d12d7dc0377bbcUL;
                S2 = 0xe9901dec426e81b5UL;
                S3 = 0x2ab14907720780b6UL;
                S4 = 0x8f3f1d02d432bc46UL;

                ulong bitLength = Convert.ToUInt64(zLen) << 3;
                S0 ^= bitLength;
                P12();
                BlockUpdate(z, zOff, zLen);
                PadAndAbsorb();
                P12();
            }

            m_bufPos = 0;
        }

        private void PadAndAbsorb()
        {
            int finalBits = m_bufPos << 3;
            S0 ^= Pack.LE_To_UInt64(m_buf, 0) & (0x00FFFFFFFFFFFFFFUL >> (56 - finalBits));
            S0 ^= 0x01UL << finalBits;
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
