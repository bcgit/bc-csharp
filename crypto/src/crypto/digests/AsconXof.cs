using System;
#if NETSTANDARD1_0_OR_GREATER || NETCOREAPP1_0_OR_GREATER
using System.Runtime.CompilerServices;
#endif

using Org.BouncyCastle.Crypto.Utilities;
using Org.BouncyCastle.Utilities;

namespace Org.BouncyCastle.Crypto.Digests
{
    /// <summary>ASCON v1.2 XOF, https://ascon.iaik.tugraz.at/ .</summary>
    /// <remarks>
    /// https://csrc.nist.gov/CSRC/media/Projects/lightweight-cryptography/documents/finalist-round/updated-spec-doc/ascon-spec-final.pdf<br/>
    /// ASCON v1.2 XOF with reference to C Reference Impl from: https://github.com/ascon/ascon-c .
    /// </remarks>
    public sealed class AsconXof
        : IXof
    {
        public enum AsconParameters
        {
            AsconXof,
            AsconXofA,
        }

        private readonly AsconParameters m_asconParameters;
        private readonly int ASCON_PB_ROUNDS;

        private ulong x0;
        private ulong x1;
        private ulong x2;
        private ulong x3;
        private ulong x4;

        private readonly byte[] m_buf = new byte[8];
        private int m_bufPos = 0;
        private bool m_squeezing = false;

        public AsconXof(AsconParameters parameters)
        {
            m_asconParameters = parameters;
            switch (parameters)
            {
            case AsconParameters.AsconXof:
                ASCON_PB_ROUNDS = 12;
                break;
            case AsconParameters.AsconXofA:
                ASCON_PB_ROUNDS = 8;
                break;
            default:
                throw new ArgumentException("Invalid parameter settings for Ascon XOF");
            }
            Reset();
        }

        public string AlgorithmName
        {
            get
            {
                switch (m_asconParameters)
                {
                case AsconParameters.AsconXof:      return "Ascon-Xof";
                case AsconParameters.AsconXofA:     return "Ascon-XofA";
                default: throw new InvalidOperationException();
                }
            }
        }

        public int GetDigestSize() => 32;

        public int GetByteLength() => 8;

        public void Update(byte input)
        {
            if (m_squeezing)
                throw new InvalidOperationException("attempt to absorb while squeezing");

            m_buf[m_bufPos] = input;
            if (++m_bufPos == 8)
            {
                x0 ^= Pack.BE_To_UInt64(m_buf, 0);
                P(ASCON_PB_ROUNDS);
                m_bufPos = 0;
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

            int available = 8 - m_bufPos;
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
                x0 ^= Pack.BE_To_UInt64(m_buf, 0);
                P(ASCON_PB_ROUNDS);
            }

            int remaining;
            while ((remaining = inLen - inPos) >= 8)
            {
                x0 ^= Pack.BE_To_UInt64(input, inOff + inPos);
                P(ASCON_PB_ROUNDS);
                inPos += 8;
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

            int available = 8 - m_bufPos;
            if (input.Length < available)
            {
                input.CopyTo(m_buf.AsSpan(m_bufPos));
                m_bufPos += input.Length;
                return;
            }

            if (m_bufPos > 0)
            {
                input[..available].CopyTo(m_buf.AsSpan(m_bufPos));
                x0 ^= Pack.BE_To_UInt64(m_buf);
                P(ASCON_PB_ROUNDS);
                input = input[available..];
            }

            while (input.Length >= 8)
            {
                x0 ^= Pack.BE_To_UInt64(input);
                P(ASCON_PB_ROUNDS);
                input = input[8..];
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

#if NETCOREAPP2_1_OR_GREATER || NETSTANDARD2_1_OR_GREATER
            return Output(output.AsSpan(outOff, outLen));
#else
            int result = outLen;

            if (!m_squeezing)
            {
                FinishAbsorbing();

                if (outLen >= 8)
                {
                    Pack.UInt64_To_BE(x0, output, outOff);
                    outOff += 8;
                    outLen -= 8;
                }
                else
                {
                    Pack.UInt64_To_BE(x0, m_buf);
                    m_bufPos = 0;
                }
            }

            if (m_bufPos < 8)
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
                //m_bufPos = 8;
            }

            while (outLen >= 8)
            {
                P(ASCON_PB_ROUNDS);
                Pack.UInt64_To_BE(x0, output, outOff);
                outOff += 8;
                outLen -= 8;
            }

            if (outLen > 0)
            {
                P(ASCON_PB_ROUNDS);
                Pack.UInt64_To_BE(x0, m_buf);
                Array.Copy(m_buf, 0, output, outOff, outLen);
            }

            m_bufPos = outLen;
            return result;
#endif
        }

#if NETCOREAPP2_1_OR_GREATER || NETSTANDARD2_1_OR_GREATER
        public int Output(Span<byte> output)
        {
            int result = output.Length;

            if (!m_squeezing)
            {
                FinishAbsorbing();

                if (output.Length >= 8)
                {
                    Pack.UInt64_To_BE(x0, output);
                    output = output[8..];
                }
                else
                {
                    Pack.UInt64_To_BE(x0, m_buf);
                    m_bufPos = 0;
                }
            }

            if (m_bufPos < 8)
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
                //m_bufPos = 8;
            }

            while (output.Length >= 8)
            {
                P(ASCON_PB_ROUNDS);
                Pack.UInt64_To_BE(x0, output);
                output = output[8..];
            }

            if (!output.IsEmpty)
            {
                P(ASCON_PB_ROUNDS);
                Pack.UInt64_To_BE(x0, m_buf);
                output.CopyFrom(m_buf);
            }

            m_bufPos = output.Length;
            return result;
        }
#endif

        public void Reset()
        {
            Array.Clear(m_buf, 0, m_buf.Length);
            m_bufPos = 0;
            m_squeezing = false;

            switch (m_asconParameters)
            {
            case AsconParameters.AsconXof:
                x0 = 13077933504456348694UL;
                x1 = 3121280575360345120UL;
                x2 = 7395939140700676632UL;
                x3 = 6533890155656471820UL;
                x4 = 5710016986865767350UL;
                break;
            case AsconParameters.AsconXofA:
                x0 = 4940560291654768690UL;
                x1 = 14811614245468591410UL;
                x2 = 17849209150987444521UL;
                x3 = 2623493988082852443UL;
                x4 = 12162917349548726079UL;
                break;
            default:
                throw new InvalidOperationException();
            }
        }

        private void FinishAbsorbing()
        {
            m_buf[m_bufPos] = 0x80;
            x0 ^= Pack.BE_To_UInt64(m_buf, 0) & (ulong.MaxValue << (56 - (m_bufPos << 3)));

            P(12);

            m_bufPos = 8;
            m_squeezing = true;
        }

        private void P(int nr)
        {
            //if (nr >= 8)
            {
                if (nr == 12)
                {
                    ROUND(0xf0UL);
                    ROUND(0xe1UL);
                    ROUND(0xd2UL);
                    ROUND(0xc3UL);
                }
                ROUND(0xb4UL);
                ROUND(0xa5UL);
            }
            ROUND(0x96UL);
            ROUND(0x87UL);
            ROUND(0x78UL);
            ROUND(0x69UL);
            ROUND(0x5aUL);
            ROUND(0x4bUL);
        }

#if NETSTANDARD1_0_OR_GREATER || NETCOREAPP1_0_OR_GREATER
        [MethodImpl(MethodImplOptions.AggressiveInlining)]
#endif
        private void ROUND(ulong c)
        {
            ulong t0 = x0 ^ x1 ^ x2 ^ x3 ^ c ^ (x1 & (x0 ^ x2 ^ x4 ^ c));
            ulong t1 = x0 ^ x2 ^ x3 ^ x4 ^ c ^ ((x1 ^ x2 ^ c) & (x1 ^ x3));
            ulong t2 = x1 ^ x2 ^ x4 ^ c ^ (x3 & x4);
            ulong t3 = x0 ^ x1 ^ x2 ^ c ^ (~x0 & (x3 ^ x4));
            ulong t4 = x1 ^ x3 ^ x4 ^ ((x0 ^ x4) & x1);
            x0 = t0 ^ Longs.RotateRight(t0, 19) ^ Longs.RotateRight(t0, 28);
            x1 = t1 ^ Longs.RotateRight(t1, 39) ^ Longs.RotateRight(t1, 61);
            x2 = ~(t2 ^ Longs.RotateRight(t2, 1) ^ Longs.RotateRight(t2, 6));
            x3 = t3 ^ Longs.RotateRight(t3, 10) ^ Longs.RotateRight(t3, 17);
            x4 = t4 ^ Longs.RotateRight(t4, 7) ^ Longs.RotateRight(t4, 41);
        }
    }
}
