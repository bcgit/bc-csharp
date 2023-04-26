using System;
#if NETSTANDARD1_0_OR_GREATER || NETCOREAPP1_0_OR_GREATER
using System.Runtime.CompilerServices;
#endif

using Org.BouncyCastle.Crypto.Engines;
using Org.BouncyCastle.Crypto.Utilities;
using Org.BouncyCastle.Utilities;

namespace Org.BouncyCastle.Crypto.Digests
{
    /// <summary>Sparkle v1.2, based on the current round 3 submission, https://sparkle-lwc.github.io/ .</summary>
    /// <remarks>
    /// Reference C implementation: https://github.com/cryptolu/sparkle.<br/>
    /// Specification:
    /// https://csrc.nist.gov/CSRC/media/Projects/lightweight-cryptography/documents/finalist-round/updated-spec-doc/sparkle-spec-final.pdf .
    /// </remarks>
    public sealed class SparkleDigest
        : IDigest
    {
        public enum SparkleParameters
        {
            ESCH256,
            ESCH384
        }

        private const int RATE_BITS = 128;
        private const int RATE_BYTES = 16;
        private const int RATE_UINTS = 4;

        private static readonly uint[] RCON = { 0xB7E15162U, 0xBF715880U, 0x38B4DA56U, 0x324E7738U, 0xBB1185EBU,
            0x4F7C7B57U, 0xCFBFA1C8U, 0xC2B3293DU };

        private string algorithmName;
        private readonly uint[] state;
        private readonly byte[] m_buf = new byte[RATE_BYTES];
        private readonly int DIGEST_BYTES;
        private readonly int SPARKLE_STEPS_SLIM;
        private readonly int SPARKLE_STEPS_BIG;
        private readonly int STATE_UINTS;

        private int m_bufPos = 0;

        public SparkleDigest(SparkleParameters sparkleParameters)
        {
            switch (sparkleParameters)
            {
            case SparkleParameters.ESCH256:
                algorithmName = "ESCH-256";
                DIGEST_BYTES = 32;
                SPARKLE_STEPS_SLIM = 7;
                SPARKLE_STEPS_BIG = 11;
                STATE_UINTS = 12;
                break;
            case SparkleParameters.ESCH384:
                algorithmName = "ESCH-384";
                DIGEST_BYTES = 48;
                SPARKLE_STEPS_SLIM = 8;
                SPARKLE_STEPS_BIG = 12;
                STATE_UINTS = 16;
                break;
            default:
                throw new ArgumentException("Invalid definition of ESCH instance");
            }

            state = new uint[STATE_UINTS];
        }

        public string AlgorithmName => algorithmName;

        public int GetDigestSize() => DIGEST_BYTES;

        public int GetByteLength() => RATE_BYTES;

        public void Update(byte input)
        {
            if (m_bufPos == RATE_BYTES)
            {
#if NETCOREAPP2_1_OR_GREATER || NETSTANDARD2_1_OR_GREATER
                ProcessBlock(m_buf, SPARKLE_STEPS_SLIM);
#else
                ProcessBlock(m_buf, 0, SPARKLE_STEPS_SLIM);
#endif
                m_bufPos = 0;
            }

            m_buf[m_bufPos++] = input;
        }

        public void BlockUpdate(byte[] input, int inOff, int inLen)
        {
            Check.DataLength(input, inOff, inLen, "input buffer too short");

#if NETCOREAPP2_1_OR_GREATER || NETSTANDARD2_1_OR_GREATER
            BlockUpdate(input.AsSpan(inOff, inLen));
#else
            if (inLen < 1)
                return;

            int available = RATE_BYTES - m_bufPos;
            if (inLen <= available)
            {
                Array.Copy(input, inOff, m_buf, m_bufPos, inLen);
                m_bufPos += inLen;
                return;
            }

            int inPos = 0;
            if (m_bufPos > 0)
            {
                Array.Copy(input, inOff, m_buf, m_bufPos, available);
                ProcessBlock(m_buf, 0, SPARKLE_STEPS_SLIM);
                inPos += available;
            }

            int remaining;
            while ((remaining = inLen - inPos) > RATE_BYTES)
            {
                ProcessBlock(input, inOff + inPos, SPARKLE_STEPS_SLIM);
                inPos += RATE_BYTES;
            }

            Array.Copy(input, inOff + inPos, m_buf, 0, remaining);
            m_bufPos = remaining;
#endif
        }

#if NETCOREAPP2_1_OR_GREATER || NETSTANDARD2_1_OR_GREATER
        public void BlockUpdate(ReadOnlySpan<byte> input)
        {
            int available = RATE_BYTES - m_bufPos;
            if (input.Length <= available)
            {
                input.CopyTo(m_buf.AsSpan(m_bufPos));
                m_bufPos += input.Length;
                return;
            }

            if (m_bufPos > 0)
            {
                input[..available].CopyTo(m_buf.AsSpan(m_bufPos));
                input = input[available..];

                ProcessBlock(m_buf, SPARKLE_STEPS_SLIM);
            }

            while (input.Length > RATE_BYTES)
            {
                ProcessBlock(input, SPARKLE_STEPS_SLIM);
                input = input[RATE_BYTES..];
            }

            input.CopyTo(m_buf);
            m_bufPos = input.Length;
        }
#endif

        public int DoFinal(byte[] output, int outOff)
        {
            Check.OutputLength(output, outOff, DIGEST_BYTES, "output buffer too short");

#if NETCOREAPP2_1_OR_GREATER || NETSTANDARD2_1_OR_GREATER
            return DoFinal(output.AsSpan(outOff));
#else
            // addition of constant M1 or M2 to the state
            if (m_bufPos < RATE_BYTES)
            {
                state[(STATE_UINTS >> 1) - 1] ^= 1U << 24;

                // padding
                m_buf[m_bufPos] = 0x80;
                while(++m_bufPos < RATE_BYTES)
                {
                    m_buf[m_bufPos] = 0x00;
                }
            }
            else
            {
                state[(STATE_UINTS >> 1) - 1] ^= 1U << 25;
            }

            // addition of last msg block (incl. padding)
            ProcessBlock(m_buf, 0, SPARKLE_STEPS_BIG);

            Pack.UInt32_To_LE(state, 0, RATE_UINTS, output, outOff);

            if (STATE_UINTS == 16)
            {
                SparkleEngine.SparkleOpt16(state, SPARKLE_STEPS_SLIM);
                Pack.UInt32_To_LE(state, 0, RATE_UINTS, output, outOff + 16);
                SparkleEngine.SparkleOpt16(state, SPARKLE_STEPS_SLIM);
                Pack.UInt32_To_LE(state, 0, RATE_UINTS, output, outOff + 32);
            }
            else
            {
                SparkleEngine.SparkleOpt12(state, SPARKLE_STEPS_SLIM);
                Pack.UInt32_To_LE(state, 0, RATE_UINTS, output, outOff + 16);
            }

            Reset();
            return DIGEST_BYTES;
#endif
        }

#if NETCOREAPP2_1_OR_GREATER || NETSTANDARD2_1_OR_GREATER
        public int DoFinal(Span<byte> output)
        {
            // addition of constant M1 or M2 to the state
            if (m_bufPos < RATE_BYTES)
            {
                state[(STATE_UINTS >> 1) - 1] ^= 1U << 24;

                // padding
                m_buf[m_bufPos] = 0x80;
                while(++m_bufPos < RATE_BYTES)
                {
                    m_buf[m_bufPos] = 0x00;
                }
            }
            else
            {
                state[(STATE_UINTS >> 1) - 1] ^= 1U << 25;
            }

            // addition of last msg block (incl. padding)
            ProcessBlock(m_buf, SPARKLE_STEPS_BIG);

            Pack.UInt32_To_LE(state[..RATE_UINTS], output);

            if (STATE_UINTS == 16)
            {
                SparkleEngine.SparkleOpt16(state, SPARKLE_STEPS_SLIM);
                Pack.UInt32_To_LE(state[..RATE_UINTS], output[16..]);
                SparkleEngine.SparkleOpt16(state, SPARKLE_STEPS_SLIM);
                Pack.UInt32_To_LE(state[..RATE_UINTS], output[32..]);
            }
            else
            {
                SparkleEngine.SparkleOpt12(state, SPARKLE_STEPS_SLIM);
                Pack.UInt32_To_LE(state[..RATE_UINTS], output[16..]);
            }

            Reset();
            return DIGEST_BYTES;
        }
#endif

        public void Reset()
        {
            Arrays.Fill(state, 0U);
            Arrays.Fill(m_buf, 0x00);
            m_bufPos = 0;
        }

#if NETSTANDARD1_0_OR_GREATER || NETCOREAPP1_0_OR_GREATER
        [MethodImpl(MethodImplOptions.AggressiveInlining)]
#endif
#if NETCOREAPP2_1_OR_GREATER || NETSTANDARD2_1_OR_GREATER
        private void ProcessBlock(ReadOnlySpan<byte> block, int steps)
        {
            uint t0 = Pack.LE_To_UInt32(block);
            uint t1 = Pack.LE_To_UInt32(block[4..]);
            uint t2 = Pack.LE_To_UInt32(block[8..]);
            uint t3 = Pack.LE_To_UInt32(block[12..]);
#else
        private void ProcessBlock(byte[] buf, int off, int steps)
        {
            uint t0 = Pack.LE_To_UInt32(buf, off     );
            uint t1 = Pack.LE_To_UInt32(buf, off +  4);
            uint t2 = Pack.LE_To_UInt32(buf, off +  8);
            uint t3 = Pack.LE_To_UInt32(buf, off + 12);
#endif

            // addition of a buffer block to the state
            uint tx = ELL(t0 ^ t2);
            uint ty = ELL(t1 ^ t3);
            state[0] ^= t0 ^ ty;
            state[1] ^= t1 ^ tx;
            state[2] ^= t2 ^ ty;
            state[3] ^= t3 ^ tx;
            state[4] ^= ty;
            state[5] ^= tx;
            if (STATE_UINTS == 16)
            {
                state[6] ^= ty;
                state[7] ^= tx;
                SparkleEngine.SparkleOpt16(state, steps);
            }
            else
            {
                SparkleEngine.SparkleOpt12(state, steps);
            }
        }

#if NETSTANDARD1_0_OR_GREATER || NETCOREAPP1_0_OR_GREATER
        [MethodImpl(MethodImplOptions.AggressiveInlining)]
#endif
        private static uint ELL(uint x)
        {
            return Integers.RotateRight(x, 16) ^ (x & 0xFFFFU);
        }
    }
}
