using System;
#if NETSTANDARD1_0_OR_GREATER || NETCOREAPP1_0_OR_GREATER
using System.Runtime.CompilerServices;
#endif

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
                throw new ArgumentException("Invalid definition of SCHWAEMM instance");
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
                m_buf[m_bufPos++] = 0x80;
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
                SparkleOpt16(state, SPARKLE_STEPS_SLIM);
                Pack.UInt32_To_LE(state, 0, RATE_UINTS, output, outOff + 16);
                SparkleOpt16(state, SPARKLE_STEPS_SLIM);
                Pack.UInt32_To_LE(state, 0, RATE_UINTS, output, outOff + 32);
            }
            else
            {
                SparkleOpt12(state, SPARKLE_STEPS_SLIM);
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
                m_buf[m_bufPos++] = 0x80;
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
                SparkleOpt16(state, SPARKLE_STEPS_SLIM);
                Pack.UInt32_To_LE(state[..RATE_UINTS], output[16..]);
                SparkleOpt16(state, SPARKLE_STEPS_SLIM);
                Pack.UInt32_To_LE(state[..RATE_UINTS], output[32..]);
            }
            else
            {
                SparkleOpt12(state, SPARKLE_STEPS_SLIM);
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
                SparkleOpt16(state, steps);
            }
            else
            {
                SparkleOpt12(state, steps);
            }
        }

        private static void SparkleOpt12(uint[] state, int steps)
        {
            uint s00 = state[ 0];
            uint s01 = state[ 1];
            uint s02 = state[ 2];
            uint s03 = state[ 3];
            uint s04 = state[ 4];
            uint s05 = state[ 5];
            uint s06 = state[ 6];
            uint s07 = state[ 7];
            uint s08 = state[ 8];
            uint s09 = state[ 9];
            uint s10 = state[10];
            uint s11 = state[11];

            for (int i = 0; i < steps; ++i)
            {
                // Add round ant
                s01 ^= RCON[i & 7];
                s03 ^= (uint)i;

                // ARXBOX layer
                ArxBoxRound(RCON[0], ref s00, ref s01);
                ArxBoxRound(RCON[1], ref s02, ref s03);
                ArxBoxRound(RCON[2], ref s04, ref s05);
                ArxBoxRound(RCON[3], ref s06, ref s07);
                ArxBoxRound(RCON[4], ref s08, ref s09);
                ArxBoxRound(RCON[5], ref s10, ref s11);

                // Linear layer
                uint x0 = s00;
                uint y0 = s01;

                uint tx = ELL(s00 ^ s02 ^ s04);
                uint ty = ELL(s01 ^ s03 ^ s05);

                s00 = s08 ^ s02 ^ ty;
                s01 = s09 ^ s03 ^ tx;
                s08 = s02;
                s09 = s03;

                s02 = s10 ^ s04 ^ ty;
                s03 = s11 ^ s05 ^ tx;
                s10 = s04;
                s11 = s05;

                s04 = s06 ^ x0 ^ ty;
                s05 = s07 ^ y0 ^ tx;
                s06 = x0;
                s07 = y0;
            }

            state[ 0] = s00;
            state[ 1] = s01;
            state[ 2] = s02;
            state[ 3] = s03;
            state[ 4] = s04;
            state[ 5] = s05;
            state[ 6] = s06;
            state[ 7] = s07;
            state[ 8] = s08;
            state[ 9] = s09;
            state[10] = s10;
            state[11] = s11;
        }

        private static void SparkleOpt16(uint[] state, int steps)
        {
            uint s00 = state[ 0];
            uint s01 = state[ 1];
            uint s02 = state[ 2];
            uint s03 = state[ 3];
            uint s04 = state[ 4];
            uint s05 = state[ 5];
            uint s06 = state[ 6];
            uint s07 = state[ 7];
            uint s08 = state[ 8];
            uint s09 = state[ 9];
            uint s10 = state[10];
            uint s11 = state[11];
            uint s12 = state[12];
            uint s13 = state[13];
            uint s14 = state[14];
            uint s15 = state[15];

            for (int i = 0; i < steps; ++i)
            {
                // Add round ant
                s01 ^= RCON[i & 7];
                s03 ^= (uint)i;

                // ARXBOX layer
                ArxBoxRound(RCON[0], ref s00, ref s01);
                ArxBoxRound(RCON[1], ref s02, ref s03);
                ArxBoxRound(RCON[2], ref s04, ref s05);
                ArxBoxRound(RCON[3], ref s06, ref s07);
                ArxBoxRound(RCON[4], ref s08, ref s09);
                ArxBoxRound(RCON[5], ref s10, ref s11);
                ArxBoxRound(RCON[6], ref s12, ref s13);
                ArxBoxRound(RCON[7], ref s14, ref s15);

                // Linear layer
                uint x0 = s00;
                uint y0 = s01;

                uint tx = ELL(s00 ^ s02 ^ s04 ^ s06);
                uint ty = ELL(s01 ^ s03 ^ s05 ^ s07);

                s00 = s10 ^ s02 ^ ty;
                s01 = s11 ^ s03 ^ tx;
                s10 = s02;
                s11 = s03;

                s02 = s12 ^ s04 ^ ty;
                s03 = s13 ^ s05 ^ tx;
                s12 = s04;
                s13 = s05;

                s04 = s14 ^ s06 ^ ty;
                s05 = s15 ^ s07 ^ tx;
                s14 = s06;
                s15 = s07;

                s06 = s08 ^ x0 ^ ty;
                s07 = s09 ^ y0 ^ tx;
                s08 = x0;
                s09 = y0;
            }

            state[ 0] = s00;
            state[ 1] = s01;
            state[ 2] = s02;
            state[ 3] = s03;
            state[ 4] = s04;
            state[ 5] = s05;
            state[ 6] = s06;
            state[ 7] = s07;
            state[ 8] = s08;
            state[ 9] = s09;
            state[10] = s10;
            state[11] = s11;
            state[12] = s12;
            state[13] = s13;
            state[14] = s14;
            state[15] = s15;
        }

#if NETSTANDARD1_0_OR_GREATER || NETCOREAPP1_0_OR_GREATER
        [MethodImpl(MethodImplOptions.AggressiveInlining)]
#endif
        private static void ArxBoxRound(uint rc, ref uint s00, ref uint s01)
        {
            s00 += Integers.RotateRight(s01, 31);
            s01 ^= Integers.RotateRight(s00, 24);
            s00 ^= rc;
            s00 += Integers.RotateRight(s01, 17);
            s01 ^= Integers.RotateRight(s00, 17);
            s00 ^= rc;
            s00 += s01;
            s01 ^= Integers.RotateRight(s00, 31);
            s00 ^= rc;
            s00 += Integers.RotateRight(s01, 24);
            s01 ^= Integers.RotateRight(s00, 16);
            s00 ^= rc;
        }

#if NETSTANDARD1_0_OR_GREATER || NETCOREAPP1_0_OR_GREATER
        [MethodImpl(MethodImplOptions.AggressiveInlining)]
#endif
        private static uint ELL(uint x)
        {
            return Integers.RotateRight(x ^ (x << 16), 16);
        }
    }
}
