using System;
using System.Diagnostics;
#if NETSTANDARD1_0_OR_GREATER || NETCOREAPP1_0_OR_GREATER
using System.Runtime.CompilerServices;
#endif
#if NETCOREAPP3_0_OR_GREATER
using System.Buffers.Binary;
using System.Runtime.InteropServices;
using System.Runtime.Intrinsics;
using System.Runtime.Intrinsics.X86;
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

            if (STATE_UINTS == 16)
            {
                OutputBlock16(output, outOff);
                SparkleOpt16(state, SPARKLE_STEPS_SLIM);
                OutputBlock16(output, outOff + 16);
                SparkleOpt16(state, SPARKLE_STEPS_SLIM);
                OutputBlock16(output, outOff + 32);
            }
            else
            {
                OutputBlock12(output, outOff);
                SparkleOpt12(state, SPARKLE_STEPS_SLIM);
                OutputBlock12(output, outOff + 16);
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

            if (STATE_UINTS == 16)
            {
                OutputBlock16(output);
                SparkleOpt16(state, SPARKLE_STEPS_SLIM);
                OutputBlock16(output[16..]);
                SparkleOpt16(state, SPARKLE_STEPS_SLIM);
                OutputBlock16(output[32..]);
            }
            else
            {
                OutputBlock12(output);
                SparkleOpt12(state, SPARKLE_STEPS_SLIM);
                OutputBlock12(output[16..]);
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

#if NETCOREAPP2_1_OR_GREATER || NETSTANDARD2_1_OR_GREATER
        private void OutputBlock12(Span<byte> output)
        {
            Pack.UInt32_To_LE(state[..RATE_UINTS], output);
        }

        private void OutputBlock16(Span<byte> output)
        {
            Pack.UInt32_To_LE(state[0], output);
            Pack.UInt32_To_LE(state[4], output[4..]);
            Pack.UInt32_To_LE(state[1], output[8..]);
            Pack.UInt32_To_LE(state[5], output[12..]);
        }
#else
        private void OutputBlock12(byte[] output, int outOff)
        {
            Pack.UInt32_To_LE(state, 0, RATE_UINTS, output, outOff);
        }

        private void OutputBlock16(byte[] output, int outOff)
        {
            Pack.UInt32_To_LE(state[0], output, outOff);
            Pack.UInt32_To_LE(state[4], output, outOff + 4);
            Pack.UInt32_To_LE(state[1], output, outOff + 8);
            Pack.UInt32_To_LE(state[5], output, outOff + 12);
        }
#endif

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
            if (STATE_UINTS == 16)
            {
                state[0] ^= t0 ^ ty;
                state[1] ^= t2 ^ ty;
                state[2] ^= ty;
                state[3] ^= ty;
                state[4] ^= t1 ^ tx;
                state[5] ^= t3 ^ tx;
                state[6] ^= tx;
                state[7] ^= tx;
                SparkleOpt16(state, steps);
            }
            else
            {
                state[0] ^= t0 ^ ty;
                state[1] ^= t1 ^ tx;
                state[2] ^= t2 ^ ty;
                state[3] ^= t3 ^ tx;
                state[4] ^= ty;
                state[5] ^= tx;
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

                uint t024 = ELL(s00 ^ s02 ^ s04);
                uint t135 = ELL(s01 ^ s03 ^ s05);

                uint u00 = s00 ^ s06;
                uint u01 = s01 ^ s07;
                uint u02 = s02 ^ s08;
                uint u03 = s03 ^ s09;
                uint u04 = s04 ^ s10;
                uint u05 = s05 ^ s11;

                s06 = s00;
                s07 = s01;
                s08 = s02;
                s09 = s03;
                s10 = s04;
                s11 = s05;

                s00 = u02 ^ t135;
                s01 = u03 ^ t024;
                s02 = u04 ^ t135;
                s03 = u05 ^ t024;
                s04 = u00 ^ t135;
                s05 = u01 ^ t024;
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
            Debug.Assert((steps & 1) == 0);

#if NETCOREAPP3_0_OR_GREATER
            if (Sse2.IsSupported)
            {
                var s0246 = Load128(state.AsSpan(0));
                var s1357 = Load128(state.AsSpan(4));
                var s8ACE = Load128(state.AsSpan(8));
                var s9BDF = Load128(state.AsSpan(12));

                var RC03 = Load128(RCON.AsSpan(0));
                var RC47 = Load128(RCON.AsSpan(4));

                for (int step = 0; step < steps; ++step)
                {
                    // Add round ant

                    s1357 = Sse2.Xor(s1357, Vector128.Create(RCON[step & 7], (uint)step, 0U, 0U));

                    // ARXBOX layer

                    ArxBoxRound(RC03, ref s0246, ref s1357);
                    ArxBoxRound(RC47, ref s8ACE, ref s9BDF);

                    // Linear layer

                    var t0246 = ELL(HorizontalXor(s0246));
                    var t1357 = ELL(HorizontalXor(s1357));

                    var u0246 = Sse2.Xor(s0246, s8ACE);
                    var u1357 = Sse2.Xor(s1357, s9BDF);

                    s8ACE = s0246;
                    s9BDF = s1357;

                    s0246 = Sse2.Xor(t1357, Sse2.Shuffle(u0246, 0x39));
                    s1357 = Sse2.Xor(t0246, Sse2.Shuffle(u1357, 0x39));
                }

                Store128(s0246, state.AsSpan(0));
                Store128(s1357, state.AsSpan(4));
                Store128(s8ACE, state.AsSpan(8));
                Store128(s9BDF, state.AsSpan(12));
            }
            else
#endif
            {
                uint s00 = state[ 0];
                uint s02 = state[ 1];
                uint s04 = state[ 2];
                uint s06 = state[ 3];
                uint s01 = state[ 4];
                uint s03 = state[ 5];
                uint s05 = state[ 6];
                uint s07 = state[ 7];
                uint s08 = state[ 8];
                uint s10 = state[ 9];
                uint s12 = state[10];
                uint s14 = state[11];
                uint s09 = state[12];
                uint s11 = state[13];
                uint s13 = state[14];
                uint s15 = state[15];

                int step = 0;
                while (step < steps)
                {
                    // STEP 1

                    // Add round ant

                    s01 ^= RCON[step & 7];
                    s03 ^= (uint)(step++);

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

                    uint t0246 = ELL(s00 ^ s02 ^ s04 ^ s06);
                    uint t1357 = ELL(s01 ^ s03 ^ s05 ^ s07);

                    uint u08 = s08;
                    uint u09 = s09;

                    s08 = s02 ^ s10 ^ t1357;
                    s09 = s03 ^ s11 ^ t0246;
                    s10 = s04 ^ s12 ^ t1357;
                    s11 = s05 ^ s13 ^ t0246;
                    s12 = s06 ^ s14 ^ t1357;
                    s13 = s07 ^ s15 ^ t0246;
                    s14 = s00 ^ u08 ^ t1357;
                    s15 = s01 ^ u09 ^ t0246;

                    // STEP 2

                    // Add round ant

                    s09 ^= RCON[step & 7];
                    s11 ^= (uint)(step++);

                    // ARXBOX layer

                    ArxBoxRound(RCON[0], ref s08, ref s09);
                    ArxBoxRound(RCON[1], ref s10, ref s11);
                    ArxBoxRound(RCON[2], ref s12, ref s13);
                    ArxBoxRound(RCON[3], ref s14, ref s15);
                    ArxBoxRound(RCON[4], ref s00, ref s01);
                    ArxBoxRound(RCON[5], ref s02, ref s03);
                    ArxBoxRound(RCON[6], ref s04, ref s05);
                    ArxBoxRound(RCON[7], ref s06, ref s07);

                    // Linear layer

                    uint t8ACE = ELL(s08 ^ s10 ^ s12 ^ s14);
                    uint t9BDF = ELL(s09 ^ s11 ^ s13 ^ s15);

                    uint u00 = s00;
                    uint u01 = s01;

                    s00 = s02 ^ s10 ^ t9BDF;
                    s01 = s03 ^ s11 ^ t8ACE;
                    s02 = s04 ^ s12 ^ t9BDF;
                    s03 = s05 ^ s13 ^ t8ACE;
                    s04 = s06 ^ s14 ^ t9BDF;
                    s05 = s07 ^ s15 ^ t8ACE;
                    s06 = u00 ^ s08 ^ t9BDF;
                    s07 = u01 ^ s09 ^ t8ACE;
                }

                state[ 0] = s00;
                state[ 1] = s02;
                state[ 2] = s04;
                state[ 3] = s06;
                state[ 4] = s01;
                state[ 5] = s03;
                state[ 6] = s05;
                state[ 7] = s07;
                state[ 8] = s08;
                state[ 9] = s10;
                state[10] = s12;
                state[11] = s14;
                state[12] = s09;
                state[13] = s11;
                state[14] = s13;
                state[15] = s15;
            }
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
            return Integers.RotateRight(x, 16) ^ (x & 0xFFFFU);
        }

#if NETCOREAPP3_0_OR_GREATER
        [MethodImpl(MethodImplOptions.AggressiveInlining)]
        private static void ArxBoxRound(Vector128<uint> rc, ref Vector128<uint> s00, ref Vector128<uint> s01)
        {
            s00 = Sse2.Add(s00, Sse2.ShiftRightLogical(s01, 31));
            s00 = Sse2.Add(s00, Sse2.ShiftLeftLogical(s01, 1));

            s01 = Sse2.Xor(s01, Sse2.ShiftRightLogical(s00, 24));
            s01 = Sse2.Xor(s01, Sse2.ShiftLeftLogical(s00, 8));

            s00 = Sse2.Xor(s00, rc);

            s00 = Sse2.Add(s00, Sse2.ShiftRightLogical(s01, 17));
            s00 = Sse2.Add(s00, Sse2.ShiftLeftLogical(s01, 15));

            s01 = Sse2.Xor(s01, Sse2.ShiftRightLogical(s00, 17));
            s01 = Sse2.Xor(s01, Sse2.ShiftLeftLogical(s00, 15));

            s00 = Sse2.Xor(s00, rc);

            s00 = Sse2.Add(s00, s01);

            s01 = Sse2.Xor(s01, Sse2.ShiftRightLogical(s00, 31));
            s01 = Sse2.Xor(s01, Sse2.ShiftLeftLogical(s00, 1));

            s00 = Sse2.Xor(s00, rc);

            s00 = Sse2.Add(s00, Sse2.ShiftRightLogical(s01, 24));
            s00 = Sse2.Add(s00, Sse2.ShiftLeftLogical(s01, 8));

            s01 = Sse2.Xor(s01, Sse2.ShiftRightLogical(s00, 16));
            s01 = Sse2.Xor(s01, Sse2.ShiftLeftLogical(s00, 16));

            s00 = Sse2.Xor(s00, rc);
        }

        [MethodImpl(MethodImplOptions.AggressiveInlining)]
        private static Vector128<uint> ELL(Vector128<uint> x)
        {
            var t = Sse2.ShiftLeftLogical(x, 16);
            var u = Sse2.Xor(x, t);
            return Sse2.Xor(t, Sse2.ShiftRightLogical(u, 16));
        }

        [MethodImpl(MethodImplOptions.AggressiveInlining)]
        private static Vector128<uint> HorizontalXor(Vector128<uint> x)
        {
            var t = Sse2.Xor(x, Sse2.Shuffle(x, 0x1B));
            return Sse2.Xor(t, Sse2.Shuffle(t, 0xB1));
        }

        [MethodImpl(MethodImplOptions.AggressiveInlining)]
        private static Vector128<uint> Load128(ReadOnlySpan<uint> t)
        {
            if (BitConverter.IsLittleEndian && Unsafe.SizeOf<Vector128<uint>>() == 16)
                return MemoryMarshal.Read<Vector128<uint>>(MemoryMarshal.AsBytes(t));

            return Vector128.Create(t[0], t[1], t[2], t[3]);
        }

        [MethodImpl(MethodImplOptions.AggressiveInlining)]
        private static void Store128(Vector128<uint> s, Span<uint> t)
        {
            var b = MemoryMarshal.AsBytes(t);
            if (BitConverter.IsLittleEndian && Unsafe.SizeOf<Vector128<uint>>() == 16)
            {
                MemoryMarshal.Write(b, ref s);
                return;
            }

            var u = s.AsUInt64();
            BinaryPrimitives.WriteUInt64LittleEndian(b[..8], u.GetElement(0));
            BinaryPrimitives.WriteUInt64LittleEndian(b[8..], u.GetElement(1));
        }
#endif
    }
}
