#if NETCOREAPP3_0_OR_GREATER
using System;
using System.Buffers.Binary;
using System.Diagnostics;
using System.Runtime.CompilerServices;
using System.Runtime.InteropServices;
using System.Runtime.Intrinsics;

using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Crypto.Digests;
using Org.BouncyCastle.Utilities;

namespace Org.BouncyCastle.Pqc.Crypto.SphincsPlus
{
    internal class HarakaS_X86
        : IXof
    {
        public static bool IsSupported => Haraka512_X86.IsSupported;

        private enum State { Absorbing, Squeezing };

        private readonly Vector128<byte>[] m_roundConstants = new Vector128<byte>[40];

        private readonly byte[] m_buf = new byte[64];
        private int m_bufPos = 0;
        private State m_state = State.Absorbing;

        internal HarakaS_X86(ReadOnlySpan<byte> pkSeed)
        {
            if (!IsSupported)
                throw new PlatformNotSupportedException(nameof(HarakaS_X86));

            // Absorb PKSeed
            Span<byte> buf = stackalloc byte[64];
            while (pkSeed.Length >= 32)
            {
                XorWith(pkSeed[..32], buf);
                Haraka512_X86.Permute(buf, buf);
                pkSeed = pkSeed[32..];
            }
            XorWith(pkSeed, buf);
            buf[pkSeed.Length] ^= 0x1F;
            buf[           31] ^= 0x80;

            // Squeeze round constants
            int rc = 0;
            while (rc < 40)
            {
                Haraka512_X86.Permute(buf, buf);
                m_roundConstants[rc++] = Load128(buf[  ..16]);
                m_roundConstants[rc++] = Load128(buf[16..32]);
            }
        }

        internal ReadOnlySpan<Vector128<byte>> RoundConstants => m_roundConstants;

        public string AlgorithmName => "HarakaS";

        public int GetDigestSize() => 32;

        public int GetByteLength() => 32;

        public void Update(byte input)
        {
            if (m_state != State.Absorbing)
                throw new InvalidOperationException();

            m_buf[m_bufPos++] ^= input;
            if (m_bufPos == 32)
            {
                Haraka512_X86.Permute(m_buf, m_buf, m_roundConstants);
                m_bufPos = 0;
            }
        }

        public void BlockUpdate(byte[] input, int inOff, int inLen)
        {
            BlockUpdate(input.AsSpan(inOff, inLen));
        }

        public void BlockUpdate(ReadOnlySpan<byte> input)
        {
            if (m_state != State.Absorbing)
                throw new InvalidOperationException();

            int available = 32 - m_bufPos;
            if (input.Length < available)
            {
                XorWith(input, m_buf.AsSpan(m_bufPos));
                m_bufPos += input.Length;
                return;
            }

            XorWith(input[..available], m_buf.AsSpan(m_bufPos));
            input = input[available..];
            Haraka512_X86.Permute(m_buf, m_buf, m_roundConstants);

            while (input.Length >= 32)
            {
                XorWith(input[..32], m_buf);
                input = input[32..];
                Haraka512_X86.Permute(m_buf, m_buf, m_roundConstants);
            }

            XorWith(input, m_buf);
            m_bufPos = input.Length;
        }

        public int DoFinal(byte[] output, int outOff)
        {
            return OutputFinal(output.AsSpan(outOff, 32));
        }

        public int DoFinal(Span<byte> output)
        {
            return OutputFinal(output[..32]);
        }

        public int Output(byte[] output, int outOff, int outLen)
        {
            return Output(output.AsSpan(outOff, outLen));
        }

        public int Output(Span<byte> output)
        {
            int result = output.Length;

            if (m_state != State.Squeezing)
            {
                m_buf[m_bufPos] ^= 0x1F;
                m_buf[31] ^= 0x80;
                m_bufPos = 32;
                m_state = State.Squeezing;

                if (output.IsEmpty)
                    return result;
            }
            else
            {
                int available = 32 - m_bufPos;
                if (output.Length <= available)
                {
                    output.CopyFrom(m_buf.AsSpan(m_bufPos));
                    m_bufPos += available;
                    return result;
                }

                output[..available].CopyFrom(m_buf.AsSpan(m_bufPos));
                output = output[available..];
            }

            Debug.Assert(!output.IsEmpty);

            while (output.Length > 32)
            {
                Haraka512_X86.Permute(m_buf, m_buf, m_roundConstants);
                output[..32].CopyFrom(m_buf);
                output = output[32..];
            }

            Haraka512_X86.Permute(m_buf, m_buf, m_roundConstants);
            output.CopyFrom(m_buf);
            m_bufPos = output.Length;

            return result;
        }

        public int OutputFinal(byte[] output, int outOff, int outLen)
        {
            return OutputFinal(output.AsSpan(outOff, outLen));
        }

        public int OutputFinal(Span<byte> output)
        {
            int result = Output(output);
            Reset();
            return result;
        }

        public void Reset()
        {
            Array.Clear(m_buf);
            m_bufPos = 0;
            m_state = State.Absorbing;
        }

        [MethodImpl(MethodImplOptions.AggressiveInlining)]
        private static Vector128<byte> Load128(ReadOnlySpan<byte> t)
        {
            if (BitConverter.IsLittleEndian && Unsafe.SizeOf<Vector128<byte>>() == 16)
                return MemoryMarshal.Read<Vector128<byte>>(t);

            return Vector128.Create(
                BinaryPrimitives.ReadUInt64LittleEndian(t[..8]),
                BinaryPrimitives.ReadUInt64LittleEndian(t[8..])
            ).AsByte();
        }

        [MethodImpl(MethodImplOptions.AggressiveInlining)]
        private static void XorWith(ReadOnlySpan<byte> x, Span<byte> z)
        {
            for (int i = 0; i < x.Length; i++)
            {
                z[i] ^= x[i];
            }
        }
    }
}
#endif
