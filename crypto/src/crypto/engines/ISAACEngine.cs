using System;

using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.Crypto.Utilities;
using Org.BouncyCastle.Utilities;

namespace Org.BouncyCastle.Crypto.Engines
{
    /// <summary>Implementation of Bob Jenkin's ISAAC (Indirection Shift Accumulate Add and Count).</summary>
    /// <remarks>
    /// <see href="https://www.burtleburtle.net/bob/rand/isaacafa.html"/>
    /// </remarks>
    public class IsaacEngine
        : IStreamCipher
    {
        // Constants
        private static readonly int SizeL = 8;
        private static readonly int StateArraySize = SizeL << 5; // 256

        // Cipher's internal state
        private readonly uint[] m_engineState = new uint[StateArraySize]; // mm
        private uint m_a = 0, m_b = 0, m_c = 0;

        // Engine state
        private readonly byte[] m_keyStream = new byte[StateArraySize << 2];
        private int m_keyStreamPos = 0;

        private byte[] m_workingKey = null;
        private bool m_initialised = false;

        public virtual string AlgorithmName => "ISAAC";

        public virtual void Init(bool forEncryption, ICipherParameters parameters)
        {
            // ISAAC encryption/decryption is symmetrical so forEncryption is ignored

            if (!(parameters is KeyParameter keyParameter))
            {
                var message = "invalid parameter passed to ISAAC Init - " + Platform.GetTypeName(parameters);
                throw new ArgumentException(message, nameof(parameters));
            }

            m_workingKey = keyParameter.GetKey();
            m_initialised = true;

            if (m_c > 1)
            {
                ClearKeyStream();
            }

            ResetCipher();
        }

        public virtual byte ReturnByte(byte input)
        {
            if (m_keyStreamPos == 0) 
            {
                Isaac();
            }

            byte output = (byte)(m_keyStream[m_keyStreamPos] ^ input);
            m_keyStreamPos = (m_keyStreamPos + 1) & 1023;

            return output;
        }

        public virtual void ProcessBytes(byte[] input, int inOff, int len, byte[] output, int outOff)
        {
#if NETCOREAPP2_1_OR_GREATER || NETSTANDARD2_1_OR_GREATER
            ProcessBytes(input.AsSpan(inOff, len), output.AsSpan(outOff));
#else
            if (!m_initialised)
                throw new InvalidOperationException(AlgorithmName + " not initialised");

            Check.DataLength(input, inOff, len, "input buffer too short");
            Check.OutputLength(output, outOff, len, "output buffer too short");

            int pos = 0;
            while (pos < len)
            {
                if (m_keyStreamPos == 0)
                {
                    Isaac();
                }

                int xorLen = System.Math.Min(len - pos, m_keyStream.Length - m_keyStreamPos);
                Bytes.Xor(xorLen, input, inOff + pos, m_keyStream, m_keyStreamPos, output, outOff + pos);

                pos += xorLen;
                m_keyStreamPos = (m_keyStreamPos + xorLen) & 1023;
            }
#endif
        }

#if NETCOREAPP2_1_OR_GREATER || NETSTANDARD2_1_OR_GREATER
        public virtual void ProcessBytes(ReadOnlySpan<byte> input, Span<byte> output)
        {
            if (!m_initialised)
                throw new InvalidOperationException(AlgorithmName + " not initialised");

            Check.OutputLength(output, input.Length, "output buffer too short");

            while (!input.IsEmpty)
            {
                if (m_keyStreamPos == 0)
                {
                    Isaac();
                }

                int xorLen = System.Math.Min(input.Length, m_keyStream.Length - m_keyStreamPos);
                Bytes.Xor(xorLen, input, m_keyStream.AsSpan(m_keyStreamPos), output);

                input = input[xorLen..];
                output = output[xorLen..];
                m_keyStreamPos = (m_keyStreamPos + xorLen) & 1023;
            }
        }
#endif

        public virtual void Reset()
        {
            if (m_c > 1)
            {
                ClearKeyStream();
                ResetCipher();
            }
        }

        private void Isaac()
        {
            uint a = m_a;
            uint b = m_b + ++m_c;

            for (int i = 0; i < StateArraySize; i++)
            {
                uint x = m_engineState[i];
                switch (i & 3)
                {
                case 0: a ^= a << 13; break;
                case 1: a ^= a >> 6; break;
                case 2: a ^= a << 2; break;
                case 3: a ^= a >> 16; break;
                }
                a += m_engineState[i ^ 0x80];
                uint y = m_engineState[(x >> 2) & 0xFF] + a + b;
                m_engineState[i] = y;
                b = m_engineState[(y >> 10) & 0xFF] + x;
                Pack.UInt32_To_BE(b, m_keyStream, i * 4);
            }

            m_a = a;
            m_b = b;
        }

        private void ClearKeyStream()
        {
            Arrays.ZeroMemory(m_keyStream);
            m_keyStreamPos = 0;
        }

        private void ResetCipher()
        {
            Arrays.Fill(m_engineState, 0U);
            m_a = 0;
            m_b = 0;
            m_c = 0;

            // Initialise the engine state from the little-endian key bytes
            int fullKeyLength = m_workingKey.Length / 4, partialKeyLength = m_workingKey.Length & 3;
            Pack.LE_To_UInt32(m_workingKey, 0, m_engineState, 0, fullKeyLength);
            if (partialKeyLength != 0)
            {
                m_engineState[fullKeyLength] = Pack.LE_To_UInt32_Low(m_workingKey, fullKeyLength * 4, partialKeyLength);
            }

            // It has begun?
            uint[] abcdefgh = new uint[SizeL];
            Arrays.Fill(abcdefgh, 0x9E3779B9U); // Phi (golden ratio)

            for (int i = 0; i < 4; i++)
            {
                Mix(abcdefgh);
            }

            for (int i = 0; i < 2; i++)
            {
                for (int j = 0; j < StateArraySize; j += SizeL)
                {
                    for (int k = 0; k < SizeL; k++)
                    {
                        abcdefgh[k] += m_engineState[j + k];
                    }

                    Mix(abcdefgh);
                    Array.Copy(abcdefgh, 0, m_engineState, j, SizeL);
                }
            }

            Isaac();
        }

        private static void Mix(uint[] x)
        {
            uint x0 = x[0], x1 = x[1], x2 = x[2], x3 = x[3], x4 = x[4], x5 = x[5], x6 = x[6], x7 = x[7];
            x0 ^= x1 << 11; x3 += x0; x1 += x2;
            x1 ^= x2 >>  2; x4 += x1; x2 += x3;
            x2 ^= x3 <<  8; x5 += x2; x3 += x4;
            x3 ^= x4 >> 16; x6 += x3; x4 += x5;
            x4 ^= x5 << 10; x7 += x4; x5 += x6;
            x5 ^= x6 >>  4; x0 += x5; x6 += x7;
            x6 ^= x7 <<  8; x1 += x6; x7 += x0;
            x7 ^= x0 >>  9; x2 += x7; x0 += x1;
            x[0] = x0; x[1] = x1; x[2] = x2; x[3] = x3; x[4] = x4; x[5] = x5; x[6] = x6; x[7] = x7;
        }
    }
}
