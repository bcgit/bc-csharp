using System;

using Org.BouncyCastle.Utilities;

namespace Org.BouncyCastle.Crypto.Digests
{
    /**
     * Photon-Beetle, https://www.isical.ac.in/~lightweight/beetle/
     * https://csrc.nist.gov/CSRC/media/Projects/lightweight-cryptography/documents/readonlyist-round/updated-spec-doc/photon-beetle-spec-readonly.pdf
     * <p>
     * Photon-Beetle with reference to C Reference Impl from: https://github.com/PHOTON-Beetle/Software
     * </p>
     */
    public sealed class PhotonBeetleDigest
        : IDigest
    {
        private const int INITIAL_RATE_INBYTES = 16;
        private const int RATE_INBYTES = 4;
        private const int SQUEEZE_RATE_INBYTES = 16;
        private const int STATE_INBYTES = 32;
        private const int TAG_INBYTES = 32;
        private const int LAST_THREE_BITS_OFFSET = 5;
        private const int ROUND = 12;
        private const int D = 8;
        private const int Dq = 3;
        private const int Dr = 7;
        private const int DSquare = 64;
        private const int S = 4;
        private const int S_1 = 3;

        private static readonly byte[] RC = { //[ROUND][D] flattened
             1,  0,  2,  6, 14, 15, 13,  9,
             3,  2,  0,  4, 12, 13, 15, 11,
             7,  6,  4,  0,  8,  9, 11, 15,
            14, 15, 13,  9,  1,  0,  2,  6,
            13, 12, 14, 10,  2,  3,  1,  5,
            11, 10,  8, 12,  4,  5,  7,  3,
             6,  7,  5,  1,  9,  8, 10, 14,
            12, 13, 15, 11,  3,  2,  0,  4,
             9,  8, 10, 14,  6,  7,  5,  1,
             2,  3,  1,  5, 13, 12, 14, 10,
             5,  4,  6,  2, 10, 11,  9, 13,
            10, 11,  9, 13,  5,  4,  6,  2,
        };

        private static readonly byte[][] MixColMatrix = { //[D][D]
            new byte[]{  2,  4,  2, 11,  2,  8,  5,  6 },
            new byte[]{ 12,  9,  8, 13,  7,  7,  5,  2 },
            new byte[]{  4,  4, 13, 13,  9,  4, 13,  9 },
            new byte[]{  1,  6,  5,  1, 12, 13, 15, 14 },
            new byte[]{ 15, 12,  9, 13, 14,  5, 14, 13 },
            new byte[]{  9, 14,  5, 15,  4, 12,  9,  6 },
            new byte[]{ 12,  2,  2, 10,  3,  1,  1, 14 },
            new byte[]{ 15,  1, 13, 10,  5, 10,  2,  3 }
        };

        private static readonly byte[] sbox = { 12, 5, 6, 11, 9, 0, 10, 13, 3, 14, 15, 8, 4, 7, 1, 2 };

        private readonly byte[] state;
        private readonly byte[][] state_2d;
        private readonly byte[] m_buf = new byte[16];
        private int m_bufPos = 0;
        private int m_phase = 0;

        public PhotonBeetleDigest()
        {
            state = new byte[STATE_INBYTES];

            state_2d = new byte[D][];
            for (int i = 0; i < D; ++i)
            {
                state_2d[i] = new byte[D];
            }
        }

        public string AlgorithmName => "Photon-Beetle Hash";

        public int GetDigestSize() => TAG_INBYTES;

        public int GetByteLength()
        {
            // TODO
            throw new NotImplementedException();
        }

        public void Update(byte input)
        {
            m_buf[m_bufPos] = input;
            if (++m_bufPos == 16)
            {
#if NETCOREAPP2_1_OR_GREATER || NETSTANDARD2_1_OR_GREATER
                ProcessBuffer(m_buf);
#else
                ProcessBuffer(m_buf, 0);
#endif
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

            int available = 16 - m_bufPos;
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
                ProcessBuffer(m_buf, 0);
            }

            int remaining;
            while ((remaining = inLen - inPos) >= 16)
            {
                ProcessBuffer(input, inOff + inPos);
                inPos += 16;
            }

            Array.Copy(input, inOff + inPos, m_buf, 0, remaining);
            m_bufPos = remaining;
#endif
        }

#if NETCOREAPP2_1_OR_GREATER || NETSTANDARD2_1_OR_GREATER
        public void BlockUpdate(ReadOnlySpan<byte> input)
        {
            int available = 16 - m_bufPos;
            if (input.Length < available)
            {
                input.CopyTo(m_buf.AsSpan(m_bufPos));
                m_bufPos += input.Length;
                return;
            }

            if (m_bufPos > 0)
            {
                input[..available].CopyTo(m_buf.AsSpan(m_bufPos));
                ProcessBuffer(m_buf);
                input = input[available..];
            }

            while (input.Length >= 16)
            {
                ProcessBuffer(input);
                input = input[16..];
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

            FinishAbsorbing();

            PHOTON_Permutation();
            Array.Copy(state, 0, output, outOff, SQUEEZE_RATE_INBYTES);
            PHOTON_Permutation();
            Array.Copy(state, 0, output, outOff + SQUEEZE_RATE_INBYTES, TAG_INBYTES - SQUEEZE_RATE_INBYTES);

            Reset();
            return TAG_INBYTES;
#endif
        }

#if NETCOREAPP2_1_OR_GREATER || NETSTANDARD2_1_OR_GREATER
        public int DoFinal(Span<byte> output)
        {
            Check.OutputLength(output, 32, "output buffer too short");

            FinishAbsorbing();

            PHOTON_Permutation();
            state.AsSpan(0, SQUEEZE_RATE_INBYTES).CopyTo(output);
            PHOTON_Permutation();
            state.AsSpan(0, TAG_INBYTES - SQUEEZE_RATE_INBYTES).CopyTo(output[SQUEEZE_RATE_INBYTES..]);

            Reset();
            return TAG_INBYTES;
        }
#endif

        public void Reset()
        {
            Arrays.Fill(state, 0);
            Arrays.Fill(m_buf, 0);
            m_bufPos = 0;
            m_phase = 0;
        }

        private void FinishAbsorbing()
        {
            if (m_phase == 0)
            {
                if (m_bufPos != 0)
                {
                    Array.Copy(m_buf, 0, state, 0, m_bufPos);
                    state[m_bufPos] ^= 0x01; // ozs
                }

                state[STATE_INBYTES - 1] ^= (byte)(1 << LAST_THREE_BITS_OFFSET);
            }
            else if (m_phase == 1 && m_bufPos == 0)
            {
                state[STATE_INBYTES - 1] ^= (byte)(2 << LAST_THREE_BITS_OFFSET);
            }
            else
            {
                int pos = 0, limit = m_bufPos - 4;
                while (pos <= limit)
                {
                    PHOTON_Permutation();
                    Bytes.XorTo(4, m_buf, pos, state, 0);
                    pos += 4;
                }

                int remaining = m_bufPos - pos;
                if (remaining != 0)
                {
                    PHOTON_Permutation();
                    Bytes.XorTo(remaining, m_buf, pos, state, 0);
                    state[remaining] ^= 0x01; // ozs
                    state[STATE_INBYTES - 1] ^= (byte)(2 << LAST_THREE_BITS_OFFSET);
                }
                else
                {
                    state[STATE_INBYTES - 1] ^= (byte)(1 << LAST_THREE_BITS_OFFSET);
                }
            }
        }

#if NETCOREAPP2_1_OR_GREATER || NETSTANDARD2_1_OR_GREATER
        private void ProcessBuffer(ReadOnlySpan<byte> buf)
        {
            if (m_phase == 0)
            {
                buf[..16].CopyTo(state);

                m_phase = 1;
            }
            else
            {
                PHOTON_Permutation();
                Bytes.XorTo(4, buf      , state);
                PHOTON_Permutation();
                Bytes.XorTo(4, buf[ 4..], state);
                PHOTON_Permutation();
                Bytes.XorTo(4, buf[ 8..], state);
                PHOTON_Permutation();
                Bytes.XorTo(4, buf[12..], state);

                m_phase = 2;
            }
        }
#else
        private void ProcessBuffer(byte[] buf, int pos)
        {
            if (m_phase == 0)
            {
                Array.Copy(buf, pos, state, 0, 16);

                m_phase = 1;
            }
            else
            {
                PHOTON_Permutation();
                Bytes.XorTo(4, buf, pos +  0, state, 0);
                PHOTON_Permutation();
                Bytes.XorTo(4, buf, pos +  4, state, 0);
                PHOTON_Permutation();
                Bytes.XorTo(4, buf, pos +  8, state, 0);
                PHOTON_Permutation();
                Bytes.XorTo(4, buf, pos + 12, state, 0);

                m_phase = 2;
            }
        }
#endif

        private void PHOTON_Permutation()
        {
            int i, j, k;
            for (i = 0; i < DSquare; i++)
            {
                state_2d[i >> Dq][i & Dr] = (byte)(((state[i >> 1] & 0xFF) >> (4 * (i & 1))) & 0xf);
            }
            for (int round = 0; round < ROUND; round++)
            {
                //AddConstant
                {
                    int rcOff = round * D;
                    for (i = 0; i < D; i++)
                    {
                        state_2d[i][0] ^= RC[rcOff++];
                    }
                }
                //SubCells
                for (i = 0; i < D; i++)
                {
                    for (j = 0; j < D; j++)
                    {
                        state_2d[i][j] = sbox[state_2d[i][j]];
                    }
                }
                //ShiftRows
                for (i = 1; i < D; i++)
                {
                    Array.Copy(state_2d[i], 0, state, 0, D);
                    Array.Copy(state, i, state_2d[i], 0, D - i);
                    Array.Copy(state, 0, state_2d[i], D - i, i);
                }
                //MixColumnSerial
                for (j = 0; j < D; j++)
                {
                    for (i = 0; i < D; i++)
                    {
                        int sum = 0;

                        for (k = 0; k < D; k++)
                        {
                            int x = MixColMatrix[i][k], b = state_2d[k][j];

                            sum ^= x * (b & 1);
                            sum ^= x * (b & 2);
                            sum ^= x * (b & 4);
                            sum ^= x * (b & 8);
                        }

                        int t0 = sum >> 4;
                        sum = (sum & 15) ^ t0 ^ (t0 << 1);

                        int t1 = sum >> 4;
                        sum = (sum & 15) ^ t1 ^ (t1 << 1);

                        state[i] = (byte)sum;
                    }
                    for (i = 0; i < D; i++)
                    {
                        state_2d[i][j] = state[i];
                    }
                }
            }
            for (i = 0; i < DSquare; i += 2)
            {
                state[i >> 1] = (byte)(((state_2d[i >> Dq][i & Dr] & 0xf)) | ((state_2d[i >> Dq][(i + 1) & Dr] & 0xf) << 4));
            }
        }
    }
}
