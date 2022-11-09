using System;

namespace Org.BouncyCastle.Crypto.Digests
{
    public sealed class Haraka256Digest
        : HarakaBase
    {
        private readonly byte[] m_buf;
        private int m_bufPos;

        public Haraka256Digest()
        {
            m_buf = new byte[32];
            m_bufPos = 0;
        }

        public override string AlgorithmName => "Haraka-256";

        public override int GetByteLength() => 32;

        public override void Update(byte input)
        {
            if (m_bufPos > 32 - 1)
                throw new ArgumentException("total input cannot be more than 32 bytes");

            m_buf[m_bufPos++] = input;
        }

        public override void BlockUpdate(byte[] input, int inOff, int len)
        {
            if (m_bufPos > 32 - len)
                throw new ArgumentException("total input cannot be more than 32 bytes");

            Array.Copy(input, inOff, m_buf, m_bufPos, len);
            m_bufPos += len;
        }

#if NETCOREAPP2_1_OR_GREATER || NETSTANDARD2_1_OR_GREATER
        public override void BlockUpdate(ReadOnlySpan<byte> input)
        {
            if (m_bufPos > 32 - input.Length)
                throw new ArgumentException("total input cannot be more than 32 bytes");

            input.CopyTo(m_buf.AsSpan(m_bufPos));
            m_bufPos += input.Length;
        }
#endif

        public override int DoFinal(byte[] output, int outOff)
        {
#if NETCOREAPP2_1_OR_GREATER || NETSTANDARD2_1_OR_GREATER
            return DoFinal(output.AsSpan(outOff));
#else
            if (m_bufPos != 32)
                throw new ArgumentException("input must be exactly 32 bytes");

            if (output.Length - outOff < 32)
                throw new ArgumentException("output too short to receive digest");

            int rv = Haraka256256(m_buf, output, outOff);

            Reset();

            return rv;
#endif
        }

#if NETCOREAPP2_1_OR_GREATER || NETSTANDARD2_1_OR_GREATER
        public override int DoFinal(Span<byte> output)
        {
            if (m_bufPos != 32)
                throw new ArgumentException("input must be exactly 32 bytes");

            if (output.Length < 32)
                throw new ArgumentException("output too short to receive digest");

#if NETCOREAPP3_0_OR_GREATER
            if (Haraka256_X86.IsSupported)
            {
                Haraka256_X86.Hash(m_buf, output);
                Reset();
                return 32;
            }
#endif

            int rv = Haraka256256(m_buf, output);

            Reset();

            return rv;
        }
#endif

        public override void Reset()
        {
            m_bufPos = 0;
            Array.Clear(m_buf, 0, 32);
        }

#if NETCOREAPP2_1_OR_GREATER || NETSTANDARD2_1_OR_GREATER
        private static int Haraka256256(ReadOnlySpan<byte> msg, Span<byte> output)
        {
            byte[][] s1 = new byte[2][];
            s1[0] = new byte[16];
            s1[1] = new byte[16];
            byte[][] s2 = new byte[2][];
            s2[0] = new byte[16];
            s2[1] = new byte[16];

            msg[  ..16].CopyTo(s1[0]);
            msg[16..32].CopyTo(s1[1]);

            s1[0] = AesEnc(s1[0], RC[0]);
            s1[1] = AesEnc(s1[1], RC[1]);
            s1[0] = AesEnc(s1[0], RC[2]);
            s1[1] = AesEnc(s1[1], RC[3]);
            Mix256(s1, s2);

            s1[0] = AesEnc(s2[0], RC[4]);
            s1[1] = AesEnc(s2[1], RC[5]);
            s1[0] = AesEnc(s1[0], RC[6]);
            s1[1] = AesEnc(s1[1], RC[7]);
            Mix256(s1, s2);

            s1[0] = AesEnc(s2[0], RC[8]);
            s1[1] = AesEnc(s2[1], RC[9]);
            s1[0] = AesEnc(s1[0], RC[10]);
            s1[1] = AesEnc(s1[1], RC[11]);
            Mix256(s1, s2);

            s1[0] = AesEnc(s2[0], RC[12]);
            s1[1] = AesEnc(s2[1], RC[13]);
            s1[0] = AesEnc(s1[0], RC[14]);
            s1[1] = AesEnc(s1[1], RC[15]);
            Mix256(s1, s2);

            s1[0] = AesEnc(s2[0], RC[16]);
            s1[1] = AesEnc(s2[1], RC[17]);
            s1[0] = AesEnc(s1[0], RC[18]);
            s1[1] = AesEnc(s1[1], RC[19]);
            Mix256(s1, s2);

            Xor(s2[0], msg      , output[  ..16]);
            Xor(s2[1], msg[16..], output[16..32]);

            return DIGEST_SIZE;
        }
#else
        private static int Haraka256256(byte[] msg, byte[] output, int outOff)
        {
            byte[][] s1 = new byte[2][];
            s1[0] = new byte[16];
            s1[1] = new byte[16];
            byte[][] s2 = new byte[2][];
            s2[0] = new byte[16];
            s2[1] = new byte[16];

            Array.Copy(msg,  0, s1[0], 0, 16);
            Array.Copy(msg, 16, s1[1], 0, 16);

            s1[0] = AesEnc(s1[0], RC[0]);
            s1[1] = AesEnc(s1[1], RC[1]);
            s1[0] = AesEnc(s1[0], RC[2]);
            s1[1] = AesEnc(s1[1], RC[3]);
            Mix256(s1, s2);

            s1[0] = AesEnc(s2[0], RC[4]);
            s1[1] = AesEnc(s2[1], RC[5]);
            s1[0] = AesEnc(s1[0], RC[6]);
            s1[1] = AesEnc(s1[1], RC[7]);
            Mix256(s1, s2);

            s1[0] = AesEnc(s2[0], RC[8]);
            s1[1] = AesEnc(s2[1], RC[9]);
            s1[0] = AesEnc(s1[0], RC[10]);
            s1[1] = AesEnc(s1[1], RC[11]);
            Mix256(s1, s2);

            s1[0] = AesEnc(s2[0], RC[12]);
            s1[1] = AesEnc(s2[1], RC[13]);
            s1[0] = AesEnc(s1[0], RC[14]);
            s1[1] = AesEnc(s1[1], RC[15]);
            Mix256(s1, s2);

            s1[0] = AesEnc(s2[0], RC[16]);
            s1[1] = AesEnc(s2[1], RC[17]);
            s1[0] = AesEnc(s1[0], RC[18]);
            s1[1] = AesEnc(s1[1], RC[19]);
            Mix256(s1, s2);

            s1[0] = Xor(s2[0], msg,  0);
            s1[1] = Xor(s2[1], msg, 16);

            Array.Copy(s1[0], 0, output, outOff     , 16);
            Array.Copy(s1[1], 0, output, outOff + 16, 16);

            return DIGEST_SIZE;
        }
#endif

        private static void Mix256(byte[][] s1, byte[][] s2)
        {
            Array.Copy(s1[0], 0, s2[0], 0, 4);
            Array.Copy(s1[1], 0, s2[0], 4, 4);
            Array.Copy(s1[0], 4, s2[0], 8, 4);
            Array.Copy(s1[1], 4, s2[0], 12, 4);

            Array.Copy(s1[0], 8, s2[1], 0, 4);
            Array.Copy(s1[1], 8, s2[1], 4, 4);
            Array.Copy(s1[0], 12, s2[1], 8, 4);
            Array.Copy(s1[1], 12, s2[1], 12, 4);
        }
    }
}
