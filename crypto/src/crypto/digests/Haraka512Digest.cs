using System;

using Org.BouncyCastle.Utilities;

namespace Org.BouncyCastle.Crypto.Digests
{
    public sealed class Haraka512Digest
        : HarakaBase
    {
        private readonly byte[] m_buf;
        private int m_bufPos;

        public Haraka512Digest()
        {
            m_buf = new byte[64];
            m_bufPos = 0;
        }

        public override string AlgorithmName => "Haraka-512";

        public override int GetByteLength() => 64;

        public override void Update(byte input)
        {
            if (m_bufPos > 64 - 1)
                throw new ArgumentException("total input cannot be more than 64 bytes");

            m_buf[m_bufPos++] = input;
        }

        public override void BlockUpdate(byte[] input, int inOff, int len)
        {
            if (m_bufPos > 64 - len)
                throw new ArgumentException("total input cannot be more than 64 bytes");

            Array.Copy(input, inOff, m_buf, m_bufPos, len);
            m_bufPos += len;
        }

#if NETCOREAPP2_1_OR_GREATER || NETSTANDARD2_1_OR_GREATER
        public override void BlockUpdate(ReadOnlySpan<byte> input)
        {
            if (m_bufPos > 64 - input.Length)
                throw new ArgumentException("total input cannot be more than 64 bytes");

            input.CopyTo(m_buf.AsSpan(m_bufPos));
            m_bufPos += input.Length;
        }
#endif

        public override int DoFinal(byte[] output, int outOff)
        {
#if NETCOREAPP2_1_OR_GREATER || NETSTANDARD2_1_OR_GREATER
            return DoFinal(output.AsSpan(outOff));
#else
            if (m_bufPos != 64)
                throw new ArgumentException("input must be exactly 64 bytes");

            if (output.Length - outOff < 32)
                throw new ArgumentException("output too short to receive digest");

            int rv = Haraka512256(m_buf, output, outOff);

            Reset();

            return rv;
#endif
        }

#if NETCOREAPP2_1_OR_GREATER || NETSTANDARD2_1_OR_GREATER
        public override int DoFinal(Span<byte> output)
        {
            if (m_bufPos != 64)
                throw new ArgumentException("input must be exactly 64 bytes");

            if (output.Length < 32)
                throw new ArgumentException("output too short to receive digest");

#if NETCOREAPP3_0_OR_GREATER
            if (Haraka512_X86.IsSupported)
            {
                Haraka512_X86.Hash(m_buf, output);
                Reset();
                return 32;
            }
#endif

            int rv = Haraka512256(m_buf, output);

            Reset();

            return rv;
        }
#endif

        public override void Reset()
        {
            m_bufPos = 0;
            Array.Clear(m_buf, 0, 64);
        }

#if NETCOREAPP2_1_OR_GREATER || NETSTANDARD2_1_OR_GREATER
        private static int Haraka512256(ReadOnlySpan<byte> msg, Span<byte> output)
        {
            byte[][] s1 = new byte[4][];
            s1[0] = new byte[16];
            s1[1] = new byte[16];
            s1[2] = new byte[16];
            s1[3] = new byte[16];
            byte[][] s2 = new byte[4][];
            s2[0] = new byte[16];
            s2[1] = new byte[16];
            s2[2] = new byte[16];
            s2[3] = new byte[16];

            msg[  ..16].CopyTo(s1[0]);
            msg[16..32].CopyTo(s1[1]);
            msg[32..48].CopyTo(s1[2]);
            msg[48..64].CopyTo(s1[3]);

            s1[0] = AesEnc(s1[0], RC[0]);
            s1[1] = AesEnc(s1[1], RC[1]);
            s1[2] = AesEnc(s1[2], RC[2]);
            s1[3] = AesEnc(s1[3], RC[3]);
            s1[0] = AesEnc(s1[0], RC[4]);
            s1[1] = AesEnc(s1[1], RC[5]);
            s1[2] = AesEnc(s1[2], RC[6]);
            s1[3] = AesEnc(s1[3], RC[7]);
            Mix512(s1, s2);

            s1[0] = AesEnc(s2[0], RC[8]);
            s1[1] = AesEnc(s2[1], RC[9]);
            s1[2] = AesEnc(s2[2], RC[10]);
            s1[3] = AesEnc(s2[3], RC[11]);
            s1[0] = AesEnc(s1[0], RC[12]);
            s1[1] = AesEnc(s1[1], RC[13]);
            s1[2] = AesEnc(s1[2], RC[14]);
            s1[3] = AesEnc(s1[3], RC[15]);
            Mix512(s1, s2);

            s1[0] = AesEnc(s2[0], RC[16]);
            s1[1] = AesEnc(s2[1], RC[17]);
            s1[2] = AesEnc(s2[2], RC[18]);
            s1[3] = AesEnc(s2[3], RC[19]);
            s1[0] = AesEnc(s1[0], RC[20]);
            s1[1] = AesEnc(s1[1], RC[21]);
            s1[2] = AesEnc(s1[2], RC[22]);
            s1[3] = AesEnc(s1[3], RC[23]);
            Mix512(s1, s2);

            s1[0] = AesEnc(s2[0], RC[24]);
            s1[1] = AesEnc(s2[1], RC[25]);
            s1[2] = AesEnc(s2[2], RC[26]);
            s1[3] = AesEnc(s2[3], RC[27]);
            s1[0] = AesEnc(s1[0], RC[28]);
            s1[1] = AesEnc(s1[1], RC[29]);
            s1[2] = AesEnc(s1[2], RC[30]);
            s1[3] = AesEnc(s1[3], RC[31]);
            Mix512(s1, s2);

            s1[0] = AesEnc(s2[0], RC[32]);
            s1[1] = AesEnc(s2[1], RC[33]);
            s1[2] = AesEnc(s2[2], RC[34]);
            s1[3] = AesEnc(s2[3], RC[35]);
            s1[0] = AesEnc(s1[0], RC[36]);
            s1[1] = AesEnc(s1[1], RC[37]);
            s1[2] = AesEnc(s1[2], RC[38]);
            s1[3] = AesEnc(s1[3], RC[39]);
            Mix512(s1, s2);

            Bytes.Xor(16, s2[0], msg      , s1[0]);
            Bytes.Xor(16, s2[1], msg[16..], s1[1]);
            Bytes.Xor(16, s2[2], msg[32..], s1[2]);
            Bytes.Xor(16, s2[3], msg[48..], s1[3]);

            s1[0].AsSpan(8, 8).CopyTo(output);
            s1[1].AsSpan(8, 8).CopyTo(output[8..]);
            s1[2].AsSpan(0, 8).CopyTo(output[16..]);
            s1[3].AsSpan(0, 8).CopyTo(output[24..]);

            return DIGEST_SIZE;
        }
#else
        private static int Haraka512256(byte[] msg, byte[] output, int outOff)
        {
            byte[][] s1 = new byte[4][];
            s1[0] = new byte[16];
            s1[1] = new byte[16];
            s1[2] = new byte[16];
            s1[3] = new byte[16];
            byte[][] s2 = new byte[4][];
            s2[0] = new byte[16];
            s2[1] = new byte[16];
            s2[2] = new byte[16];
            s2[3] = new byte[16];

            Array.Copy(msg,  0, s1[0], 0, 16);
            Array.Copy(msg, 16, s1[1], 0, 16);
            Array.Copy(msg, 32, s1[2], 0, 16);
            Array.Copy(msg, 48, s1[3], 0, 16);

            s1[0] = AesEnc(s1[0], RC[0]);
            s1[1] = AesEnc(s1[1], RC[1]);
            s1[2] = AesEnc(s1[2], RC[2]);
            s1[3] = AesEnc(s1[3], RC[3]);
            s1[0] = AesEnc(s1[0], RC[4]);
            s1[1] = AesEnc(s1[1], RC[5]);
            s1[2] = AesEnc(s1[2], RC[6]);
            s1[3] = AesEnc(s1[3], RC[7]);
            Mix512(s1, s2);

            s1[0] = AesEnc(s2[0], RC[8]);
            s1[1] = AesEnc(s2[1], RC[9]);
            s1[2] = AesEnc(s2[2], RC[10]);
            s1[3] = AesEnc(s2[3], RC[11]);
            s1[0] = AesEnc(s1[0], RC[12]);
            s1[1] = AesEnc(s1[1], RC[13]);
            s1[2] = AesEnc(s1[2], RC[14]);
            s1[3] = AesEnc(s1[3], RC[15]);
            Mix512(s1, s2);

            s1[0] = AesEnc(s2[0], RC[16]);
            s1[1] = AesEnc(s2[1], RC[17]);
            s1[2] = AesEnc(s2[2], RC[18]);
            s1[3] = AesEnc(s2[3], RC[19]);
            s1[0] = AesEnc(s1[0], RC[20]);
            s1[1] = AesEnc(s1[1], RC[21]);
            s1[2] = AesEnc(s1[2], RC[22]);
            s1[3] = AesEnc(s1[3], RC[23]);
            Mix512(s1, s2);

            s1[0] = AesEnc(s2[0], RC[24]);
            s1[1] = AesEnc(s2[1], RC[25]);
            s1[2] = AesEnc(s2[2], RC[26]);
            s1[3] = AesEnc(s2[3], RC[27]);
            s1[0] = AesEnc(s1[0], RC[28]);
            s1[1] = AesEnc(s1[1], RC[29]);
            s1[2] = AesEnc(s1[2], RC[30]);
            s1[3] = AesEnc(s1[3], RC[31]);
            Mix512(s1, s2);

            s1[0] = AesEnc(s2[0], RC[32]);
            s1[1] = AesEnc(s2[1], RC[33]);
            s1[2] = AesEnc(s2[2], RC[34]);
            s1[3] = AesEnc(s2[3], RC[35]);
            s1[0] = AesEnc(s1[0], RC[36]);
            s1[1] = AesEnc(s1[1], RC[37]);
            s1[2] = AesEnc(s1[2], RC[38]);
            s1[3] = AesEnc(s1[3], RC[39]);
            Mix512(s1, s2);

            Bytes.Xor(16, s2[0], 0, msg,  0, s1[0], 0);
            Bytes.Xor(16, s2[1], 0, msg, 16, s1[1], 0);
            Bytes.Xor(16, s2[2], 0, msg, 32, s1[2], 0);
            Bytes.Xor(16, s2[3], 0, msg, 48, s1[3], 0);

            Array.Copy(s1[0], 8, output, outOff, 8);
            Array.Copy(s1[1], 8, output, outOff + 8, 8);
            Array.Copy(s1[2], 0, output, outOff + 16, 8);
            Array.Copy(s1[3], 0, output, outOff + 24, 8);

            return DIGEST_SIZE;
        }
#endif

        private static void Mix512(byte[][] s1, byte[][] s2)
        {
            Array.Copy(s1[0], 12, s2[0], 0, 4);
            Array.Copy(s1[2], 12, s2[0], 4, 4);
            Array.Copy(s1[1], 12, s2[0], 8, 4);
            Array.Copy(s1[3], 12, s2[0], 12, 4);

            Array.Copy(s1[2], 0, s2[1], 0, 4);
            Array.Copy(s1[0], 0, s2[1], 4, 4);
            Array.Copy(s1[3], 0, s2[1], 8, 4);
            Array.Copy(s1[1], 0, s2[1], 12, 4);

            Array.Copy(s1[2], 4, s2[2], 0, 4);
            Array.Copy(s1[0], 4, s2[2], 4, 4);
            Array.Copy(s1[3], 4, s2[2], 8, 4);
            Array.Copy(s1[1], 4, s2[2], 12, 4);

            Array.Copy(s1[0], 8, s2[3], 0, 4);
            Array.Copy(s1[2], 8, s2[3], 4, 4);
            Array.Copy(s1[1], 8, s2[3], 8, 4);
            Array.Copy(s1[3], 8, s2[3], 12, 4);
        }
    }
}
