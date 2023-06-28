using System;

namespace Org.BouncyCastle.Pqc.Crypto.SphincsPlus
{
    internal sealed class HarakaS256Digest
        : HarakaSBase
    {
        public HarakaS256Digest(HarakaSXof harakaSXof)
        {
            haraka256_rc = harakaSXof.haraka256_rc;
        }

        public string AlgorithmName => "HarakaS-256";

        public int GetDigestSize()
        {
            return 32;
        }

        public void Update(byte input)
        {
            if (off > 32 - 1)
                throw new ArgumentException("total input cannot be more than 32 bytes");

            buffer[off++] = input;
        }

        public void BlockUpdate(byte[] input, int inOff, int len)
        {
            if (off > 32 - len)
                throw new ArgumentException("total input cannot be more than 32 bytes");

            Array.Copy(input, inOff, buffer, off, len);
            off += len;
        }

#if NETCOREAPP2_1_OR_GREATER || NETSTANDARD2_1_OR_GREATER
        public void BlockUpdate(ReadOnlySpan<byte> input)
        {
            if (off > 32 - input.Length)
                throw new ArgumentException("total input cannot be more than 32 bytes");

            input.CopyTo(buffer.AsSpan(off));
            off += input.Length;
        }
#endif

        public int DoFinal(byte[] output, int outOff)
        {
            // TODO Check received all 32 bytes of input?

            byte[] s = new byte[32];
            Haraka256Perm(s);
            Xor(s, 0, buffer, 0, output, outOff, 32);

            Reset();

            return 32;
        }

#if NETCOREAPP2_1_OR_GREATER || NETSTANDARD2_1_OR_GREATER
        public int DoFinal(Span<byte> output)
        {
            // TODO Check received all 32 bytes of input?

            Span<byte> s = stackalloc byte[32];
            Haraka256Perm(s);
            Xor(s, buffer, output[..32]);

            Reset();

            return 32;
        }
#endif
    }
}
