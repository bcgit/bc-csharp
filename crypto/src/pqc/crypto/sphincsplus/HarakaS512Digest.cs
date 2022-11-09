﻿using System;

namespace Org.BouncyCastle.Pqc.Crypto.SphincsPlus
{
    /**
    * Haraka-512 v2, https://eprint.iacr.org/2016/098.pdf
    * <p>
    * Haraka512-256 with reference to Python Reference Impl from: https://github.com/sphincs/sphincsplus
    * </p>
    */
    internal sealed class HarakaS512Digest
        : HarakaSBase
    {
        public HarakaS512Digest(HarakaSBase harakaSBase)
        {
            haraka512_rc = harakaSBase.haraka512_rc;
        }

        public string AlgorithmName => "HarakaS-512";

        public int GetDigestSize()
        {
            return 32;
        }

        public void Update(byte input)
        {
            if (off > 64 - 1)
                throw new ArgumentException("total input cannot be more than 64 bytes");

            buffer[off++] = input;
        }

        public void BlockUpdate(byte[] input, int inOff, int len)
        {
            if (off > 64 - len)
                throw new ArgumentException("total input cannot be more than 64 bytes");

            Array.Copy(input, inOff, buffer, off, len);
            off += len;
        }

#if NETCOREAPP2_1_OR_GREATER || NETSTANDARD2_1_OR_GREATER
        public void BlockUpdate(ReadOnlySpan<byte> input)
        {
            if (off > 64 - input.Length)
                throw new ArgumentException("total input cannot be more than 64 bytes");

            input.CopyTo(buffer.AsSpan(off));
            off += input.Length;
        }
#endif

        public int DoFinal(byte[] output, int outOff)
        {
            // TODO Check received all 64 bytes of input?

            byte[] s = new byte[64];
            Haraka512Perm(s);
            Xor(s,  8, buffer,  8, output, outOff     ,  8);
            Xor(s, 24, buffer, 24, output, outOff +  8, 16);
            Xor(s, 48, buffer, 48, output, outOff + 24,  8);

            Reset();

            return 32;
        }

#if NETCOREAPP2_1_OR_GREATER || NETSTANDARD2_1_OR_GREATER
        public int DoFinal(Span<byte> output)
        {
            // TODO Check received all 64 bytes of input?

            Span<byte> s = stackalloc byte[64];
            Haraka512Perm(s);
            Xor(s[8..], buffer.AsSpan(8), output[..8]);
            Xor(s[24..], buffer.AsSpan(24), output[8..24]);
            Xor(s[48..], buffer.AsSpan(48), output[24..32]);

            Reset();

            return 32;
        }
#endif
    }
}
