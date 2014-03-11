using System;

using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.Crypto.Utilities;

namespace Org.BouncyCastle.Crypto.Macs
{
    /// <summary>
    /// Implementation of SipHash as specified in "SipHash: a fast short-input PRF", by Jean-Philippe
    /// Aumasson and Daniel J. Bernstein (https://131002.net/siphash/siphash.pdf).
    /// </summary>
    /// <remarks>
    /// "SipHash is a family of PRFs SipHash-c-d where the integer parameters c and d are the number of
    /// compression rounds and the number of finalization rounds. A compression round is identical to a
    /// finalization round and this round function is called SipRound. Given a 128-bit key k and a
    /// (possibly empty) byte string m, SipHash-c-d returns a 64-bit value..."
    /// </remarks>
    public class SipHash
        : IMac
    {
        protected readonly int c, d;

        protected long k0, k1;
        protected long v0, v1, v2, v3, v4;

        protected long m = 0;
        protected int wordPos = 0;
        protected int wordCount = 0;

        /// <summary>SipHash-2-4</summary>
        public SipHash()
            : this(2, 4)
        {
        }

        /// <summary>SipHash-c-d</summary>
        /// <param name="c">the number of compression rounds</param>
        /// <param name="d">the number of finalization rounds</param>
        public SipHash(int c, int d)
        {
            this.c = c;
            this.d = d;
        }

        public virtual string AlgorithmName
        {
            get { return "SipHash-" + c + "-" + d; }
        }

        public virtual int GetMacSize()
        {
            return 8;
        }

        public virtual void Init(ICipherParameters parameters)
        {
            KeyParameter keyParameter = parameters as KeyParameter;
            if (keyParameter == null)
                throw new ArgumentException("must be an instance of KeyParameter", "parameters");
            byte[] key = keyParameter.GetKey();
            if (key.Length != 16)
                throw new ArgumentException("must be a 128-bit key", "parameters");

            this.k0 = (long)Pack.LE_To_UInt64(key, 0);
            this.k1 = (long)Pack.LE_To_UInt64(key, 8);

            Reset();
        }

        public virtual void Update(byte input)
        {
            m = (long)(((ulong)m >> 8) | ((ulong)input << 56));

            if (++wordPos == 8)
            {
                ProcessMessageWord();
                wordPos = 0;
            }
        }

        public virtual void BlockUpdate(byte[] input, int offset, int length)
        {
            int i = 0, fullWords = length & ~7;
            if (wordPos == 0)
            {
                for (; i < fullWords; i += 8)
                {
                    m = (long)Pack.LE_To_UInt64(input, offset + i);
                    ProcessMessageWord();
                }
                for (; i < length; ++i)
                {
                    m = (long)(((ulong)m >> 8) | ((ulong)input[offset + i] << 56));
                }
                wordPos = length - fullWords;
            }
            else
            {
                int bits = wordPos << 3;
                for (; i < fullWords; i += 8)
                {
                    ulong n = Pack.LE_To_UInt64(input, offset + i);
                    m = (long)(((ulong)m >> (64 - bits)) | (n << bits));
                    ProcessMessageWord();
                    m = (long)n;
                }
                for (; i < length; ++i)
                {
                    m = (long)(((ulong)m >> 8) | ((ulong)input[offset + i] << 56));

                    if (++wordPos == 8)
                    {
                        ProcessMessageWord();
                        wordPos = 0;
                    }
                }
            }
        }

        public virtual long DoFinal()
        {
            m = (long)(((ulong)m >> ((8 - wordPos) << 3)) | ((ulong)((wordCount << 3) + wordPos) << 56));

            ProcessMessageWord();

            v2 ^= 0xffL;

            ApplySipRounds(d);

            long result = v0 ^ v1 ^ v2 ^ v3;

            Reset();

            return result;
        }

        public virtual int DoFinal(byte[] output, int outOff)
        {
            long result = DoFinal();
            Pack.UInt64_To_LE((ulong)result, output, outOff);
            return 8;
        }

        public virtual void Reset()
        {
            v0 = k0 ^ 0x736f6d6570736575L;
            v1 = k1 ^ 0x646f72616e646f6dL;
            v2 = k0 ^ 0x6c7967656e657261L;
            v3 = k1 ^ 0x7465646279746573L;

            m = 0;
            wordPos = 0;
            wordCount = 0;
        }

        protected virtual void ProcessMessageWord()
        {
            ++wordCount;
            v3 ^= m;
            ApplySipRounds(c);
            v0 ^= m;
        }

        protected virtual void ApplySipRounds(int n)
        {
            for (int r = 0; r < n; ++r)
            {
                v0 += v1;
                v2 += v3;
                v1 = RotateLeft(v1, 13);
                v3 = RotateLeft(v3, 16);
                v1 ^= v0;
                v3 ^= v2;
                v0 = RotateLeft(v0, 32);
                v2 += v1;
                v0 += v3;
                v1 = RotateLeft(v1, 17);
                v3 = RotateLeft(v3, 21);
                v1 ^= v2;
                v3 ^= v0;
                v2 = RotateLeft(v2, 32);
            }
        }

        protected static long RotateLeft(long x, int n)
        {
            ulong ux = (ulong)x;
            ux = (ux << n) | (ux >> (64 - n));
            return (long)ux;
        }
    }
}
