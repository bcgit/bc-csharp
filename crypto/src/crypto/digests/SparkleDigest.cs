using System;
using System.IO;

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
        private readonly MemoryStream message = new MemoryStream();
        private readonly int DIGEST_BYTES;
        private readonly int SPARKLE_STEPS_SLIM;
        private readonly int SPARKLE_STEPS_BIG;
        private readonly int STATE_BRANS;
        private readonly int STATE_UINTS;

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
            STATE_BRANS = STATE_UINTS >> 1;
            state = new uint[STATE_UINTS];
        }

        public string AlgorithmName => algorithmName;

        public int GetDigestSize() => DIGEST_BYTES;

        public int GetByteLength() => RATE_BYTES;

        public void Update(byte input)
        {
            message.WriteByte(input);
        }

        public void BlockUpdate(byte[] input, int inOff, int inLen)
        {
            Check.DataLength(input, inOff, inLen, "input buffer too short");

            message.Write(input, inOff, inLen);
        }

#if NETCOREAPP2_1_OR_GREATER || NETSTANDARD2_1_OR_GREATER
        public void BlockUpdate(ReadOnlySpan<byte> input)
        {
            message.Write(input);
        }
#endif

        public int DoFinal(byte[] output, int outOff)
        {
            Check.OutputLength(output, outOff, DIGEST_BYTES, "output buffer too short");

            byte[] input = message.GetBuffer();
            int inlen = (int)message.Length, i, inOff = 0;
            uint tmpx, tmpy;
            // Main Hashing Loop
            uint[] in32 = Pack.LE_To_UInt32(input, 0, inlen >> 2);
            while (inlen > RATE_BYTES)
            {
                // addition of a buffer block to the state
                tmpx = 0;
                tmpy = 0;
                for (i = 0; i < RATE_UINTS; i += 2)
                {
                    tmpx ^= in32[i + (inOff >> 2)];
                    tmpy ^= in32[i + 1 + (inOff >> 2)];
                }
                tmpx = ELL(tmpx);
                tmpy = ELL(tmpy);
                for (i = 0; i < RATE_UINTS; i += 2)
                {
                    state[i] ^= (in32[i + (inOff >> 2)] ^ tmpy);
                    state[i + 1] ^= (in32[i + 1 + (inOff >> 2)] ^ tmpx);
                }
                for (i = RATE_UINTS; i < (STATE_UINTS / 2); i += 2)
                {
                    state[i] ^= tmpy;
                    state[i + 1] ^= tmpx;
                }
                // execute SPARKLE with slim number of steps
                sparkle_opt(state, STATE_BRANS, SPARKLE_STEPS_SLIM);
                inlen -= RATE_BYTES;
                inOff += RATE_BYTES;
            }
            // Hashing of Last Block
            // addition of constant M1 or M2 to the state
            state[STATE_BRANS - 1] ^= ((inlen < RATE_BYTES) ? (1u << 24) : (1u << 25));
            // addition of last msg block (incl. padding)
            uint[] buffer = new uint[RATE_UINTS];
            for (i = 0; i < inlen; ++i)
            {
                buffer[i >> 2] |= (input[inOff++] & 0xffu) << ((i & 3) << 3);
            }
            if (inlen < RATE_BYTES)
            {  // padding
                buffer[i >> 2] |= 0x80u << ((i & 3) << 3);
            }
            tmpx = 0;
            tmpy = 0;
            for (i = 0; i < RATE_UINTS; i += 2)
            {
                tmpx ^= buffer[i];
                tmpy ^= buffer[i + 1];
            }
            tmpx = ELL(tmpx);
            tmpy = ELL(tmpy);
            for (i = 0; i < RATE_UINTS; i += 2)
            {
                state[i] ^= (buffer[i] ^ tmpy);
                state[i + 1] ^= (buffer[i + 1] ^ tmpx);
            }
            for (i = RATE_UINTS; i < (STATE_UINTS / 2); i += 2)
            {
                state[i] ^= tmpy;
                state[i + 1] ^= tmpx;
            }
            // execute SPARKLE with big number of steps
            sparkle_opt(state, STATE_BRANS, SPARKLE_STEPS_BIG);
            Pack.UInt32_To_LE(state, 0, RATE_UINTS, output, outOff);
            int outlen = RATE_BYTES;
            outOff += RATE_BYTES;
            while (outlen < DIGEST_BYTES)
            {
                sparkle_opt(state, STATE_BRANS, SPARKLE_STEPS_SLIM);
                Pack.UInt32_To_LE(state, 0, RATE_UINTS, output, outOff);
                outlen += RATE_BYTES;
                outOff += RATE_BYTES;
            }
            Reset();
            return DIGEST_BYTES;
        }

#if NETCOREAPP2_1_OR_GREATER || NETSTANDARD2_1_OR_GREATER
        public int DoFinal(Span<byte> output)
        {
            byte[] rv = new byte[DIGEST_BYTES];
            DoFinal(rv, 0);
            rv.AsSpan(0, rv.Length).CopyTo(output);
            return DIGEST_BYTES;
        }
#endif

        public void Reset()
        {
            message.SetLength(0);
            Arrays.Fill(state, 0U);
        }

        private void sparkle_opt(uint[] state, int brans, int steps)
        {
            uint i, j, rc, tmpx, tmpy, x0, y0;
            for (i = 0; i < steps; i++)
            {
                // Add round ant
                state[1] ^= RCON[i & 7];
                state[3] ^= i;
                // ARXBOX layer
                for (j = 0; j < 2 * brans; j += 2)
                {
                    rc = RCON[j >> 1];
                    state[j] += Integers.RotateRight(state[j + 1], 31);
                    state[j + 1] ^= Integers.RotateRight(state[j], 24);
                    state[j] ^= rc;
                    state[j] += Integers.RotateRight(state[j + 1], 17);
                    state[j + 1] ^= Integers.RotateRight(state[j], 17);
                    state[j] ^= rc;
                    state[j] += state[j + 1];
                    state[j + 1] ^= Integers.RotateRight(state[j], 31);
                    state[j] ^= rc;
                    state[j] += Integers.RotateRight(state[j + 1], 24);
                    state[j + 1] ^= Integers.RotateRight(state[j], 16);
                    state[j] ^= rc;
                }
                // Linear layer
                tmpx = x0 = state[0];
                tmpy = y0 = state[1];
                for (j = 2; j < brans; j += 2)
                {
                    tmpx ^= state[j];
                    tmpy ^= state[j + 1];
                }
                tmpx = ELL(tmpx);
                tmpy = ELL(tmpy);
                for (j = 2; j < brans; j += 2)
                {
                    state[j - 2] = state[j + brans] ^ state[j] ^ tmpy;
                    state[j + brans] = state[j];
                    state[j - 1] = state[j + brans + 1] ^ state[j + 1] ^ tmpx;
                    state[j + brans + 1] = state[j + 1];
                }
                state[brans - 2] = state[brans] ^ x0 ^ tmpy;
                state[brans] = x0;
                state[brans - 1] = state[brans + 1] ^ y0 ^ tmpx;
                state[brans + 1] = y0;
            }
        }

        private static uint ELL(uint x)
        {
            return Integers.RotateRight(x ^ (x << 16), 16);
        }
    }
}
