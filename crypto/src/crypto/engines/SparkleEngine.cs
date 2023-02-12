using System;
using System.IO;

using Org.BouncyCastle.Crypto.Modes;
using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.Crypto.Utilities;
using Org.BouncyCastle.Utilities;

namespace Org.BouncyCastle.Crypto.Engines
{
    /// <summary>Sparkle v1.2, based on the current round 3 submission, https://sparkle-lwc.github.io/ .</summary>
    /// <remarks>
    /// Reference C implementation: https://github.com/cryptolu/sparkle.<br/>
    /// Specification:
    /// https://csrc.nist.gov/CSRC/media/Projects/lightweight-cryptography/documents/finalist-round/updated-spec-doc/sparkle-spec-final.pdf .
    /// </remarks>
    public class SparkleEngine
        : IAeadBlockCipher
    {
        public enum SparkleParameters
        {
            SCHWAEMM128_128,
            SCHWAEMM256_128,
            SCHWAEMM192_192,
            SCHWAEMM256_256
        }
        private string algorithmName;
        private bool forEncryption;
        private readonly uint[] state;
        private readonly uint[] k;
        private readonly uint[] npub;
        private byte[] tag;
        private bool initialised;
        private bool encrypted;
        private bool aadFinished;
        private readonly MemoryStream aadData = new MemoryStream();
        private readonly MemoryStream message = new MemoryStream();
        private readonly int SCHWAEMM_KEY_LEN;
        private readonly int SCHWAEMM_NONCE_LEN;
        private readonly int SPARKLE_STEPS_SLIM;
        private readonly int SPARKLE_STEPS_BIG;
        private readonly int KEY_BYTES;
        private readonly int KEY_WORDS;
        private readonly int TAG_WORDS;
        private readonly int TAG_BYTES;
        private readonly int STATE_BRANS;
        private readonly int STATE_WORDS;
        private readonly int RATE_WORDS;
        private readonly int RATE_BYTES;
        private readonly int CAP_WORDS;
        private readonly uint _A0;
        private readonly uint _A1;
        private readonly uint _M2;
        private readonly uint _M3;

        public SparkleEngine(SparkleParameters sparkleParameters)
        {
            int SPARKLE_STATE;
            int SCHWAEMM_TAG_LEN;
            int SPARKLE_CAPACITY;
            switch (sparkleParameters)
            {
                case SparkleParameters.SCHWAEMM128_128:
                    SCHWAEMM_KEY_LEN = 128;
                    SCHWAEMM_NONCE_LEN = 128;
                    SCHWAEMM_TAG_LEN = 128;
                    SPARKLE_STATE = 256;
                    SPARKLE_CAPACITY = 128;
                    SPARKLE_STEPS_SLIM = 7;
                    SPARKLE_STEPS_BIG = 10;
                    algorithmName = "SCHWAEMM128-128";
                    break;
                case SparkleParameters.SCHWAEMM256_128:
                    SCHWAEMM_KEY_LEN = 128;
                    SCHWAEMM_NONCE_LEN = 256;
                    SCHWAEMM_TAG_LEN = 128;
                    SPARKLE_STATE = 384;
                    SPARKLE_CAPACITY = 128;
                    SPARKLE_STEPS_SLIM = 7;
                    SPARKLE_STEPS_BIG = 11;
                    algorithmName = "SCHWAEMM256-128";
                    break;
                case SparkleParameters.SCHWAEMM192_192:
                    SCHWAEMM_KEY_LEN = 192;
                    SCHWAEMM_NONCE_LEN = 192;
                    SCHWAEMM_TAG_LEN = 192;
                    SPARKLE_STATE = 384;
                    SPARKLE_CAPACITY = 192;
                    SPARKLE_STEPS_SLIM = 7;
                    SPARKLE_STEPS_BIG = 11;
                    algorithmName = "SCHWAEMM192-192";
                    break;
                case SparkleParameters.SCHWAEMM256_256:
                    SCHWAEMM_KEY_LEN = 256;
                    SCHWAEMM_NONCE_LEN = 256;
                    SCHWAEMM_TAG_LEN = 256;
                    SPARKLE_STATE = 512;
                    SPARKLE_CAPACITY = 256;
                    SPARKLE_STEPS_SLIM = 8;
                    SPARKLE_STEPS_BIG = 12;
                    algorithmName = "SCHWAEMM256-256";
                    break;
                default:
                    throw new ArgumentException("Invalid definition of SCHWAEMM instance");
            }
            KEY_WORDS = SCHWAEMM_KEY_LEN >> 5;
            KEY_BYTES = SCHWAEMM_KEY_LEN >> 3;
            TAG_WORDS = SCHWAEMM_TAG_LEN >> 5;
            TAG_BYTES = SCHWAEMM_TAG_LEN >> 3;
            STATE_BRANS = SPARKLE_STATE >> 6;
            STATE_WORDS = SPARKLE_STATE >> 5;
            RATE_WORDS = SCHWAEMM_NONCE_LEN >> 5;
            RATE_BYTES = SCHWAEMM_NONCE_LEN >> 3;
            int CAP_BRANS = SPARKLE_CAPACITY >> 6;
            CAP_WORDS = SPARKLE_CAPACITY >> 5;
            _A0 = ((((1u << CAP_BRANS))) << 24);
            _A1 = (((1u ^ (1u << CAP_BRANS))) << 24);
            _M2 = (((2u ^ (1u << CAP_BRANS))) << 24);
            _M3 = (((3u ^ (1u << CAP_BRANS))) << 24);
            state = new uint[STATE_WORDS];
            tag = new byte[TAG_BYTES];
            k = new uint[KEY_WORDS];
            npub = new uint[RATE_WORDS];
            initialised = false;
        }

        private uint ROT(uint x, int n)
        {
            return (((x) >> n) | ((x) << (32 - n)));
        }

        private uint ELL(uint x)
        {
            return ROT(((x) ^ ((x) << 16)), 16);
        }

        private static readonly uint[] RCON = {0xB7E15162, 0xBF715880, 0x38B4DA56, 0x324E7738, 0xBB1185EB, 0x4F7C7B57,
        0xCFBFA1C8, 0xC2B3293D};

        void sparkle_opt(uint[] state, int brans, int steps)
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
                    state[j] += ROT(state[j + 1], 31);
                    state[j + 1] ^= ROT(state[j], 24);
                    state[j] ^= rc;
                    state[j] += ROT(state[j + 1], 17);
                    state[j + 1] ^= ROT(state[j], 17);
                    state[j] ^= rc;
                    state[j] += state[j + 1];
                    state[j + 1] ^= ROT(state[j], 31);
                    state[j] ^= rc;
                    state[j] += ROT(state[j + 1], 24);
                    state[j + 1] ^= ROT(state[j], 16);
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

        private int CAP_INDEX(int i)
        {
            if (RATE_WORDS > CAP_WORDS)
            {
                return i & (CAP_WORDS - 1);
            }
            return i;
        }

        // The ProcessAssocData function absorbs the associated data, which becomes
        // only authenticated but not encrypted, into the state (in blocks of size
        // RATE_BYTES). Note that this function MUST NOT be called when the length of
        // the associated data is 0.
        void ProcessAssocData(uint[] state)
        {
            int inlen = (int)aadData.Length;
            if (aadFinished || inlen == 0)
            {
                return;
            }
            aadFinished = true;
            byte[] input = aadData.GetBuffer();
            // Main Authentication Loop
            int inOff = 0, i, j;
            uint tmp;
            uint[] in32 = Pack.LE_To_UInt32(input, inOff, input.Length >> 2);
            while (inlen > RATE_BYTES)
            {
                // combined Rho and rate-whitening operation
                // Rho and rate-whitening for the authentication of associated data. The third
                // parameter indicates whether the uint8_t-pointer 'in' is properly aligned to
                // permit casting to a int-pointer. If this is the case then array 'in' is
                // processed directly, otherwise it is first copied to an aligned buffer.
                for (i = 0, j = RATE_WORDS / 2; i < RATE_WORDS / 2; i++, j++)
                {
                    tmp = state[i];
                    state[i] = state[j] ^ in32[i + (inOff >> 2)] ^ state[RATE_WORDS + i];
                    state[j] ^= tmp ^ in32[j + (inOff >> 2)] ^ state[RATE_WORDS + CAP_INDEX(j)];
                }
                // execute SPARKLE with slim number of steps
                sparkle_opt(state, STATE_BRANS, SPARKLE_STEPS_SLIM);
                inlen -= RATE_BYTES;
                inOff += RATE_BYTES;
            }
            // Authentication of Last Block
            // addition of ant A0 or A1 to the state
            state[STATE_WORDS - 1] ^= ((inlen < RATE_BYTES) ? _A0 : _A1);
            // combined Rho and rate-whitening (incl. padding)
            // Rho and rate-whitening for the authentication of the last associated-data
            // block. Since this last block may require padding, it is always copied to a buffer.
            uint[] buffer = new uint[RATE_WORDS];
            for (i = 0; i < inlen; ++i)
            {
                buffer[i >> 2] |= (uint)input[inOff++] << ((i & 3) << 3);
            }
            if (inlen < RATE_BYTES)
            {  // padding
                buffer[i >> 2] |= 0x80u << ((i & 3) << 3);
            }
            for (i = 0, j = RATE_WORDS / 2; i < RATE_WORDS / 2; i++, j++)
            {
                tmp = state[i];
                state[i] = state[j] ^ buffer[i] ^ state[RATE_WORDS + i];
                state[j] ^= tmp ^ buffer[j] ^ state[RATE_WORDS + CAP_INDEX(j)];
            }
            // execute SPARKLE with big number of steps
            sparkle_opt(state, STATE_BRANS, SPARKLE_STEPS_BIG);
        }

        // The ProcessPlainText function encrypts the plaintext (input blocks of size
        // RATE_BYTES) and generates the respective ciphertext. The uint8_t-array 'input'
        // contains the plaintext and the ciphertext is written to uint8_t-array 'output'
        // ('input' and 'output' can be the same array, i.e. they can have the same start
        // address). Note that this function MUST NOT be called when the length of the
        // plaintext is 0.
        private int ProcessPlainText(uint[] state, byte[] output, byte[] input, int inOff, int inlen)
        {
            // Main Encryption Loop
            int outOff = 0, i, j;
            uint tmp1, tmp2;
            uint[] in32 = Pack.LE_To_UInt32(input, inOff, input.Length >> 2);
            uint[] out32 = new uint[output.Length >> 2];
            int rv = 0;
            while (inlen > RATE_BYTES)
            {
                // combined Rho and rate-whitening operation
                // Rho and rate-whitening for the encryption of plaintext. The third parameter
                // indicates whether the uint8_t-pointers 'input' and 'output' are properly aligned
                // to permit casting to int-pointers. If this is the case then array 'input'
                // and 'output' are processed directly, otherwise 'input' is copied to an aligned buffer.
                for (i = 0, j = RATE_WORDS / 2; i < RATE_WORDS / 2; i++, j++)
                {
                    tmp1 = state[i];
                    tmp2 = state[j];
                    if (forEncryption)
                    {
                        state[i] = state[j] ^ in32[i + (inOff >> 2)] ^ state[RATE_WORDS + i];
                        state[j] ^= tmp1 ^ in32[j + (inOff >> 2)] ^ state[RATE_WORDS + CAP_INDEX(j)];
                    }
                    else
                    {
                        state[i] ^= state[j] ^ in32[i + (inOff >> 2)] ^ state[RATE_WORDS + i];
                        state[j] = tmp1 ^ in32[j + (inOff >> 2)] ^ state[RATE_WORDS + CAP_INDEX(j)];
                    }
                    out32[i] = in32[i] ^ tmp1;
                    out32[j] = in32[j] ^ tmp2;
                }
                Pack.UInt32_To_LE(out32, 0, RATE_WORDS, output, outOff);
                // execute SPARKLE with slim number of steps
                sparkle_opt(state, STATE_BRANS, SPARKLE_STEPS_SLIM);
                inlen -= RATE_BYTES;
                outOff += RATE_BYTES;
                inOff += RATE_BYTES;
                rv += RATE_BYTES;
                encrypted = true;
            }
            return rv;
        }

        public void Init(bool forEncryption, ICipherParameters param)
        {
            this.forEncryption = forEncryption;
            if (!(param is ParametersWithIV))
            {
                throw new ArgumentException(algorithmName + " init parameters must include an IV");
            }

            ParametersWithIV ivParams = (ParametersWithIV)param;
            byte[] iv = ivParams.GetIV();

            if (iv == null || iv.Length != SCHWAEMM_NONCE_LEN >> 3)
            {
                throw new ArgumentException(algorithmName + " requires exactly 16 bytes of IV");
            }
            Pack.LE_To_UInt32(iv, 0, npub, 0, RATE_WORDS);

            if (!(ivParams.Parameters is KeyParameter))
            {
                throw new ArgumentException(algorithmName + " init parameters must include a key");
            }

            KeyParameter key = (KeyParameter)ivParams.Parameters;
            byte[] key8 = key.GetKey();
            if (key8.Length != SCHWAEMM_KEY_LEN >> 3)
            {
                throw new ArgumentException(algorithmName + " key must be 128 bits long");
            }
            Pack.LE_To_UInt32(key8, 0, k, 0, KEY_WORDS);
            initialised = true;
            reset(false);
        }

        public void ProcessAadByte(byte input)
        {
            if (encrypted)
            {
                throw new ArgumentException(algorithmName + ": AAD cannot be added after reading a full block(" +
                    GetBlockSize() + " bytes) of input for " + (forEncryption ? "encryption" : "decryption"));
            }
            aadData.Write(new byte[] { input }, 0, 1);
        }


        public void ProcessAadBytes(byte[] input, int inOff, int len)
        {
            if (encrypted)
            {
                throw new ArgumentException(algorithmName + ": AAD cannot be added after reading a full block(" +
                    GetBlockSize() + " bytes) of input for " + (forEncryption ? "encryption" : "decryption"));
            }
            if (inOff + len > input.Length)
            {
                throw new DataLengthException(algorithmName + " input buffer too short");
            }
            aadData.Write(input, inOff, len);
        }


        public int ProcessByte(byte input, byte[] output, int outOff)
        {
            return ProcessBytes(new byte[] { input }, 0, 1, output, outOff);
        }


        public int ProcessBytes(byte[] input, int inOff, int len, byte[] output, int outOff)
        {
            if (!initialised)
            {
                throw new ArgumentException(algorithmName + " Need call init function before encryption/decryption");
            }
            if (inOff + len > input.Length)
            {
                throw new DataLengthException(algorithmName + " input buffer too short");
            }
            message.Write(input, inOff, len);
            len = 0;
            if ((forEncryption && (int)message.Length > GetBlockSize()) ||
                (!forEncryption && (int)message.Length - TAG_BYTES > GetBlockSize()))
            {
                len = ((int)message.Length - (forEncryption ? 0 : TAG_BYTES));
                if (len / RATE_BYTES * RATE_BYTES + outOff > output.Length)
                {
                    throw new OutputLengthException(algorithmName + " output buffer is too short");
                }
                byte[] m = message.GetBuffer();
                ProcessAssocData(state);
                if (len != 0)
                {
                    len = ProcessPlainText(state, output, m, 0, len);
                }
                int mlen = (int)message.Length;
                message.SetLength(0);
                message.Write(m, len, mlen - len);
            }
            return len;
        }


        public int DoFinal(byte[] output, int outOff)
        {
            if (!initialised)
            {
                throw new ArgumentException(algorithmName + " needs call init function before dofinal");
            }
            int inlen = (int)message.Length - (forEncryption ? 0 : TAG_BYTES);
            if ((forEncryption && inlen + TAG_BYTES + outOff > output.Length) ||
                (!forEncryption && inlen + outOff > output.Length))
            {
                throw new OutputLengthException("output buffer is too short");
            }
            ProcessAssocData(state);
            int i, j;
            uint tmp1, tmp2;
            byte[] input = message.GetBuffer();
            int inOff = 0;
            if (encrypted || inlen != 0)
            {
                // Encryption of Last Block
                // addition of ant M2 or M3 to the state
                state[STATE_WORDS - 1] ^= ((inlen < RATE_BYTES) ? _M2 : _M3);
                // combined Rho and rate-whitening (incl. padding)
                // Rho and rate-whitening for the encryption of the last plaintext block. Since
                // this last block may require padding, it is always copied to a buffer.
                uint[] buffer = new uint[RATE_WORDS];
                for (i = 0; i < inlen; ++i)
                {
                    buffer[i >> 2] |= (input[inOff++] & 0xffu) << ((i & 3) << 3);
                }
                if (inlen < RATE_BYTES)
                {
                    if (!forEncryption)
                    {
                        int tmp = (i & 3) << 3;
                        buffer[i >> 2] |= (state[i >> 2] >> tmp) << tmp;
                        tmp = (i >> 2) + 1;
                        Array.Copy(state, tmp, buffer, tmp, RATE_WORDS - tmp);
                    }
                    buffer[i >> 2] ^= 0x80u << ((i & 3) << 3);
                }
                for (i = 0, j = RATE_WORDS / 2; i < RATE_WORDS / 2; i++, j++)
                {
                    tmp1 = state[i];
                    tmp2 = state[j];
                    if (forEncryption)
                    {
                        state[i] = state[j] ^ buffer[i] ^ state[RATE_WORDS + i];
                        state[j] ^= tmp1 ^ buffer[j] ^ state[RATE_WORDS + CAP_INDEX(j)];
                    }
                    else
                    {
                        state[i] ^= state[j] ^ buffer[i] ^ state[RATE_WORDS + i];
                        state[j] = tmp1 ^ buffer[j] ^ state[RATE_WORDS + CAP_INDEX(j)];
                    }
                    buffer[i] ^= tmp1;
                    buffer[j] ^= tmp2;
                }
                for (i = 0; i < inlen; ++i)
                {
                    output[outOff++] = (byte)(buffer[i >> 2] >> ((i & 3) << 3));
                }
                // execute SPARKLE with big number of steps
                sparkle_opt(state, STATE_BRANS, SPARKLE_STEPS_BIG);
            }
            // add key to the capacity-part of the state
            for (i = 0; i < KEY_WORDS; i++)
            {
                state[RATE_WORDS + i] ^= k[i];
            }
            tag = new byte[TAG_BYTES];
            Pack.UInt32_To_LE(state, RATE_WORDS, TAG_WORDS, tag, 0);
            if (forEncryption)
            {
                Array.Copy(tag, 0, output, outOff, TAG_BYTES);
                inlen += TAG_BYTES;
            }
            else
            {
                if (!Arrays.FixedTimeEquals(TAG_BYTES, tag, 0, input, inlen))
                    throw new InvalidCipherTextException("mac check in " + AlgorithmName + " failed");
            }
            reset(false);
            return inlen;
        }

        public byte[] GetMac()
        {
            return tag;
        }


        public int GetUpdateOutputSize(int len)
        {
            return len;
        }


        public int GetOutputSize(int len)
        {
            return len + TAG_BYTES;
        }


        public void Reset()
        {
            if (!initialised)
            {
                throw new ArgumentException(algorithmName + " needs call init function before reset");
            }
            reset(true);
        }

        private void reset(bool clearMac)
        {
            if (clearMac)
            {
                tag = null;
            }
            // The Initialize function loads nonce and key into the state and executes the
            // SPARKLE permutation with the big number of steps.
            // load nonce into the rate-part of the state
            Array.Copy(npub, 0, state, 0, RATE_WORDS);
            // load key into the capacity-part of the sate
            Array.Copy(k, 0, state, RATE_WORDS, KEY_WORDS);
            // execute SPARKLE with big number of steps
            sparkle_opt(state, STATE_BRANS, SPARKLE_STEPS_BIG);
            aadData.SetLength(0);
            message.SetLength(0);
            encrypted = false;
            aadFinished = false;
        }
        public string AlgorithmName => algorithmName;

        public IBlockCipher UnderlyingCipher => throw new NotImplementedException();

        public int GetBlockSize()
        {
            return RATE_BYTES;
        }



#if NETCOREAPP2_1_OR_GREATER || NETSTANDARD2_1_OR_GREATER
        public void ProcessAadBytes(ReadOnlySpan<byte> input)
        {
            aadData.Write(input);
        }

        public int ProcessByte(byte input, Span<byte> output)
        {
            byte[] rv = new byte[1];
            int len = ProcessBytes(new byte[] { input }, 0, 1, rv, 0);
            rv.AsSpan(0, len).CopyTo(output);
            return len;

        }

        public int ProcessBytes(ReadOnlySpan<byte> input, Span<byte> output)
        {
            byte[] rv = new byte[input.Length];
            int len = ProcessBytes(input.ToArray(), 0, rv.Length, rv, 0);
            rv.AsSpan(0, len).CopyTo(output);
            return len;
        }

        public int DoFinal(Span<byte> output)
        {
            byte[] rv;
            if (forEncryption)
            {
                rv = new byte[message.Length + TAG_BYTES];
            }
            else
            {
                rv = new byte[message.Length - TAG_BYTES];
            }
            int len = DoFinal(rv, 0);
            rv.AsSpan(0, len).CopyTo(output);
            return rv.Length;

        }
#endif

        public int GetKeyBytesSize()
        {
            return KEY_BYTES;
        }

        public int GetIVBytesSize()
        {
            return RATE_BYTES;
        }
    }
}

