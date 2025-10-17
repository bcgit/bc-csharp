using System;
using System.Diagnostics;
#if NETSTANDARD1_0_OR_GREATER || NETCOREAPP1_0_OR_GREATER
using System.Runtime.CompilerServices;
#endif
#if NETCOREAPP3_0_OR_GREATER
using System.Buffers.Binary;
using System.Runtime.InteropServices;
using System.Runtime.Intrinsics;
using System.Runtime.Intrinsics.X86;
#endif

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
    public sealed class SparkleEngine
        : IAeadCipher
    {
        public enum SparkleParameters
        {
            SCHWAEMM128_128,
            SCHWAEMM256_128,
            SCHWAEMM192_192,
            SCHWAEMM256_256
        }

        private enum State
        {
            Uninitialized  = 0,
            EncInit        = 1,
            EncAad         = 2,
            EncData        = 3,
            EncFinal       = 4,
            DecInit        = 5,
            DecAad         = 6,
            DecData        = 7,
            DecFinal       = 8,
        }

        private static readonly uint[] RCON = { 0xB7E15162U, 0xBF715880U, 0x38B4DA56U, 0x324E7738U, 0xBB1185EBU,
            0x4F7C7B57U, 0xCFBFA1C8U, 0xC2B3293DU };

        private string algorithmName;
        private readonly uint[] state;
        private readonly uint[] k;
        private readonly uint[] npub;
        private byte[] tag;
        private bool encrypted;
        private State m_state = State.Uninitialized;
        private byte[] initialAssociatedText;

        private readonly int m_bufferSizeDecrypt;
        private readonly byte[] m_buf;
        private int m_bufPos = 0;

        private readonly int SCHWAEMM_KEY_LEN;
        private readonly int SCHWAEMM_NONCE_LEN;
        private readonly int SPARKLE_STEPS_SLIM;
        private readonly int SPARKLE_STEPS_BIG;
        private readonly int KEY_BYTES;
        private readonly int KEY_WORDS;
        private readonly int TAG_WORDS;
        private readonly int TAG_BYTES;
        private readonly int STATE_WORDS;
        private readonly int RATE_WORDS;
        private readonly int RATE_BYTES;
        private readonly int CAP_MASK;
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
            STATE_WORDS = SPARKLE_STATE >> 5;
            RATE_WORDS = SCHWAEMM_NONCE_LEN >> 5;
            RATE_BYTES = SCHWAEMM_NONCE_LEN >> 3;
            int CAP_BRANS = SPARKLE_CAPACITY >> 6;
            int CAP_WORDS = SPARKLE_CAPACITY >> 5;
            CAP_MASK = RATE_WORDS > CAP_WORDS ? CAP_WORDS - 1 : -1;
            _A0 = ((((1u << CAP_BRANS))) << 24);
            _A1 = (((1u ^ (1u << CAP_BRANS))) << 24);
            _M2 = (((2u ^ (1u << CAP_BRANS))) << 24);
            _M3 = (((3u ^ (1u << CAP_BRANS))) << 24);
            state = new uint[STATE_WORDS];
            k = new uint[KEY_WORDS];
            npub = new uint[RATE_WORDS];

            m_bufferSizeDecrypt = RATE_BYTES + TAG_BYTES;
            m_buf = new byte[m_bufferSizeDecrypt];

            // Relied on by ProcessBytes methods for decryption
            Debug.Assert(RATE_BYTES >= TAG_BYTES);
        }

        public int GetKeyBytesSize() => KEY_BYTES;

        public int GetIVBytesSize() => RATE_BYTES;

        public string AlgorithmName => algorithmName;

        public void Init(bool forEncryption, ICipherParameters parameters)
        {
            KeyParameter key;
#if NETCOREAPP2_1_OR_GREATER || NETSTANDARD2_1_OR_GREATER
            ReadOnlySpan<byte> iv;
#else
            byte[] iv;
#endif

            if (parameters is AeadParameters aeadParameters)
            {
                key = aeadParameters.Key;
#if NETCOREAPP2_1_OR_GREATER || NETSTANDARD2_1_OR_GREATER
                iv = aeadParameters.Nonce;
#else
                iv = aeadParameters.GetNonce();
#endif
                initialAssociatedText = aeadParameters.GetAssociatedText();

                int macSizeBits = aeadParameters.MacSize;
                if (macSizeBits != TAG_BYTES * 8)
                    throw new ArgumentException("Invalid value for MAC size: " + macSizeBits);
            }
            else if (parameters is ParametersWithIV withIV)
            {
                key = withIV.Parameters as KeyParameter;
#if NETCOREAPP2_1_OR_GREATER || NETSTANDARD2_1_OR_GREATER
                iv = withIV.InternalIV;
#else
                iv = withIV.GetIV();
#endif
                initialAssociatedText = null;
            }
            else
            {
                throw new ArgumentException("invalid parameters passed to Sparkle");
            }

            if (key == null)
                throw new ArgumentException("Sparkle Init parameters must include a key");

            int expectedKeyLength = KEY_WORDS * 4;
            if (expectedKeyLength != key.KeyLength)
                throw new ArgumentException(algorithmName + " requires exactly " + expectedKeyLength + " bytes of key");

            int expectedIVLength = RATE_WORDS * 4;
            if (expectedIVLength != iv.Length)
                throw new ArgumentException(algorithmName + " requires exactly " + expectedIVLength + " bytes of IV");

#if NETCOREAPP2_1_OR_GREATER || NETSTANDARD2_1_OR_GREATER
            Pack.LE_To_UInt32(key.InternalKey, k);
            Pack.LE_To_UInt32(iv, npub);
#else
            Pack.LE_To_UInt32(key.GetKey(), 0, k);
            Pack.LE_To_UInt32(iv, 0, npub);
#endif

            m_state = forEncryption ? State.EncInit : State.DecInit;

            Reset();
        }

        public void ProcessAadByte(byte input)
        {
            CheckAad();

            if (m_bufPos == RATE_BYTES)
            {
#if NETCOREAPP2_1_OR_GREATER || NETSTANDARD2_1_OR_GREATER
                ProcessBufferAad(m_buf);
#else
                ProcessBufferAad(m_buf, 0);
#endif
                m_bufPos = 0;
            }

            m_buf[m_bufPos++] = input;
        }

        public void ProcessAadBytes(byte[] inBytes, int inOff, int len)
        {
            Check.DataLength(inBytes, inOff, len, "input buffer too short");

#if NETCOREAPP2_1_OR_GREATER || NETSTANDARD2_1_OR_GREATER
            ProcessAadBytes(inBytes.AsSpan(inOff, len));
#else
            // Don't enter AAD state until we actually get input
            if (len <= 0)
                return;

            CheckAad();

            if (m_bufPos > 0)
            {
                int available = RATE_BYTES - m_bufPos;
                if (len <= available)
                {
                    Array.Copy(inBytes, inOff, m_buf, m_bufPos, len);
                    m_bufPos += len;
                    return;
                }

                Array.Copy(inBytes, inOff, m_buf, m_bufPos, available);
                inOff += available;
                len -= available;

                ProcessBufferAad(m_buf, 0);
                //m_bufPos = 0;
            }

            while (len > RATE_BYTES)
            {
                ProcessBufferAad(inBytes, inOff);
                inOff += RATE_BYTES;
                len -= RATE_BYTES;
            }

            Array.Copy(inBytes, inOff, m_buf, 0, len);
            m_bufPos = len;
#endif
        }

#if NETCOREAPP2_1_OR_GREATER || NETSTANDARD2_1_OR_GREATER
        public void ProcessAadBytes(ReadOnlySpan<byte> input)
        {
            // Don't enter AAD state until we actually get input
            if (input.IsEmpty)
                return;

            CheckAad();

            if (m_bufPos > 0)
            {
                int available = RATE_BYTES - m_bufPos;
                if (input.Length <= available)
                {
                    input.CopyTo(m_buf.AsSpan(m_bufPos));
                    m_bufPos += input.Length;
                    return;
                }

                input[..available].CopyTo(m_buf.AsSpan(m_bufPos));
                input = input[available..];

                ProcessBufferAad(m_buf);
                //m_bufPos = 0;
            }

            while (input.Length > RATE_BYTES)
            {
                ProcessBufferAad(input);
                input = input[RATE_BYTES..];
            }

            input.CopyTo(m_buf);
            m_bufPos = input.Length;
        }
#endif

        public int ProcessByte(byte input, byte[] outBytes, int outOff)
        {
#if NETCOREAPP2_1_OR_GREATER || NETSTANDARD2_1_OR_GREATER
            return ProcessByte(input, Spans.FromNullable(outBytes, outOff));
#else
            return ProcessBytes(new byte[]{ input }, 0, 1, outBytes, outOff);
#endif
        }

#if NETCOREAPP2_1_OR_GREATER || NETSTANDARD2_1_OR_GREATER
        public int ProcessByte(byte input, Span<byte> output)
        {
            Span<byte> singleByte = stackalloc byte[1]{ input };

            return ProcessBytes(singleByte, output);
        }
#endif

        public int ProcessBytes(byte[] inBytes, int inOff, int len, byte[] outBytes, int outOff)
        {
            Check.DataLength(inBytes, inOff, len, "input buffer too short");

#if NETCOREAPP2_1_OR_GREATER || NETSTANDARD2_1_OR_GREATER
            return ProcessBytes(inBytes.AsSpan(inOff, len), Spans.FromNullable(outBytes, outOff));
#else
            bool forEncryption = CheckData();

            int resultLength = 0;

            if (forEncryption)
            {
                if (m_bufPos > 0)
                {
                    int available = RATE_BYTES - m_bufPos;
                    if (len <= available)
                    {
                        Array.Copy(inBytes, inOff, m_buf, m_bufPos, len);
                        m_bufPos += len;
                        return 0;
                    }

                    Array.Copy(inBytes, inOff, m_buf, m_bufPos, available);
                    inOff += available;
                    len -= available;

                    ProcessBufferEncrypt(m_buf, 0, outBytes, outOff);
                    resultLength = RATE_BYTES;
                    //m_bufPos = 0;
                }

                while (len > RATE_BYTES)
                {
                    ProcessBufferEncrypt(inBytes, inOff, outBytes, outOff + resultLength);
                    inOff += RATE_BYTES;
                    len -= RATE_BYTES;
                    resultLength += RATE_BYTES;
                }
            }
            else
            {
                int available = m_bufferSizeDecrypt - m_bufPos;
                if (len <= available)
                {
                    Array.Copy(inBytes, inOff, m_buf, m_bufPos, len);
                    m_bufPos += len;
                    return 0;
                }

                if (m_bufPos > RATE_BYTES)
                {
                    ProcessBufferDecrypt(m_buf, 0, outBytes, outOff);
                    m_bufPos -= RATE_BYTES;
                    Array.Copy(m_buf, RATE_BYTES, m_buf, 0, m_bufPos);
                    resultLength = RATE_BYTES;

                    available += RATE_BYTES;
                    if (len <= available)
                    {
                        Array.Copy(inBytes, inOff, m_buf, m_bufPos, len);
                        m_bufPos += len;
                        return resultLength;
                    }
                }

                available = RATE_BYTES - m_bufPos;
                Array.Copy(inBytes, inOff, m_buf, m_bufPos, available);
                inOff += available;
                len -= available;
                ProcessBufferDecrypt(m_buf, 0, outBytes, outOff + resultLength);
                resultLength += RATE_BYTES;
                //m_bufPos = 0;

                while (len > m_bufferSizeDecrypt)
                {
                    ProcessBufferDecrypt(inBytes, inOff, outBytes, outOff + resultLength);
                    inOff += RATE_BYTES;
                    len -= RATE_BYTES;
                    resultLength += RATE_BYTES;
                }
            }

            Array.Copy(inBytes, inOff, m_buf, 0, len);
            m_bufPos = len;

            return resultLength;
#endif
        }

#if NETCOREAPP2_1_OR_GREATER || NETSTANDARD2_1_OR_GREATER
        public int ProcessBytes(ReadOnlySpan<byte> input, Span<byte> output)
        {
            bool forEncryption = CheckData();

            int resultLength = 0;

            if (forEncryption)
            {
                if (m_bufPos > 0)
                {
                    int available = RATE_BYTES - m_bufPos;
                    if (input.Length <= available)
                    {
                        input.CopyTo(m_buf.AsSpan(m_bufPos));
                        m_bufPos += input.Length;
                        return 0;
                    }

                    input[..available].CopyTo(m_buf.AsSpan(m_bufPos));
                    input = input[available..];

                    ProcessBufferEncrypt(m_buf, output);
                    resultLength = RATE_BYTES;
                    //m_bufPos = 0;
                }

                while (input.Length > RATE_BYTES)
                {
                    ProcessBufferEncrypt(input, output[resultLength..]);
                    input = input[RATE_BYTES..];
                    resultLength += RATE_BYTES;
                }
            }
            else
            {
                int available = m_bufferSizeDecrypt - m_bufPos;
                if (input.Length <= available)
                {
                    input.CopyTo(m_buf.AsSpan(m_bufPos));
                    m_bufPos += input.Length;
                    return 0;
                }

                if (m_bufPos > RATE_BYTES)
                {
                    ProcessBufferDecrypt(m_buf, output);
                    m_bufPos -= RATE_BYTES;
                    m_buf.AsSpan(0, m_bufPos).CopyFrom(m_buf.AsSpan(RATE_BYTES));
                    resultLength = RATE_BYTES;

                    available += RATE_BYTES;
                    if (input.Length <= available)
                    {
                        input.CopyTo(m_buf.AsSpan(m_bufPos));
                        m_bufPos += input.Length;
                        return resultLength;
                    }
                }

                available = RATE_BYTES - m_bufPos;
                input[..available].CopyTo(m_buf.AsSpan(m_bufPos));
                input = input[available..];
                ProcessBufferDecrypt(m_buf, output[resultLength..]);
                resultLength += RATE_BYTES;
                //m_bufPos = 0;

                while (input.Length > m_bufferSizeDecrypt)
                {
                    ProcessBufferDecrypt(input, output[resultLength..]);
                    input = input[RATE_BYTES..];
                    resultLength += RATE_BYTES;
                }
            }

            input.CopyTo(m_buf);
            m_bufPos = input.Length;

            return resultLength;
        }
#endif

        public int DoFinal(byte[] outBytes, int outOff)
        {
            bool forEncryption = CheckData();

            int resultLength;
            if (forEncryption)
            {
                resultLength = m_bufPos + TAG_BYTES;
            }
            else
            {
                if (m_bufPos < TAG_BYTES)
                    throw new InvalidCipherTextException("data too short");

                m_bufPos -= TAG_BYTES;

                resultLength = m_bufPos;
            }

            Check.OutputLength(outBytes, outOff, resultLength, "output buffer too short");

            if (encrypted || m_bufPos > 0)
            {
                // Encryption of Last Block
                // addition of ant M2 or M3 to the state
                state[STATE_WORDS - 1] ^= (m_bufPos < RATE_BYTES) ? _M2 : _M3;
                // combined Rho and rate-whitening (incl. padding)
                // Rho and rate-whitening for the encryption of the last plaintext block. Since
                // this last block may require padding, it is always copied to a buffer.
                uint[] buffer = new uint[RATE_WORDS];
                for (int i = 0; i < m_bufPos; ++i)
                {
                    buffer[i >> 2] |= (uint)m_buf[i] << ((i & 3) << 3);
                }
                if (m_bufPos < RATE_BYTES)
                {
                    if (!forEncryption)
                    {
                        int tmp = (m_bufPos & 3) << 3;
                        buffer[m_bufPos >> 2] |= (state[m_bufPos >> 2] >> tmp) << tmp;
                        tmp = (m_bufPos >> 2) + 1;
                        Array.Copy(state, tmp, buffer, tmp, RATE_WORDS - tmp);
                    }
                    buffer[m_bufPos >> 2] ^= 0x80U << ((m_bufPos & 3) << 3);
                }
                for (int i = 0; i < RATE_WORDS / 2; ++i)
                {
                    int j = i + RATE_WORDS / 2;

                    uint s_i = state[i];
                    uint s_j = state[j];
                    if (forEncryption)
                    {
                        state[i] =       s_j ^ buffer[i] ^ state[RATE_WORDS + i];
                        state[j] = s_i ^ s_j ^ buffer[j] ^ state[RATE_WORDS + (j & CAP_MASK)];
                    }
                    else
                    {
                        state[i] = s_i ^ s_j ^ buffer[i] ^ state[RATE_WORDS + i];
                        state[j] = s_i       ^ buffer[j] ^ state[RATE_WORDS + (j & CAP_MASK)];
                    }
                    buffer[i] ^= s_i;
                    buffer[j] ^= s_j;
                }
                for (int i = 0; i < m_bufPos; ++i)
                {
                    outBytes[outOff++] = (byte)(buffer[i >> 2] >> ((i & 3) << 3));
                }

                SparkleOpt(state, SPARKLE_STEPS_BIG);
            }
            // add key to the capacity-part of the state
            for (int i = 0; i < KEY_WORDS; i++)
            {
                state[RATE_WORDS + i] ^= k[i];
            }
            tag = new byte[TAG_BYTES];
            Pack.UInt32_To_LE(state, RATE_WORDS, TAG_WORDS, tag, 0);
            if (forEncryption)
            {
                Array.Copy(tag, 0, outBytes, outOff, TAG_BYTES);
            }
            else
            {
                if (!Arrays.FixedTimeEquals(TAG_BYTES, tag, 0, m_buf, m_bufPos))
                    throw new InvalidCipherTextException("mac check in " + AlgorithmName + " failed");
            }
            Reset(!forEncryption);
            return resultLength;
        }

#if NETCOREAPP2_1_OR_GREATER || NETSTANDARD2_1_OR_GREATER
        public int DoFinal(Span<byte> output)
        {
            byte[] rv = new byte[GetOutputSize(0)];
            int len = DoFinal(rv, 0);
            rv.AsSpan(0, len).CopyTo(output);
            return len;
        }
#endif

        public byte[] GetMac()
        {
            return tag;
        }

        public int GetUpdateOutputSize(int len)
        {
            // The -1 is to account for the lazy processing of a full buffer
            int total = System.Math.Max(0, len) - 1;

            switch (m_state)
            {
            case State.DecInit:
            case State.DecAad:
                total = System.Math.Max(0, total - TAG_BYTES);
                break;
            case State.DecData:
            case State.DecFinal:
                total = System.Math.Max(0, total + m_bufPos - TAG_BYTES);
                break;
            case State.EncData:
            case State.EncFinal:
                total = System.Math.Max(0, total + m_bufPos);
                break;
            default:
                break;
            }

            return total - total % RATE_BYTES;
        }

        public int GetOutputSize(int len)
        {
            int total = System.Math.Max(0, len);

            switch (m_state)
            {
            case State.DecInit:
            case State.DecAad:
                return System.Math.Max(0, total - TAG_BYTES);
            case State.DecData:
            case State.DecFinal:
                return System.Math.Max(0, total + m_bufPos - TAG_BYTES);
            case State.EncData:
            case State.EncFinal:
                return total + m_bufPos + TAG_BYTES;
            default:
                return total + TAG_BYTES;
            }
        }

        public void Reset()
        {
            Reset(true);
        }

        private void CheckAad()
        {
            switch (m_state)
            {
            case State.DecInit:
                m_state = State.DecAad;
                break;
            case State.EncInit:
                m_state = State.EncAad;
                break;
            case State.DecAad:
            case State.EncAad:
                break;
            case State.EncFinal:
                throw new InvalidOperationException(AlgorithmName + " cannot be reused for encryption");
            default:
                throw new InvalidOperationException(AlgorithmName + " needs to be initialized");
            }
        }

        private bool CheckData()
        {
            switch (m_state)
            {
            case State.DecInit:
            case State.DecAad:
                FinishAad(State.DecData);
                return false;
            case State.EncInit:
            case State.EncAad:
                FinishAad(State.EncData);
                return true;
            case State.DecData:
                return false;
            case State.EncData:
                return true;
            case State.EncFinal:
                throw new InvalidOperationException(AlgorithmName + " cannot be reused for encryption");
            default:
                throw new InvalidOperationException(AlgorithmName + " needs to be initialized");
            }
        }

        private void FinishAad(State nextState)
        {
            // State indicates whether we ever received AAD
            switch (m_state)
            {
            case State.DecAad:
            case State.EncAad:
            {
                ProcessFinalAad();
                break;
            }
            default:
                break;
            }

            m_bufPos = 0;
            m_state = nextState;
        }

#if NETCOREAPP2_1_OR_GREATER || NETSTANDARD2_1_OR_GREATER
        private void ProcessBufferAad(ReadOnlySpan<byte> buffer)
        {
            for (int i = 0; i < RATE_WORDS / 2; ++i)
            {
                int j = i + (RATE_WORDS >> 1);

                uint si = state[i];
                uint sj = state[j];

                uint d_i = Pack.LE_To_UInt32(buffer, i << 2);
                uint d_j = Pack.LE_To_UInt32(buffer, j << 2);

                state[i] = sj      ^ d_i ^ state[RATE_WORDS + i];
                state[j] = si ^ sj ^ d_j ^ state[RATE_WORDS + (j & CAP_MASK)];
            }

            SparkleOpt(state, SPARKLE_STEPS_SLIM);
        }

        private void ProcessBufferDecrypt(ReadOnlySpan<byte> buffer, Span<byte> output)
        {
            Debug.Assert(buffer.Length >= RATE_BYTES);

            Check.OutputLength(output, RATE_BYTES, "output buffer too short");

            for (int i = 0; i < RATE_WORDS / 2; ++i)
            {
                int j = i + (RATE_WORDS / 2);

                uint s_i = state[i];
                uint s_j = state[j];

                uint d_i = Pack.LE_To_UInt32(buffer, i * 4);
                uint d_j = Pack.LE_To_UInt32(buffer, j * 4);

                state[i] = s_i ^ s_j ^ d_i ^ state[RATE_WORDS + i];
                state[j] = s_i       ^ d_j ^ state[RATE_WORDS + (j & CAP_MASK)];

                Pack.UInt32_To_LE(d_i ^ s_i, output, i * 4);
                Pack.UInt32_To_LE(d_j ^ s_j, output, j * 4);
            }

            SparkleOpt(state, SPARKLE_STEPS_SLIM);

            encrypted = true;
        }

        private void ProcessBufferEncrypt(ReadOnlySpan<byte> buffer, Span<byte> output)
        {
            Debug.Assert(buffer.Length >= RATE_BYTES);

            Check.OutputLength(output, RATE_BYTES, "output buffer too short");

            for (int i = 0; i < RATE_WORDS / 2; ++i)
            {
                int j = i + (RATE_WORDS / 2);

                uint s_i = state[i];
                uint s_j = state[j];

                uint d_i = Pack.LE_To_UInt32(buffer, i * 4);
                uint d_j = Pack.LE_To_UInt32(buffer, j * 4);

                state[i] =       s_j ^ d_i ^ state[RATE_WORDS + i];
                state[j] = s_i ^ s_j ^ d_j ^ state[RATE_WORDS + (j & CAP_MASK)];

                Pack.UInt32_To_LE(d_i ^ s_i, output, i * 4);
                Pack.UInt32_To_LE(d_j ^ s_j, output, j * 4);
            }

            SparkleOpt(state, SPARKLE_STEPS_SLIM);

            encrypted = true;
        }
#else
        private void ProcessBufferAad(byte[] buffer, int bufOff)
        {
            for (int i = 0; i < RATE_WORDS / 2; ++i)
            {
                int j = i + (RATE_WORDS / 2);

                uint s_i = state[i];
                uint s_j = state[j];

                uint d_i = Pack.LE_To_UInt32(buffer, bufOff + (i * 4));
                uint d_j = Pack.LE_To_UInt32(buffer, bufOff + (j * 4));

                state[i] =       s_j ^ d_i ^ state[RATE_WORDS + i];
                state[j] = s_i ^ s_j ^ d_j ^ state[RATE_WORDS + (j & CAP_MASK)];
            }

            SparkleOpt(state, SPARKLE_STEPS_SLIM);
        }

        private void ProcessBufferDecrypt(byte[] buffer, int bufOff, byte[] output, int outOff)
        {
            Debug.Assert(bufOff <= buffer.Length - RATE_BYTES);

            Check.OutputLength(output, outOff, RATE_BYTES, "output buffer too short");

            for (int i = 0; i < RATE_WORDS / 2; ++i)
            {
                int j = i + (RATE_WORDS / 2);

                uint s_i = state[i];
                uint s_j = state[j];

                uint d_i = Pack.LE_To_UInt32(buffer, bufOff + (i * 4));
                uint d_j = Pack.LE_To_UInt32(buffer, bufOff + (j * 4));

                state[i] = s_i ^ s_j ^ d_i ^ state[RATE_WORDS + i];
                state[j] = s_i       ^ d_j ^ state[RATE_WORDS + (j & CAP_MASK)];

                Pack.UInt32_To_LE(d_i ^ s_i, output, outOff + (i * 4));
                Pack.UInt32_To_LE(d_j ^ s_j, output, outOff + (j * 4));
            }

            SparkleOpt(state, SPARKLE_STEPS_SLIM);

            encrypted = true;
        }

        private void ProcessBufferEncrypt(byte[] buffer, int bufOff, byte[] output, int outOff)
        {
            Debug.Assert(bufOff <= buffer.Length - RATE_BYTES);

            Check.OutputLength(output, outOff, RATE_BYTES, "output buffer too short");

            for (int i = 0; i < RATE_WORDS / 2; ++i)
            {
                int j = i + (RATE_WORDS / 2);

                uint s_i = state[i];
                uint s_j = state[j];

                uint d_i = Pack.LE_To_UInt32(buffer, bufOff + (i * 4));
                uint d_j = Pack.LE_To_UInt32(buffer, bufOff + (j * 4));

                state[i] =       s_j ^ d_i ^ state[RATE_WORDS + i];
                state[j] = s_i ^ s_j ^ d_j ^ state[RATE_WORDS + (j & CAP_MASK)];

                Pack.UInt32_To_LE(d_i ^ s_i, output, outOff + (i * 4));
                Pack.UInt32_To_LE(d_j ^ s_j, output, outOff + (j * 4));
            }

            SparkleOpt(state, SPARKLE_STEPS_SLIM);

            encrypted = true;
        }
#endif

        private void ProcessFinalAad()
        {
            // addition of constant A0 or A1 to the state
            if (m_bufPos < RATE_BYTES)
            {
                state[STATE_WORDS - 1] ^= _A0;

                // padding
                m_buf[m_bufPos] = 0x80;
                while (++m_bufPos < RATE_BYTES)
                {
                    m_buf[m_bufPos] = 0x00;
                }
            }
            else
            {
                state[STATE_WORDS - 1] ^= _A1;
            }

            for (int i = 0; i < RATE_WORDS / 2; ++i)
            {
                int j = i + (RATE_WORDS / 2);

                uint s_i = state[i];
                uint s_j = state[j];

                uint d_i = Pack.LE_To_UInt32(m_buf, i * 4);
                uint d_j = Pack.LE_To_UInt32(m_buf, j * 4);

                state[i] =       s_j ^ d_i ^ state[RATE_WORDS + i];
                state[j] = s_i ^ s_j ^ d_j ^ state[RATE_WORDS + (j & CAP_MASK)];
            }

            SparkleOpt(state, SPARKLE_STEPS_BIG);
        }

        private void Reset(bool clearMac)
        {
            if (clearMac)
            {
                tag = null;
            }

            Arrays.Clear(m_buf);
            m_bufPos = 0;
            encrypted = false;

            switch (m_state)
            {
            case State.DecInit:
            case State.EncInit:
                break;
            case State.DecAad:
            case State.DecData:
            case State.DecFinal:
                m_state = State.DecInit;
                break;
            case State.EncAad:
            case State.EncData:
            case State.EncFinal:
                m_state = State.EncFinal;
                return;
            default:
                throw new InvalidOperationException(AlgorithmName + " needs to be initialized");
            }

            // The Initialize function loads nonce and key into the state and executes the
            // SPARKLE permutation with the big number of steps.
            // load nonce into the rate-part of the state
            Array.Copy(npub, 0, state, 0, RATE_WORDS);
            // load key into the capacity-part of the sate
            Array.Copy(k, 0, state, RATE_WORDS, KEY_WORDS);

            SparkleOpt(state, SPARKLE_STEPS_BIG);

            if (initialAssociatedText != null)
            {
#if NETCOREAPP2_1_OR_GREATER || NETSTANDARD2_1_OR_GREATER
                ProcessAadBytes(initialAssociatedText);
#else
                ProcessAadBytes(initialAssociatedText, 0, initialAssociatedText.Length);
#endif
            }
        }

#if NETSTANDARD1_0_OR_GREATER || NETCOREAPP1_0_OR_GREATER
        [MethodImpl(MethodImplOptions.AggressiveInlining)]
#endif
        private static void ArxBox(uint rc, ref uint s00, ref uint s01)
        {
            s00 += Integers.RotateRight(s01, 31);
            s01 ^= Integers.RotateRight(s00, 24);
            s00 ^= rc;
            s00 += Integers.RotateRight(s01, 17);
            s01 ^= Integers.RotateRight(s00, 17);
            s00 ^= rc;
            s00 += s01;
            s01 ^= Integers.RotateRight(s00, 31);
            s00 ^= rc;
            s00 += Integers.RotateRight(s01, 24);
            s01 ^= Integers.RotateRight(s00, 16);
            s00 ^= rc;
        }

#if NETSTANDARD1_0_OR_GREATER || NETCOREAPP1_0_OR_GREATER
        [MethodImpl(MethodImplOptions.AggressiveInlining)]
#endif
        private static uint ELL(uint x)
        {
            return Integers.RotateRight(x, 16) ^ (x & 0xFFFFU);
        }

#if NETSTANDARD1_0_OR_GREATER || NETCOREAPP1_0_OR_GREATER
        [MethodImpl(MethodImplOptions.AggressiveInlining)]
#endif
        private static void SparkleOpt(uint[] state, int steps)
        {
            switch (state.Length)
            {
            case  8:    SparkleOpt8 (state, steps);     break;
            case 12:    SparkleOpt12(state, steps);     break;
            case 16:    SparkleOpt16(state, steps);     break;
            default:    throw new InvalidOperationException();
            }
        }

        internal static void SparkleOpt8(uint[] state, int steps)
        {
            uint s00 = state[0];
            uint s01 = state[1];
            uint s02 = state[2];
            uint s03 = state[3];
            uint s04 = state[4];
            uint s05 = state[5];
            uint s06 = state[6];
            uint s07 = state[7];

            for (int step = 0; step < steps; ++step)
            {
                // Add round ant

                s01 ^= RCON[step & 7];
                s03 ^= (uint)step;

                // ARXBOX layer

                ArxBox(RCON[0], ref s00, ref s01);
                ArxBox(RCON[1], ref s02, ref s03);
                ArxBox(RCON[2], ref s04, ref s05);
                ArxBox(RCON[3], ref s06, ref s07);

                // Linear layer

                uint t02 = ELL(s00 ^ s02);
                uint t13 = ELL(s01 ^ s03);

                uint u00 = s00 ^ s04;
                uint u01 = s01 ^ s05;
                uint u02 = s02 ^ s06;
                uint u03 = s03 ^ s07;

                s04 = s00;
                s05 = s01;
                s06 = s02;
                s07 = s03;

                s00 = u02 ^ t13;
                s01 = u03 ^ t02;
                s02 = u00 ^ t13;
                s03 = u01 ^ t02;
            }

            state[0] = s00;
            state[1] = s01;
            state[2] = s02;
            state[3] = s03;
            state[4] = s04;
            state[5] = s05;
            state[6] = s06;
            state[7] = s07;
        }

        internal static void SparkleOpt12(uint[] state, int steps)
        {
            uint s00 = state[0];
            uint s01 = state[1];
            uint s02 = state[2];
            uint s03 = state[3];
            uint s04 = state[4];
            uint s05 = state[5];
            uint s06 = state[6];
            uint s07 = state[7];
            uint s08 = state[8];
            uint s09 = state[9];
            uint s10 = state[10];
            uint s11 = state[11];

            for (int step = 0; step < steps; ++step)
            {
                // Add round ant

                s01 ^= RCON[step & 7];
                s03 ^= (uint)step;

                // ARXBOX layer

                ArxBox(RCON[0], ref s00, ref s01);
                ArxBox(RCON[1], ref s02, ref s03);
                ArxBox(RCON[2], ref s04, ref s05);
                ArxBox(RCON[3], ref s06, ref s07);
                ArxBox(RCON[4], ref s08, ref s09);
                ArxBox(RCON[5], ref s10, ref s11);

                // Linear layer

                uint t024 = ELL(s00 ^ s02 ^ s04);
                uint t135 = ELL(s01 ^ s03 ^ s05);

                uint u00 = s00 ^ s06;
                uint u01 = s01 ^ s07;
                uint u02 = s02 ^ s08;
                uint u03 = s03 ^ s09;
                uint u04 = s04 ^ s10;
                uint u05 = s05 ^ s11;

                s06 = s00;
                s07 = s01;
                s08 = s02;
                s09 = s03;
                s10 = s04;
                s11 = s05;

                s00 = u02 ^ t135;
                s01 = u03 ^ t024;
                s02 = u04 ^ t135;
                s03 = u05 ^ t024;
                s04 = u00 ^ t135;
                s05 = u01 ^ t024;
            }

            state[0] = s00;
            state[1] = s01;
            state[2] = s02;
            state[3] = s03;
            state[4] = s04;
            state[5] = s05;
            state[6] = s06;
            state[7] = s07;
            state[8] = s08;
            state[9] = s09;
            state[10] = s10;
            state[11] = s11;
        }

        internal static void SparkleOpt16(uint[] state, int steps)
        {
            Debug.Assert((steps & 1) == 0);

#if NETCOREAPP3_0_OR_GREATER
            if (Org.BouncyCastle.Runtime.Intrinsics.X86.Sse2.IsEnabled)
            {
                var s0246 = Vector128.Create(state[0], state[2], state[4], state[6]);
                var s1357 = Vector128.Create(state[1], state[3], state[5], state[7]);
                var s8ACE = Vector128.Create(state[8], state[10], state[12], state[14]);
                var s9BDF = Vector128.Create(state[9], state[11], state[13], state[15]);

                var RC03 = Load128(RCON.AsSpan(0));
                var RC47 = Load128(RCON.AsSpan(4));

                for (int step = 0; step < steps; ++step)
                {
                    // Add round ant

                    s1357 = Sse2.Xor(s1357, Vector128.Create(RCON[step & 7], (uint)step, 0U, 0U));

                    // ARXBOX layer

                    ArxBox(RC03, ref s0246, ref s1357);
                    ArxBox(RC47, ref s8ACE, ref s9BDF);

                    // Linear layer

                    var t0246 = ELL(HorizontalXor(s0246));
                    var t1357 = ELL(HorizontalXor(s1357));

                    var u0246 = Sse2.Xor(s0246, s8ACE);
                    var u1357 = Sse2.Xor(s1357, s9BDF);

                    s8ACE = s0246;
                    s9BDF = s1357;

                    s0246 = Sse2.Xor(t1357, Sse2.Shuffle(u0246, 0x39));
                    s1357 = Sse2.Xor(t0246, Sse2.Shuffle(u1357, 0x39));
                }

                Store128(Sse2.UnpackLow (s0246, s1357), state.AsSpan(0));
                Store128(Sse2.UnpackHigh(s0246, s1357), state.AsSpan(4));
                Store128(Sse2.UnpackLow (s8ACE, s9BDF), state.AsSpan(8));
                Store128(Sse2.UnpackHigh(s8ACE, s9BDF), state.AsSpan(12));
            }
            else
#endif
            {
                uint s00 = state[0];
                uint s01 = state[1];
                uint s02 = state[2];
                uint s03 = state[3];
                uint s04 = state[4];
                uint s05 = state[5];
                uint s06 = state[6];
                uint s07 = state[7];
                uint s08 = state[8];
                uint s09 = state[9];
                uint s10 = state[10];
                uint s11 = state[11];
                uint s12 = state[12];
                uint s13 = state[13];
                uint s14 = state[14];
                uint s15 = state[15];

                int step = 0;
                while (step < steps)
                {
                    // STEP 1

                    // Add round ant

                    s01 ^= RCON[step & 7];
                    s03 ^= (uint)(step++);

                    // ARXBOX layer

                    ArxBox(RCON[0], ref s00, ref s01);
                    ArxBox(RCON[1], ref s02, ref s03);
                    ArxBox(RCON[2], ref s04, ref s05);
                    ArxBox(RCON[3], ref s06, ref s07);
                    ArxBox(RCON[4], ref s08, ref s09);
                    ArxBox(RCON[5], ref s10, ref s11);
                    ArxBox(RCON[6], ref s12, ref s13);
                    ArxBox(RCON[7], ref s14, ref s15);

                    // Linear layer

                    uint t0246 = ELL(s00 ^ s02 ^ s04 ^ s06);
                    uint t1357 = ELL(s01 ^ s03 ^ s05 ^ s07);

                    uint u08 = s08;
                    uint u09 = s09;

                    s08 = s02 ^ s10 ^ t1357;
                    s09 = s03 ^ s11 ^ t0246;
                    s10 = s04 ^ s12 ^ t1357;
                    s11 = s05 ^ s13 ^ t0246;
                    s12 = s06 ^ s14 ^ t1357;
                    s13 = s07 ^ s15 ^ t0246;
                    s14 = s00 ^ u08 ^ t1357;
                    s15 = s01 ^ u09 ^ t0246;

                    // STEP 2

                    // Add round ant

                    s09 ^= RCON[step & 7];
                    s11 ^= (uint)(step++);

                    // ARXBOX layer

                    ArxBox(RCON[0], ref s08, ref s09);
                    ArxBox(RCON[1], ref s10, ref s11);
                    ArxBox(RCON[2], ref s12, ref s13);
                    ArxBox(RCON[3], ref s14, ref s15);
                    ArxBox(RCON[4], ref s00, ref s01);
                    ArxBox(RCON[5], ref s02, ref s03);
                    ArxBox(RCON[6], ref s04, ref s05);
                    ArxBox(RCON[7], ref s06, ref s07);

                    // Linear layer

                    uint t8ACE = ELL(s08 ^ s10 ^ s12 ^ s14);
                    uint t9BDF = ELL(s09 ^ s11 ^ s13 ^ s15);

                    uint u00 = s00;
                    uint u01 = s01;

                    s00 = s02 ^ s10 ^ t9BDF;
                    s01 = s03 ^ s11 ^ t8ACE;
                    s02 = s04 ^ s12 ^ t9BDF;
                    s03 = s05 ^ s13 ^ t8ACE;
                    s04 = s06 ^ s14 ^ t9BDF;
                    s05 = s07 ^ s15 ^ t8ACE;
                    s06 = u00 ^ s08 ^ t9BDF;
                    s07 = u01 ^ s09 ^ t8ACE;
                }

                state[0] = s00;
                state[1] = s01;
                state[2] = s02;
                state[3] = s03;
                state[4] = s04;
                state[5] = s05;
                state[6] = s06;
                state[7] = s07;
                state[8] = s08;
                state[9] = s09;
                state[10] = s10;
                state[11] = s11;
                state[12] = s12;
                state[13] = s13;
                state[14] = s14;
                state[15] = s15;
            }
        }

#if NETCOREAPP3_0_OR_GREATER
        [MethodImpl(MethodImplOptions.AggressiveInlining)]
        private static void ArxBox(Vector128<uint> rc, ref Vector128<uint> s00, ref Vector128<uint> s01)
        {
            s00 = Sse2.Add(s00, Sse2.ShiftRightLogical(s01, 31));
            s00 = Sse2.Add(s00, Sse2.ShiftLeftLogical(s01, 1));

            s01 = Sse2.Xor(s01, Sse2.ShiftRightLogical(s00, 24));
            s01 = Sse2.Xor(s01, Sse2.ShiftLeftLogical(s00, 8));

            s00 = Sse2.Xor(s00, rc);

            s00 = Sse2.Add(s00, Sse2.ShiftRightLogical(s01, 17));
            s00 = Sse2.Add(s00, Sse2.ShiftLeftLogical(s01, 15));

            s01 = Sse2.Xor(s01, Sse2.ShiftRightLogical(s00, 17));
            s01 = Sse2.Xor(s01, Sse2.ShiftLeftLogical(s00, 15));

            s00 = Sse2.Xor(s00, rc);

            s00 = Sse2.Add(s00, s01);

            s01 = Sse2.Xor(s01, Sse2.ShiftRightLogical(s00, 31));
            s01 = Sse2.Xor(s01, Sse2.ShiftLeftLogical(s00, 1));

            s00 = Sse2.Xor(s00, rc);

            s00 = Sse2.Add(s00, Sse2.ShiftRightLogical(s01, 24));
            s00 = Sse2.Add(s00, Sse2.ShiftLeftLogical(s01, 8));

            s01 = Sse2.Xor(s01, Sse2.ShiftRightLogical(s00, 16));
            s01 = Sse2.Xor(s01, Sse2.ShiftLeftLogical(s00, 16));

            s00 = Sse2.Xor(s00, rc);
        }

        [MethodImpl(MethodImplOptions.AggressiveInlining)]
        private static Vector128<uint> ELL(Vector128<uint> x)
        {
            var t = Sse2.ShiftLeftLogical(x, 16);
            var u = Sse2.Xor(x, t);
            return Sse2.Xor(t, Sse2.ShiftRightLogical(u, 16));
        }

        [MethodImpl(MethodImplOptions.AggressiveInlining)]
        private static Vector128<uint> HorizontalXor(Vector128<uint> x)
        {
            var t = Sse2.Xor(x, Sse2.Shuffle(x, 0x1B));
            return Sse2.Xor(t, Sse2.Shuffle(t, 0xB1));
        }

        [MethodImpl(MethodImplOptions.AggressiveInlining)]
        private static Vector128<uint> Load128(ReadOnlySpan<uint> t)
        {
            if (Org.BouncyCastle.Runtime.Intrinsics.Vector.IsPackedLittleEndian)
                return MemoryMarshal.Read<Vector128<uint>>(MemoryMarshal.AsBytes(t));

            return Vector128.Create(t[0], t[1], t[2], t[3]);
        }

        [MethodImpl(MethodImplOptions.AggressiveInlining)]
        private static void Store128(Vector128<uint> s, Span<uint> t)
        {
            var b = MemoryMarshal.AsBytes(t);
            if (Org.BouncyCastle.Runtime.Intrinsics.Vector.IsPackedLittleEndian)
            {
#if NET8_0_OR_GREATER
                MemoryMarshal.Write(b, in s);
#else
                MemoryMarshal.Write(b, ref s);
#endif
                return;
            }

            var u = s.AsUInt64();
            BinaryPrimitives.WriteUInt64LittleEndian(b[..8], u.GetElement(0));
            BinaryPrimitives.WriteUInt64LittleEndian(b[8..], u.GetElement(1));
        }
#endif
    }
}
