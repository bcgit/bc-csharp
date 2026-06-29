using System;

using Org.BouncyCastle.Crypto.Engines;
using Org.BouncyCastle.Crypto.Macs;
using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.Crypto.Utilities;
using Org.BouncyCastle.Utilities;

namespace Org.BouncyCastle.Crypto.Modes
{
    /// <summary>
    /// Implementation of the ChaCha20-Poly1305 AEAD construction as defined in RFC 7539 / RFC 8439.
    /// </summary>
    /// <remarks>
    /// <para>
    /// ChaCha20-Poly1305 is an Authenticated Encryption with Associated Data (AEAD) algorithm 
    /// combining the ChaCha20 stream cipher with the Poly1305 message authentication code.
    /// </para>
    /// <para>
    /// <b>CRITICAL SECURITY WARNING:</b> For encryption, a unique nonce (IV) MUST be used for every 
    /// invocation with the same key. Reusing a nonce with the same key catastrophically compromises 
    /// the security of the cipher, allowing an attacker to recover the authentication key (Poly1305) 
    /// and plaintext.
    /// </para>
    /// </remarks>
    public class ChaCha20Poly1305
        : IAeadCipher
    {
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

        private const int BufSize = 64;
        private const int KeySize = 32;
        private const int MacSize = 16;
        private static readonly byte[] Zeros = new byte[MacSize - 1];

        private const ulong AadLimit = ulong.MaxValue;
        private const ulong DataLimit = ((1UL << 32) - 1) * 64;

        private readonly ChaCha7539Engine m_chacha20;
        private readonly IMac m_poly1305;
        private readonly int m_nonceSize;

        private readonly byte[] m_key = new byte[KeySize];
        private readonly byte[] m_nonce;
        private readonly byte[] m_buf = new byte[BufSize + MacSize];
        private readonly byte[] m_mac = new byte[MacSize];

        private byte[] m_initialAad;

        private ulong m_aadCount;
        private ulong m_dataCount;
        private State m_state = State.Uninitialized;
        private int m_bufPos;

        /// <summary>
        /// Default constructor using the standard <see cref="Poly1305"/> MAC.
        /// </summary>
        public ChaCha20Poly1305()
            : this(new Poly1305())
        {
        }

        /// <summary>
        /// Constructor allowing a custom Poly1305 implementation.
        /// </summary>
        /// <param name="poly1305">The Poly1305 MAC implementation to use.</param>
        /// <exception cref="ArgumentNullException">If poly1305 is null.</exception>
        /// <exception cref="ArgumentException">If poly1305 is not a 128-bit MAC.</exception>
        public ChaCha20Poly1305(IMac poly1305)
            : this(new ChaCha7539Engine(), poly1305, 12)
        {
        }

        /// <summary>
        /// Constructor for subclasses to inject an alternative ChaCha20 engine (e.g. XChaCha20)
        /// and the matching nonce size.
        /// </summary>
        protected ChaCha20Poly1305(ChaCha7539Engine chacha20, IMac poly1305, int nonceSize)
        {
            if (null == chacha20)
                throw new ArgumentNullException(nameof(chacha20));
            if (null == poly1305)
                throw new ArgumentNullException(nameof(poly1305));
            if (MacSize != poly1305.GetMacSize())
                throw new ArgumentException("must be a 128-bit MAC", nameof(poly1305));

            m_chacha20 = chacha20;
            m_poly1305 = poly1305;
            m_nonceSize = nonceSize;
            m_nonce = new byte[nonceSize];
        }

        /// <summary>The name of the algorithm ("ChaCha20Poly1305").</summary>
        public virtual string AlgorithmName => "ChaCha20Poly1305";

        /// <summary>
        /// Initialise the ChaCha20Poly1305 cipher.
        /// </summary>
        /// <param name="forEncryption">True if initializing for encryption, false for decryption.</param>
        /// <param name="parameters">The parameters required (typically <see cref="AeadParameters"/> or <see cref="ParametersWithIV"/>).</param>
        /// <exception cref="ArgumentException">If parameters are invalid or nonce is reused for encryption.</exception>
        public virtual void Init(bool forEncryption, ICipherParameters parameters)
        {
            KeyParameter keyParameter = null;
#if NETCOREAPP2_1_OR_GREATER || NETSTANDARD2_1_OR_GREATER
            ReadOnlySpan<byte> initNonce;
#else
            byte[] initNonce;
#endif
            ICipherParameters chacha20Params;

            if (parameters is AeadParameters aeadParameters)
            {
                int macSizeInBits = aeadParameters.MacSize;
                if ((MacSize * 8) != macSizeInBits)
                    throw new ArgumentException("Invalid value for MAC size: " + macSizeInBits);

                keyParameter = aeadParameters.Key;
#if NETCOREAPP2_1_OR_GREATER || NETSTANDARD2_1_OR_GREATER
                initNonce = aeadParameters.Nonce;
#else
                initNonce = aeadParameters.GetNonce();
#endif
                chacha20Params = new ParametersWithIV(keyParameter, initNonce);

                m_initialAad = aeadParameters.GetAssociatedText();
            }
            else if (parameters is ParametersWithIV withIV)
            {
                if (withIV.Parameters != null)
                {
                    keyParameter = withIV.Parameters as KeyParameter ?? throw new ArgumentException(
                        $"invalid parameters passed to {AlgorithmName}", nameof(parameters));
                }

#if NETCOREAPP2_1_OR_GREATER || NETSTANDARD2_1_OR_GREATER
                initNonce = withIV.InternalIV;
#else
                initNonce = withIV.GetIV();
#endif
                chacha20Params = withIV;

                m_initialAad = null;
            }
            else
            {
                throw new ArgumentException($"invalid parameters passed to {AlgorithmName}", nameof(parameters));
            }

            // Validate key
            if (null == keyParameter)
            {
                if (State.Uninitialized == m_state)
                    throw new ArgumentException("Key must be specified in initial init");
            }
            else
            {
                if (KeySize != keyParameter.KeyLength)
                    throw new ArgumentException("Key must be 256 bits");
            }

            // Validate nonce
            if (m_nonceSize != initNonce.Length)
                throw new ArgumentException("Nonce must be " + (m_nonceSize * 8) + " bits");

            // Check for encryption with reused nonce
#if NETCOREAPP2_1_OR_GREATER || NETSTANDARD2_1_OR_GREATER
            if (State.Uninitialized != m_state && forEncryption && initNonce.SequenceEqual(m_nonce))
#else
            if (State.Uninitialized != m_state && forEncryption && Arrays.AreEqual(m_nonce, initNonce))
#endif
            {
                if (null == keyParameter || keyParameter.FixedTimeEquals(m_key))
                    throw new ArgumentException($"cannot reuse nonce for {AlgorithmName} encryption");
            }

            if (null != keyParameter)
            {
                keyParameter.CopyKeyTo(m_key, 0, KeySize);
            }

#if NETCOREAPP2_1_OR_GREATER || NETSTANDARD2_1_OR_GREATER
            initNonce.CopyTo(m_nonce);
#else
            Array.Copy(initNonce, 0, m_nonce, 0, m_nonceSize);
#endif

            m_chacha20.Init(forEncryption: true, chacha20Params);

            m_state = forEncryption ? State.EncInit : State.DecInit;

            Reset(clearMac: true, resetCipher: false);
        }

        /// <summary>Return the size of the output buffer required for an input of <paramref name="len"/> bytes.</summary>
        /// <param name="len">Input length.</param>
        /// <returns>Required output buffer size.</returns>
        public virtual int GetOutputSize(int len)
        {
            int total = System.Math.Max(0, len);

            switch (m_state)
            {
            case State.DecInit:
            case State.DecAad:
                return System.Math.Max(0, total - MacSize);
            case State.DecData:
            case State.DecFinal:
                return System.Math.Max(0, total + m_bufPos - MacSize);
            case State.EncData:
            case State.EncFinal:
                return total + m_bufPos + MacSize;
            default:
                return total + MacSize;
            }
        }

        /// <summary>Return the size of the output buffer required for a <c>ProcessBytes</c> call with <paramref name="len"/> bytes.</summary>
        /// <param name="len">Input length.</param>
        /// <returns>Update output size.</returns>
        public virtual int GetUpdateOutputSize(int len)
        {
            int total = System.Math.Max(0, len);

            switch (m_state)
            {
            case State.DecInit:
            case State.DecAad:
                total = System.Math.Max(0, total - MacSize);
                break;
            case State.DecData:
            case State.DecFinal:
                total = System.Math.Max(0, total + m_bufPos - MacSize);
                break;
            case State.EncData:
            case State.EncFinal:
                total += m_bufPos;
                break;
            default:
                break;
            }

            return total - total % BufSize;
        }

        /// <summary>Process a single byte of Additional Authenticated Data (AAD).</summary>
        /// <param name="input">The byte to be processed.</param>
        public virtual void ProcessAadByte(byte input)
        {
            CheckAad();

            m_aadCount = IncrementCount(m_aadCount, 1, AadLimit);
            m_poly1305.Update(input);
        }

        /// <summary>Process a sequence of bytes of Additional Authenticated Data (AAD).</summary>
        /// <param name="inBytes">The input buffer containing AAD.</param>
        /// <param name="inOff">The offset into the input buffer.</param>
        /// <param name="len">The length of the data to process.</param>
        public virtual void ProcessAadBytes(byte[] inBytes, int inOff, int len)
        {
            if (null == inBytes)
                throw new ArgumentNullException("inBytes");
            if (inOff < 0)
                throw new ArgumentException("cannot be negative", "inOff");
            if (len < 0)
                throw new ArgumentException("cannot be negative", "len");
            Check.DataLength(inBytes, inOff, len, "input buffer too short");

            CheckAad();

            if (len > 0)
            {
                m_aadCount = IncrementCount(m_aadCount, (uint)len, AadLimit);
                m_poly1305.BlockUpdate(inBytes, inOff, len);
            }
        }

#if NETCOREAPP2_1_OR_GREATER || NETSTANDARD2_1_OR_GREATER
        /// <summary>Process a span of bytes of Additional Authenticated Data (AAD).</summary>
        /// <param name="input">The input span containing AAD.</param>
        public virtual void ProcessAadBytes(ReadOnlySpan<byte> input)
        {
            CheckAad();

            if (!input.IsEmpty)
            {
                m_aadCount = IncrementCount(m_aadCount, (uint)input.Length, AadLimit);
                m_poly1305.BlockUpdate(input);
            }
        }
#endif

        /// <summary>Process a single byte of data.</summary>
        /// <param name="input">The input byte.</param>
        /// <param name="outBytes">The output buffer.</param>
        /// <param name="outOff">The offset into the output buffer.</param>
        /// <returns>Number of bytes written to the output buffer.</returns>
        public virtual int ProcessByte(byte input, byte[] outBytes, int outOff)
        {
            CheckData();

            switch (m_state)
            {
            case State.DecData:
            {
                m_buf[m_bufPos] = input;
                if (++m_bufPos == m_buf.Length)
                {
                    m_poly1305.BlockUpdate(m_buf, 0, BufSize);
#if NETCOREAPP2_1_OR_GREATER || NETSTANDARD2_1_OR_GREATER
                    ProcessBlock(m_buf, outBytes.AsSpan(outOff));
#else
                    ProcessBlock(m_buf, 0, outBytes, outOff);
#endif
                    Array.Copy(m_buf, BufSize, m_buf, 0, MacSize);
                    m_bufPos = MacSize;
                    return BufSize;
                }

                return 0;
            }
            case State.EncData:
            {
                m_buf[m_bufPos] = input;
                if (++m_bufPos == BufSize)
                {
#if NETCOREAPP2_1_OR_GREATER || NETSTANDARD2_1_OR_GREATER
                    ProcessBlock(m_buf, outBytes.AsSpan(outOff));
#else
                    ProcessBlock(m_buf, 0, outBytes, outOff);
#endif
                    m_poly1305.BlockUpdate(outBytes, outOff, BufSize);
                    m_bufPos = 0;
                    return BufSize;
                }

                return 0;
            }
            default:
                throw new InvalidOperationException();
            }
        }

#if NETCOREAPP2_1_OR_GREATER || NETSTANDARD2_1_OR_GREATER
        /// <summary>Process a single byte of data using Spans.</summary>
        /// <param name="input">The input byte.</param>
        /// <param name="output">The output span.</param>
        /// <returns>Number of bytes written to the output span.</returns>
        public virtual int ProcessByte(byte input, Span<byte> output)
        {
            CheckData();

            switch (m_state)
            {
            case State.DecData:
            {
                m_buf[m_bufPos] = input;
                if (++m_bufPos == m_buf.Length)
                {
                    m_poly1305.BlockUpdate(m_buf.AsSpan(0, BufSize));
                    ProcessBlock(m_buf, output);
                    Array.Copy(m_buf, BufSize, m_buf, 0, MacSize);
                    m_bufPos = MacSize;
                    return BufSize;
                }

                return 0;
            }
            case State.EncData:
            {
                m_buf[m_bufPos] = input;
                if (++m_bufPos == BufSize)
                {
                    ProcessBlock(m_buf, output);
                    m_poly1305.BlockUpdate(output[..BufSize]);
                    m_bufPos = 0;
                    return BufSize;
                }

                return 0;
            }
            default:
                throw new InvalidOperationException();
            }
        }
#endif

        /// <summary>Process a sequence of bytes from the input buffer.</summary>
        /// <param name="inBytes">The input buffer.</param>
        /// <param name="inOff">The offset into the input buffer.</param>
        /// <param name="len">The length of data to process.</param>
        /// <param name="outBytes">The output buffer.</param>
        /// <param name="outOff">The offset into the output buffer.</param>
        /// <returns>The number of bytes written to the output buffer.</returns>
        public virtual int ProcessBytes(byte[] inBytes, int inOff, int len, byte[] outBytes, int outOff)
        {
            if (null == inBytes)
                throw new ArgumentNullException("inBytes");
            /*
             * Following bc-java, we allow null when no output is expected (e.g. based on a
             * GetUpdateOutputSize call).
             */
            if (null == outBytes)
            {
                //throw new ArgumentNullException("outBytes");
            }
            if (inOff < 0)
                throw new ArgumentException("cannot be negative", "inOff");
            if (len < 0)
                throw new ArgumentException("cannot be negative", "len");
            Check.DataLength(inBytes, inOff, len, "input buffer too short");
            if (outOff < 0)
                throw new ArgumentException("cannot be negative", "outOff");

#if NETCOREAPP2_1_OR_GREATER || NETSTANDARD2_1_OR_GREATER
            return ProcessBytes(inBytes.AsSpan(inOff, len), Spans.FromNullable(outBytes, outOff));
#else
            CheckData();

            int resultLen = 0;

            switch (m_state)
            {
            case State.DecData:
            {
                int available = m_buf.Length - m_bufPos;
                if (len < available)
                {
                    Array.Copy(inBytes, inOff, m_buf, m_bufPos, len);
                    m_bufPos += len;
                    break;
                }

                if (m_bufPos >= BufSize)
                {
                    m_poly1305.BlockUpdate(m_buf, 0, BufSize);
                    ProcessBlock(m_buf, 0, outBytes, outOff);
                    Array.Copy(m_buf, BufSize, m_buf, 0, m_bufPos -= BufSize);
                    resultLen = BufSize;

                    available += BufSize;
                    if (len < available)
                    {
                        Array.Copy(inBytes, inOff, m_buf, m_bufPos, len);
                        m_bufPos += len;
                        break;
                    }
                }

                int inLimit1 = inOff + len - m_buf.Length;
                int inLimit2 = inLimit1 - BufSize;

                available = BufSize - m_bufPos;
                Array.Copy(inBytes, inOff, m_buf, m_bufPos, available);
                m_poly1305.BlockUpdate(m_buf, 0, BufSize);
                ProcessBlock(m_buf, 0, outBytes, outOff + resultLen);
                inOff += available;
                resultLen += BufSize;

                while (inOff <= inLimit2)
                {
                    m_poly1305.BlockUpdate(inBytes, inOff, BufSize * 2);
                    ProcessBlocks2(inBytes, inOff, outBytes, outOff + resultLen);
                    inOff += BufSize * 2;
                    resultLen += BufSize * 2;
                }

                if (inOff <= inLimit1)
                {
                    m_poly1305.BlockUpdate(inBytes, inOff, BufSize);
                    ProcessBlock(inBytes, inOff, outBytes, outOff + resultLen);
                    inOff += BufSize;
                    resultLen += BufSize;
                }

                m_bufPos = m_buf.Length + inLimit1 - inOff;
                Array.Copy(inBytes, inOff, m_buf, 0, m_bufPos);
                break;
            }
            case State.EncData:
            {
                int available = BufSize - m_bufPos;
                if (len < available)
                {
                    Array.Copy(inBytes, inOff, m_buf, m_bufPos, len);
                    m_bufPos += len;
                    break;
                }

                int inLimit1 = inOff + len - BufSize;
                int inLimit2 = inLimit1 - BufSize;

                if (m_bufPos > 0)
                {
                    Array.Copy(inBytes, inOff, m_buf, m_bufPos, available);
                    ProcessBlock(m_buf, 0, outBytes, outOff);
                    inOff += available;
                    resultLen = BufSize;
                }

                while (inOff <= inLimit2)
                {
                    ProcessBlocks2(inBytes, inOff, outBytes, outOff + resultLen);
                    inOff += BufSize * 2;
                    resultLen += BufSize * 2;
                }

                if (inOff <= inLimit1)
                {
                    ProcessBlock(inBytes, inOff, outBytes, outOff + resultLen);
                    inOff += BufSize;
                    resultLen += BufSize;
                }

                m_poly1305.BlockUpdate(outBytes, outOff, resultLen);

                m_bufPos = BufSize + inLimit1 - inOff;
                Array.Copy(inBytes, inOff, m_buf, 0, m_bufPos);
                break;
            }
            default:
                throw new InvalidOperationException();
            }

            return resultLen;
#endif
        }

#if NETCOREAPP2_1_OR_GREATER || NETSTANDARD2_1_OR_GREATER
        /// <summary>Process a span of bytes from the input.</summary>
        /// <param name="input">The input span.</param>
        /// <param name="output">The output span.</param>
        /// <returns>The number of bytes written to the output span.</returns>
        public virtual int ProcessBytes(ReadOnlySpan<byte> input, Span<byte> output)
        {
            CheckData();

            int resultLen = 0;

            switch (m_state)
            {
            case State.DecData:
            {
                int available = m_buf.Length - m_bufPos;
                if (input.Length < available)
                {
                    input.CopyTo(m_buf.AsSpan(m_bufPos));
                    m_bufPos += input.Length;
                    break;
                }

                if (m_bufPos >= BufSize)
                {
                    m_poly1305.BlockUpdate(m_buf.AsSpan(0, BufSize));
                    ProcessBlock(m_buf, output);
                    Array.Copy(m_buf, BufSize, m_buf, 0, m_bufPos -= BufSize);
                    resultLen = BufSize;

                    available += BufSize;
                    if (input.Length < available)
                    {
                        input.CopyTo(m_buf.AsSpan(m_bufPos));
                        m_bufPos += input.Length;
                        break;
                    }
                }

                int inLimit1 = m_buf.Length;
                int inLimit2 = inLimit1 + BufSize;

                available = BufSize - m_bufPos;
                input[..available].CopyTo(m_buf.AsSpan(m_bufPos));
                m_poly1305.BlockUpdate(m_buf.AsSpan(0, BufSize));
                ProcessBlock(m_buf, output[resultLen..]);
                input = input[available..];
                resultLen += BufSize;

                while (input.Length >= inLimit2)
                {
                    m_poly1305.BlockUpdate(input[..(BufSize * 2)]);
                    ProcessBlocks2(input, output[resultLen..]);
                    input = input[(BufSize * 2)..];
                    resultLen += BufSize * 2;
                }

                if (input.Length >= inLimit1)
                {
                    m_poly1305.BlockUpdate(input[..BufSize]);
                    ProcessBlock(input, output[resultLen..]);
                    input = input[BufSize..];
                    resultLen += BufSize;
                }

                m_bufPos = input.Length;
                input.CopyTo(m_buf);
                break;
            }
            case State.EncData:
            {
                int available = BufSize - m_bufPos;
                if (input.Length < available)
                {
                    input.CopyTo(m_buf.AsSpan(m_bufPos));
                    m_bufPos += input.Length;
                    break;
                }

                if (m_bufPos > 0)
                {
                    input[..available].CopyTo(m_buf.AsSpan(m_bufPos));
                    ProcessBlock(m_buf, output);
                    input = input[available..];
                    resultLen = BufSize;
                }

                while (input.Length >= BufSize * 2)
                {
                    ProcessBlocks2(input, output[resultLen..]);
                    input = input[(BufSize * 2)..];
                    resultLen += BufSize * 2;
                }

                if (input.Length >= BufSize)
                {
                    ProcessBlock(input, output[resultLen..]);
                    input = input[BufSize..];
                    resultLen += BufSize;
                }

                m_poly1305.BlockUpdate(output[..resultLen]);

                m_bufPos = input.Length;
                input.CopyTo(m_buf);
                break;
            }
            default:
                throw new InvalidOperationException();
            }

            return resultLen;
        }
#endif

        /// <summary>Finish the operation, generating or verifying the MAC.</summary>
        /// <param name="outBytes">The output buffer for remaining processed data and/or MAC.</param>
        /// <param name="outOff">The offset into the output buffer.</param>
        /// <returns>Number of bytes written to the output buffer.</returns>
        /// <exception cref="InvalidCipherTextException">If the MAC check fails.</exception>
        public virtual int DoFinal(byte[] outBytes, int outOff)
        {
            if (null == outBytes)
                throw new ArgumentNullException("outBytes");
            if (outOff < 0)
                throw new ArgumentException("cannot be negative", "outOff");

#if NETCOREAPP2_1_OR_GREATER || NETSTANDARD2_1_OR_GREATER
            return DoFinal(outBytes.AsSpan(outOff));
#else
            CheckData();

            Array.Clear(m_mac, 0, MacSize);

            int resultLen = 0;

            switch (m_state)
            {
            case State.DecData:
            {
                if (m_bufPos < MacSize)
                    throw new InvalidCipherTextException("data too short");

                resultLen = m_bufPos - MacSize;

                Check.OutputLength(outBytes, outOff, resultLen, "output buffer too short");

                if (resultLen > 0)
                {
                    m_poly1305.BlockUpdate(m_buf, 0, resultLen);
                    ProcessData(m_buf, 0, resultLen, outBytes, outOff);
                }

                FinishData(State.DecFinal);

                if (!Arrays.FixedTimeEquals(MacSize, m_mac, 0, m_buf, resultLen))
                    throw new InvalidCipherTextException($"mac check in {AlgorithmName} failed");

                break;
            }
            case State.EncData:
            {
                resultLen = m_bufPos + MacSize;

                Check.OutputLength(outBytes, outOff, resultLen, "output buffer too short");

                if (m_bufPos > 0)
                {
                    ProcessData(m_buf, 0, m_bufPos, outBytes, outOff);
                    m_poly1305.BlockUpdate(outBytes, outOff, m_bufPos);
                }

                FinishData(State.EncFinal);

                Array.Copy(m_mac, 0, outBytes, outOff + m_bufPos, MacSize);
                break;
            }
            default:
                throw new InvalidOperationException();
            }

            Reset(clearMac: false, resetCipher: true);

            return resultLen;
#endif
        }

#if NETCOREAPP2_1_OR_GREATER || NETSTANDARD2_1_OR_GREATER
        /// <summary>Finish the operation using Spans, generating or verifying the MAC.</summary>
        /// <param name="output">The output span for remaining data and/or MAC.</param>
        /// <returns>Number of bytes written to the output span.</returns>
        /// <exception cref="InvalidCipherTextException">If the MAC check fails.</exception>
        public virtual int DoFinal(Span<byte> output)
        {
            CheckData();

            Array.Clear(m_mac, 0, MacSize);

            int resultLen = 0;

            switch (m_state)
            {
            case State.DecData:
            {
                if (m_bufPos < MacSize)
                    throw new InvalidCipherTextException("data too short");

                resultLen = m_bufPos - MacSize;

                Check.OutputLength(output, resultLen, "output buffer too short");

                if (resultLen > 0)
                {
                    m_poly1305.BlockUpdate(m_buf, 0, resultLen);
                    ProcessData(m_buf.AsSpan(0, resultLen), output);
                }

                FinishData(State.DecFinal);

                if (!Arrays.FixedTimeEquals(MacSize, m_mac, 0, m_buf, resultLen))
                    throw new InvalidCipherTextException($"mac check in {AlgorithmName} failed");

                break;
            }
            case State.EncData:
            {
                resultLen = m_bufPos + MacSize;

                Check.OutputLength(output, resultLen, "output buffer too short");

                if (m_bufPos > 0)
                {
                    ProcessData(m_buf.AsSpan(0, m_bufPos), output);
                    m_poly1305.BlockUpdate(output[..m_bufPos]);
                }

                FinishData(State.EncFinal);

                m_mac.AsSpan(0, MacSize).CopyTo(output[m_bufPos..]);
                break;
            }
            default:
                throw new InvalidOperationException();
            }

            Reset(clearMac: false, resetCipher: true);

            return resultLen;
        }
#endif

        /// <summary>Return the Message Authentication Code (MAC) generated or verified by the cipher.</summary>
        /// <returns>A byte array containing the MACBlock.</returns>
        public virtual byte[] GetMac() => Arrays.Clone(m_mac);

        /// <summary>Reset the cipher to its initial state (ready for a new message with the same key but DIFFERENT nonce).</summary>
        public virtual void Reset() => Reset(clearMac: true, resetCipher: true);

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

        private void CheckData()
        {
            switch (m_state)
            {
            case State.DecInit:
            case State.DecAad:
                FinishAad(State.DecData);
                break;
            case State.EncInit:
            case State.EncAad:
                FinishAad(State.EncData);
                break;
            case State.DecData:
            case State.EncData:
                break;
            case State.EncFinal:
                throw new InvalidOperationException(AlgorithmName + " cannot be reused for encryption");
            default:
                throw new InvalidOperationException(AlgorithmName + " needs to be initialized");
            }
        }

        private void FinishAad(State nextState)
        {
            PadMac(m_aadCount);

            m_state = nextState;
        }

        private void FinishData(State nextState)
        {
            PadMac(m_dataCount);

            byte[] lengths = new byte[16];
            Pack.UInt64_To_LE(m_aadCount, lengths, 0);
            Pack.UInt64_To_LE(m_dataCount, lengths, 8);
            m_poly1305.BlockUpdate(lengths, 0, 16);
            m_poly1305.DoFinal(m_mac, 0);

            m_state = nextState;
        }

        private ulong IncrementCount(ulong count, uint increment, ulong limit)
        {
            if (count > (limit - increment))
                throw new InvalidOperationException ("Limit exceeded");

            return count + increment;
        }

        private void InitMac()
        {
#if NETCOREAPP2_1_OR_GREATER || NETSTANDARD2_1_OR_GREATER
            Span<byte> firstBlock = stackalloc byte[64];
            try
            {
                m_chacha20.ProcessBytes(firstBlock, firstBlock);
                m_poly1305.Init(new KeyParameter(firstBlock[..32]));
            }
            finally
            {
                firstBlock.Fill(0x00);
            }
#else
            byte[] firstBlock = new byte[64];
            try
            {
                m_chacha20.ProcessBytes(firstBlock, 0, 64, firstBlock, 0);
                m_poly1305.Init(new KeyParameter(firstBlock, 0, 32));
            }
            finally
            {
                Array.Clear(firstBlock, 0, 64);
            }
#endif
        }

        private void PadMac(ulong count)
        {
            int partial = (int)count & (MacSize - 1);
            if (0 != partial)
            {
                m_poly1305.BlockUpdate(Zeros, 0, MacSize - partial);
            }
        }

#if NETCOREAPP2_1_OR_GREATER || NETSTANDARD2_1_OR_GREATER
        private void ProcessBlock(ReadOnlySpan<byte> input, Span<byte> output)
        {
            Check.OutputLength(output, 64, "output buffer too short");

            m_chacha20.ProcessBlock(input, output);
            m_dataCount = IncrementCount(m_dataCount, 64U, DataLimit);
        }

        private void ProcessBlocks2(ReadOnlySpan<byte> input, Span<byte> output)
        {
            Check.OutputLength(output, 128, "output buffer too short");

            m_chacha20.ProcessBlocks2(input, output);
            m_dataCount = IncrementCount(m_dataCount, 128U, DataLimit);
        }

        private void ProcessData(ReadOnlySpan<byte> input, Span<byte> output)
        {
            Check.OutputLength(output, input.Length, "output buffer too short");

            m_chacha20.ProcessBytes(input, output);
            m_dataCount = IncrementCount(m_dataCount, (uint)input.Length, DataLimit);
        }
#else
        private void ProcessBlock(byte[] inBytes, int inOff, byte[] outBytes, int outOff)
        {
            Check.OutputLength(outBytes, outOff, 64, "output buffer too short");

            m_chacha20.ProcessBlock(inBytes, inOff, outBytes, outOff);
            m_dataCount = IncrementCount(m_dataCount, 64U, DataLimit);
        }

        private void ProcessBlocks2(byte[] inBytes, int inOff, byte[] outBytes, int outOff)
        {
            Check.OutputLength(outBytes, outOff, 128, "output buffer too short");

            m_chacha20.ProcessBlocks2(inBytes, inOff, outBytes, outOff);
            m_dataCount = IncrementCount(m_dataCount, 128U, DataLimit);
        }

        private void ProcessData(byte[] inBytes, int inOff, int inLen, byte[] outBytes, int outOff)
        {
            Check.OutputLength(outBytes, outOff, inLen, "output buffer too short");

            m_chacha20.ProcessBytes(inBytes, inOff, inLen, outBytes, outOff);
            m_dataCount = IncrementCount(m_dataCount, (uint)inLen, DataLimit);
        }
#endif

        private void Reset(bool clearMac, bool resetCipher)
        {
            Array.Clear(m_buf, 0, m_buf.Length);

            if (clearMac)
            {
                Array.Clear(m_mac, 0, m_mac.Length);
            }

            m_aadCount = 0UL;
            m_dataCount = 0UL;
            m_bufPos = 0;

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

            if (resetCipher)
            {
                m_chacha20.Reset();
            }

            InitMac();

            if (null != m_initialAad)
            {
#if NETCOREAPP2_1_OR_GREATER || NETSTANDARD2_1_OR_GREATER
                ProcessAadBytes(m_initialAad);
#else
                ProcessAadBytes(m_initialAad, 0, m_initialAad.Length);
#endif
            }
        }
    }
}
