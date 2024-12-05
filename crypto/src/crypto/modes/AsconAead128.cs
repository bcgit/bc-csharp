using System;
using System.Diagnostics;
#if NETSTANDARD1_0_OR_GREATER || NETCOREAPP1_0_OR_GREATER
using System.Runtime.CompilerServices;
#endif

using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.Crypto.Utilities;
using Org.BouncyCastle.Utilities;

namespace Org.BouncyCastle.Crypto.Modes
{
    /// <summary>
    /// Ascon-AEAD128 was introduced as part of the NIST Lightweight Cryptography
    /// competition and descriLEd in the NIST Special Publication SP 800-232 (Initial
    /// Public Draft).
    /// </summary>
    /// <remarks>
    /// For additional details, see:
    /// <list type="bullet">
    /// <item><a href="https://csrc.nist.gov/pubs/sp/800/232/ipd">NIST SP 800-232 (Initial Public Draft)</a>.</item>
    /// <item><a href="https://github.com/ascon/ascon-c">Reference, highly optimized, masked C and ASM implementations
    /// of Ascon (NIST SP 800-232)</a>.</item>
    /// </list>
    /// </remarks>
    public sealed class AsconAead128
        : IAeadCipher
    {
        private enum State
        {
            Uninitialized = 0,
            EncInit = 1,
            EncAad = 2,
            EncData = 3,
            EncFinal = 4,
            DecInit = 5,
            DecAad = 6,
            DecData = 7,
            DecFinal = 8,
        }

        private const ulong AsconIV = 0x00001000808c0001UL;
        private const int BufSizeDecrypt = Rate + CryptoABytes;
        private const int CryptoABytes = 16;
        private const int CryptoKeyBytes = 16;
        private const int Rate = 16;

        private readonly byte[] m_buf;

        private byte[] m_initialAssociatedText;
        private byte[] m_mac;
        private ulong K0, K1;
        private ulong N0, N1;
        private ulong S0, S1, S2, S3, S4;
        private State m_state = State.Uninitialized;
        private int m_bufPos = 0;

        public AsconAead128()
        {
            m_buf = new byte[BufSizeDecrypt];
        }

        public int GetKeyBytesSize() => CryptoKeyBytes;

        public int GetIVBytesSize() => CryptoABytes;

        public string AlgorithmName => "Ascon-AEAD128";

        public void Init(bool forEncryption, ICipherParameters parameters)
        {
            KeyParameter key;
#if NETCOREAPP2_1_OR_GREATER || NETSTANDARD2_1_OR_GREATER
            ReadOnlySpan<byte> npub;
#else
            byte[] npub;
#endif

            if (parameters is AeadParameters aeadParameters)
            {
                key = aeadParameters.Key;
#if NETCOREAPP2_1_OR_GREATER || NETSTANDARD2_1_OR_GREATER
                npub = aeadParameters.Nonce;
#else
                npub = aeadParameters.GetNonce();
#endif
                m_initialAssociatedText = aeadParameters.GetAssociatedText();

                int macSizeBits = aeadParameters.MacSize;
                if (macSizeBits != CryptoABytes * 8)
                    throw new ArgumentException($"Invalid value for MAC size: {macSizeBits}");
            }
            else if (parameters is ParametersWithIV withIV)
            {
                key = withIV.Parameters as KeyParameter;
#if NETCOREAPP2_1_OR_GREATER || NETSTANDARD2_1_OR_GREATER
                npub = withIV.IV;
#else
                npub = withIV.GetIV();
#endif
                m_initialAssociatedText = null;
            }
            else
            {
                throw new ArgumentException($"invalid parameters passed to {AlgorithmName}");
            }

            if (key == null)
                throw new ArgumentException($"{AlgorithmName} Init parameters must include a key");
            if (npub.Length != CryptoABytes)
                throw new ArgumentException($"{AlgorithmName} requires exactly {CryptoABytes} bytes of IV");

#if NETCOREAPP2_1_OR_GREATER || NETSTANDARD2_1_OR_GREATER
            var k = key.Key;
#else
            byte[] k = key.GetKey();
#endif

            if (k.Length != CryptoKeyBytes)
                throw new ArgumentException($"{AlgorithmName} key must be {CryptoABytes} bytes long");

            K0 = Pack.LE_To_UInt64(k, 0);
            K1 = Pack.LE_To_UInt64(k, 8);

            N0 = Pack.LE_To_UInt64(npub, 0);
            N1 = Pack.LE_To_UInt64(npub, 8);

            m_state = forEncryption ? State.EncInit : State.DecInit;

            Reset(clearMac: true);
        }

        public void ProcessAadByte(byte input)
        {
            CheckAad();

            m_buf[m_bufPos] = input;
            if (++m_bufPos == Rate)
            {
#if NETCOREAPP2_0_OR_GREATER || NETSTANDARD2_1_OR_GREATER
                ProcessBufferAad(m_buf);
#else
                ProcessBufferAad(m_buf, 0);
#endif
                m_bufPos = 0;
            }
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
                int available = Rate - m_bufPos;
                if (len < available)
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

            while (len >= Rate)
            {
                ProcessBufferAad(inBytes, inOff);
                inOff += Rate;
                len -= Rate;
            }

            Array.Copy(inBytes, inOff, m_buf, 0, len);
            m_bufPos = len;
#endif
        }

#if NETCOREAPP2_0_OR_GREATER || NETSTANDARD2_1_OR_GREATER
        public void ProcessAadBytes(ReadOnlySpan<byte> input)
        {
            // Don't enter AAD state until we actually get input
            if (input.IsEmpty)
                return;

            CheckAad();

            if (m_bufPos > 0)
            {
                int available = Rate - m_bufPos;
                if (input.Length < available)
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

            while (input.Length >= Rate)
            {
                ProcessBufferAad(input);
                input = input[Rate..];
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
                    int available = Rate - m_bufPos;
                    if (len < available)
                    {
                        Array.Copy(inBytes, inOff, m_buf, m_bufPos, len);
                        m_bufPos += len;
                        return 0;
                    }

                    Array.Copy(inBytes, inOff, m_buf, m_bufPos, available);
                    inOff += available;
                    len -= available;

                    ProcessBufferEncrypt(m_buf, 0, outBytes, outOff);
                    resultLength = Rate;
                    //m_bufPos = 0;
                }

                while (len >= Rate)
                {
                    ProcessBufferEncrypt(inBytes, inOff, outBytes, outOff + resultLength);
                    inOff += Rate;
                    len -= Rate;
                    resultLength += Rate;
                }
            }
            else
            {
                int available = BufSizeDecrypt - m_bufPos;
                if (len < available)
                {
                    Array.Copy(inBytes, inOff, m_buf, m_bufPos, len);
                    m_bufPos += len;
                    return 0;
                }

                // NOTE: Need 'while' here if Rate < CryptoABytes (as in some legacy parameter sets)
                Debug.Assert(Rate >= CryptoABytes);
                if (m_bufPos >= Rate)
                {
                    ProcessBufferDecrypt(m_buf, 0, outBytes, outOff + resultLength);
                    m_bufPos -= Rate;
                    Array.Copy(m_buf, Rate, m_buf, 0, m_bufPos);
                    resultLength += Rate;

                    available += Rate;
                    if (len < available)
                    {
                        Array.Copy(inBytes, inOff, m_buf, m_bufPos, len);
                        m_bufPos += len;
                        return resultLength;
                    }
                }

                available = Rate - m_bufPos;
                Array.Copy(inBytes, inOff, m_buf, m_bufPos, available);
                inOff += available;
                len -= available;
                ProcessBufferDecrypt(m_buf, 0, outBytes, outOff + resultLength);
                resultLength += Rate;
                //m_bufPos = 0;

                while (len >= BufSizeDecrypt)
                {
                    ProcessBufferDecrypt(inBytes, inOff, outBytes, outOff + resultLength);
                    inOff += Rate;
                    len -= Rate;
                    resultLength += Rate;
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
                    int available = Rate - m_bufPos;
                    if (input.Length < available)
                    {
                        input.CopyTo(m_buf.AsSpan(m_bufPos));
                        m_bufPos += input.Length;
                        return 0;
                    }

                    input[..available].CopyTo(m_buf.AsSpan(m_bufPos));
                    input = input[available..];

                    ProcessBufferEncrypt(m_buf, output);
                    resultLength = Rate;
                    //m_bufPos = 0;
                }

                while (input.Length >= Rate)
                {
                    ProcessBufferEncrypt(input, output[resultLength..]);
                    input = input[Rate..];
                    resultLength += Rate;
                }
            }
            else
            {
                int available = BufSizeDecrypt - m_bufPos;
                if (input.Length < available)
                {
                    input.CopyTo(m_buf.AsSpan(m_bufPos));
                    m_bufPos += input.Length;
                    return 0;
                }

                // NOTE: Need 'while' here if Rate < CryptoABytes (as in some legacy parameter sets)
                Debug.Assert(Rate >= CryptoABytes);
                if (m_bufPos >= Rate)
                {
                    ProcessBufferDecrypt(m_buf, output[resultLength..]);
                    m_bufPos -= Rate;
                    m_buf.AsSpan(0, m_bufPos).CopyFrom(m_buf.AsSpan(Rate));
                    resultLength += Rate;

                    available += Rate;
                    if (input.Length < available)
                    {
                        input.CopyTo(m_buf.AsSpan(m_bufPos));
                        m_bufPos += input.Length;
                        return resultLength;
                    }
                }

                available = Rate - m_bufPos;
                input[..available].CopyTo(m_buf.AsSpan(m_bufPos));
                input = input[available..];
                ProcessBufferDecrypt(m_buf, output[resultLength..]);
                resultLength += Rate;
                //m_bufPos = 0;

                while (input.Length >= BufSizeDecrypt)
                {
                    ProcessBufferDecrypt(input, output[resultLength..]);
                    input = input[Rate..];
                    resultLength += Rate;
                }
            }

            input.CopyTo(m_buf);
            m_bufPos = input.Length;

            return resultLength;
        }
#endif

        public int DoFinal(byte[] outBytes, int outOff)
        {
#if NETCOREAPP2_1_OR_GREATER || NETSTANDARD2_1_OR_GREATER
            return DoFinal(outBytes.AsSpan(outOff));
#else
            bool forEncryption = CheckData();

            int resultLength;
            if (forEncryption)
            {
                resultLength = m_bufPos + CryptoABytes;
                Check.OutputLength(outBytes, outOff, resultLength, "output buffer too short");

                ProcessFinalEncrypt(m_buf, 0, m_bufPos, outBytes, outOff);

                m_mac = new byte[CryptoABytes];
                Pack.UInt64_To_LE(S3, m_mac, 0);
                Pack.UInt64_To_LE(S4, m_mac, 8);
                Array.Copy(m_mac, 0, outBytes, outOff + m_bufPos, CryptoABytes);

                Reset(clearMac: false);
            }
            else
            {
                if (m_bufPos < CryptoABytes)
                    throw new InvalidCipherTextException("data too short");

                m_bufPos -= CryptoABytes;

                resultLength = m_bufPos;
                Check.OutputLength(outBytes, outOff, resultLength, "output buffer too short");

                ProcessFinalDecrypt(m_buf, 0, m_bufPos, outBytes, outOff);

                S3 ^= Pack.LE_To_UInt64(m_buf, m_bufPos);
                S4 ^= Pack.LE_To_UInt64(m_buf, m_bufPos + 8);
                if ((S3 | S4) != 0UL)
                    throw new InvalidCipherTextException($"mac check in {AlgorithmName} failed");

                Reset(clearMac: true);
            }
            return resultLength;
#endif
        }

#if NETCOREAPP2_1_OR_GREATER || NETSTANDARD2_1_OR_GREATER
        public int DoFinal(Span<byte> output)
        {
            bool forEncryption = CheckData();

            int resultLength;
            if (forEncryption)
            {
                resultLength = m_bufPos + CryptoABytes;
                Check.OutputLength(output, resultLength, "output buffer too short");

                ProcessFinalEncrypt(m_buf.AsSpan(0, m_bufPos), output);

                m_mac = new byte[CryptoABytes];
                Pack.UInt64_To_LE(S3, m_mac.AsSpan());
                Pack.UInt64_To_LE(S4, m_mac.AsSpan(8));
                m_mac.CopyTo(output[m_bufPos..]);

                Reset(clearMac: false);
            }
            else
            {
                if (m_bufPos < CryptoABytes)
                    throw new InvalidCipherTextException("data too short");

                m_bufPos -= CryptoABytes;

                resultLength = m_bufPos;
                Check.OutputLength(output, resultLength, "output buffer too short");

                ProcessFinalDecrypt(m_buf.AsSpan(0, m_bufPos), output);

                S3 ^= Pack.LE_To_UInt64(m_buf.AsSpan(m_bufPos));
                S4 ^= Pack.LE_To_UInt64(m_buf.AsSpan(m_bufPos + 8));
                if ((S3 | S4) != 0UL)
                    throw new InvalidCipherTextException($"mac check in {AlgorithmName} failed");

                Reset(clearMac: true);
            }
            return resultLength;
        }
#endif

        public byte[] GetMac() => m_mac;

        public int GetUpdateOutputSize(int len)
        {
            int total = System.Math.Max(0, len);

            switch (m_state)
            {
            case State.DecInit:
            case State.DecAad:
                total = System.Math.Max(0, total - CryptoABytes);
                break;
            case State.DecData:
            case State.DecFinal:
                total = System.Math.Max(0, total + m_bufPos - CryptoABytes);
                break;
            case State.EncData:
            case State.EncFinal:
                total += m_bufPos;
                break;
            default:
                break;
            }

            return total - total % Rate;
        }

        public int GetOutputSize(int len)
        {
            int total = System.Math.Max(0, len);

            switch (m_state)
            {
            case State.DecInit:
            case State.DecAad:
                return System.Math.Max(0, total - CryptoABytes);
            case State.DecData:
            case State.DecFinal:
                return System.Math.Max(0, total + m_bufPos - CryptoABytes);
            case State.EncData:
            case State.EncFinal:
                return total + m_bufPos + CryptoABytes;
            default:
                return total + CryptoABytes;
            }
        }

        public void Reset() => Reset(true);

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
                throw new InvalidOperationException($"{AlgorithmName} cannot be reused for encryption");
            default:
                throw new InvalidOperationException($"{AlgorithmName} needs to be initialized");
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
                throw new InvalidOperationException($"{AlgorithmName} cannot be reused for encryption");
            default:
                throw new InvalidOperationException($"{AlgorithmName} needs to be initialized");
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
                // Pad buffer instead of XOR with Pad(m_bufPos)
                m_buf[m_bufPos] = 0x01;

                if (m_bufPos >= 8) // Rate == 16 is implied
                {
                    S0 ^= Pack.LE_To_UInt64(m_buf, 0);
                    S1 ^= Pack.LE_To_UInt64(m_buf, 8) & (ulong.MaxValue >> (56 - ((m_bufPos - 8) << 3)));
                }
                else
                {
                    S0 ^= Pack.LE_To_UInt64(m_buf, 0) & (ulong.MaxValue >> (56 - (m_bufPos << 3)));
                }

                P8();
                break;
            }
            default:
                break;
            }

            // domain separation
            S4 ^= 0x8000000000000000UL;

            m_bufPos = 0;
            m_state = nextState;
        }

        private void FinishData(State nextState)
        {
            S2 ^= K0;
            S3 ^= K1;
            P12();
            S3 ^= K0;
            S4 ^= K1;

            m_state = nextState;
        }

        private void InitState()
        {
            S0 = AsconIV;
            S1 = K0;
            S2 = K1;
            S3 = N0;
            S4 = N1;
            P12();
            S3 ^= K0;
            S4 ^= K1;
        }

        private void P8()
        {
            Round(0xb4UL);
            Round(0xa5UL);
            Round(0x96UL);
            Round(0x87UL);
            Round(0x78UL);
            Round(0x69UL);
            Round(0x5aUL);
            Round(0x4bUL);
        }

        private void P12()
        {
            Round(0xf0UL);
            Round(0xe1UL);
            Round(0xd2UL);
            Round(0xc3UL);
            Round(0xb4UL);
            Round(0xa5UL);
            Round(0x96UL);
            Round(0x87UL);
            Round(0x78UL);
            Round(0x69UL);
            Round(0x5aUL);
            Round(0x4bUL);
        }

#if NETCOREAPP2_0_OR_GREATER || NETSTANDARD2_1_OR_GREATER
        private void ProcessBufferAad(ReadOnlySpan<byte> buffer)
        {
            Debug.Assert(buffer.Length >= Rate);

            S0 ^= Pack.LE_To_UInt64(buffer);
            S1 ^= Pack.LE_To_UInt64(buffer[8..]);

            P8();
        }

        private void ProcessBufferDecrypt(ReadOnlySpan<byte> buffer, Span<byte> output)
        {
            Debug.Assert(buffer.Length >= Rate);

            Check.OutputLength(output, Rate, "output buffer too short");

            ulong t0 = Pack.LE_To_UInt64(buffer);
            Pack.UInt64_To_LE(S0 ^ t0, output);
            S0 = t0;

            ulong t1 = Pack.LE_To_UInt64(buffer[8..]);
            Pack.UInt64_To_LE(S1 ^ t1, output[8..]);
            S1 = t1;

            P8();
        }

        private void ProcessBufferEncrypt(ReadOnlySpan<byte> buffer, Span<byte> output)
        {
            Debug.Assert(buffer.Length >= Rate);

            Check.OutputLength(output, Rate, "output buffer too short");

            S0 ^= Pack.LE_To_UInt64(buffer);
            Pack.UInt64_To_LE(S0, output);

            S1 ^= Pack.LE_To_UInt64(buffer[8..]);
            Pack.UInt64_To_LE(S1, output[8..]);

            P8();
        }

        private void ProcessFinalDecrypt(ReadOnlySpan<byte> input, Span<byte> output)
        {
            Debug.Assert(input.Length < Rate);

            if (input.Length >= 8) // Rate == 16 is implied
            {
                ulong t0 = Pack.LE_To_UInt64(input);
                Pack.UInt64_To_LE(S0 ^ t0, output);
                S0 = t0;

                input = input[8..];
                if (!input.IsEmpty)
                {
                    ProcessFinalDecrypt64(input, output[8..], ref S1);
                }

                S1 ^= Pad(input.Length);
            }
            else
            {
                if (!input.IsEmpty)
                {
                    ProcessFinalDecrypt64(input, output, ref S0);
                }

                S0 ^= Pad(input.Length);
            }

            FinishData(State.DecFinal);
        }

        private static void ProcessFinalDecrypt64(ReadOnlySpan<byte> input, Span<byte> output, ref ulong s)
        {
            int inLen = input.Length;
            Debug.Assert(1 <= inLen && inLen < 8);

            ulong t = Pack.LE_To_UInt64_Low(input);
            Pack.UInt64_To_LE_Low(s ^ t, output[..inLen]);
            s &= ulong.MaxValue << (inLen << 3);
            s ^= t;
        }

        private void ProcessFinalEncrypt(ReadOnlySpan<byte> input, Span<byte> output)
        {
            Debug.Assert(input.Length < Rate);

            if (input.Length >= 8) // Rate == 16 is implied
            {
                S0 ^= Pack.LE_To_UInt64(input);
                Pack.UInt64_To_LE(S0, output);

                input = input[8..];
                if (!input.IsEmpty)
                {
                    ProcessFinalEncrypt64(input, output[8..], ref S1);
                }

                S1 ^= Pad(input.Length - 8);
            }
            else
            {
                if (!input.IsEmpty)
                {
                    ProcessFinalEncrypt64(input, output, ref S0);
                }

                S0 ^= Pad(input.Length);
            }

            FinishData(State.EncFinal);
        }

        private static void ProcessFinalEncrypt64(ReadOnlySpan<byte> input, Span<byte> output, ref ulong s)
        {
            int inLen = input.Length;
            Debug.Assert(1 <= inLen && inLen < 8);

            s ^= Pack.LE_To_UInt64_Low(input);
            Pack.UInt64_To_LE_Low(s, output[..inLen]);
        }
#else
        private void ProcessBufferAad(byte[] buffer, int bufOff)
        {
            Debug.Assert(bufOff <= buffer.Length - Rate);

			S0 ^= Pack.LE_To_UInt64(buffer, bufOff);
			S1 ^= Pack.LE_To_UInt64(buffer, bufOff + 8);

			P8();
		}

        private void ProcessBufferDecrypt(byte[] buffer, int bufOff, byte[] output, int outOff)
		{
            Debug.Assert(bufOff <= buffer.Length - Rate);

            Check.OutputLength(output, outOff, Rate, "output buffer too short");

            ulong t0 = Pack.LE_To_UInt64(buffer, bufOff);
            Pack.UInt64_To_LE(S0 ^ t0, output, outOff);
            S0 = t0;

			ulong t1 = Pack.LE_To_UInt64(buffer, bufOff + 8);
            Pack.UInt64_To_LE(S1 ^ t1, output, outOff + 8);
			S1 = t1;

			P8();
		}

        private void ProcessBufferEncrypt(byte[] buffer, int bufOff, byte[] output, int outOff)
		{
            Debug.Assert(bufOff <= buffer.Length - Rate);

            Check.OutputLength(output, outOff, Rate, "output buffer too short");

            S0 ^= Pack.LE_To_UInt64(buffer, bufOff);
            Pack.UInt64_To_LE(S0, output, outOff);

			S1 ^= Pack.LE_To_UInt64(buffer, bufOff + 8);
            Pack.UInt64_To_LE(S1, output, outOff + 8);

			P8();
		}

        private void ProcessFinalDecrypt(byte[] input, int inOff, int inLen, byte[] output, int outOff)
		{
            Debug.Assert(inLen < Rate);

            if (inLen >= 8) // Rate == 16 is implied
			{
				ulong t0 = Pack.LE_To_UInt64(input, inOff);
                Pack.UInt64_To_LE(S0 ^ t0, output, outOff);
                S0 = t0;

                inLen -= 8;
                if (inLen > 0)
                {
                    ProcessFinalDecrypt64(input, inOff + 8, inLen, output, outOff + 8, ref S1);
                }

                S1 ^= Pad(inLen);
			}
			else
			{
				if (inLen > 0)
				{
                    ProcessFinalDecrypt64(input, inOff, inLen, output, outOff, ref S0);
				}

				S0 ^= Pad(inLen);
			}

			FinishData(State.DecFinal);
		}

        private static void ProcessFinalDecrypt64(byte[] input, int inOff, int inLen, byte[] output, int outOff,
            ref ulong s)
        {
            Debug.Assert(1 <= inLen && inLen < 8);

            ulong t = Pack.LE_To_UInt64_Low(input, inOff, inLen);
            Pack.UInt64_To_LE_Low(s ^ t, output, outOff, inLen);
            s &= ulong.MaxValue << (inLen << 3);
            s ^= t;
        }

        private void ProcessFinalEncrypt(byte[] input, int inOff, int inLen, byte[] output, int outOff)
		{
            Debug.Assert(inLen < Rate);

            if (inLen >= 8) // Rate == 16 is implied
			{
				S0 ^= Pack.LE_To_UInt64(input, inOff);
                Pack.UInt64_To_LE(S0, output, outOff);

                inLen -= 8;
                if (inLen > 0)
                {
                    ProcessFinalEncrypt64(input, inOff + 8, inLen, output, outOff + 8, ref S1);
                }

				S1 ^= Pad(inLen);
			}
			else
			{
				if (inLen > 0)
				{
                    ProcessFinalEncrypt64(input, inOff, inLen, output, outOff, ref S0);
				}

				S0 ^= Pad(inLen);
			}

			FinishData(State.EncFinal);
		}

        private static void ProcessFinalEncrypt64(byte[] input, int inOff, int inLen, byte[] output, int outOff,
            ref ulong s)
        {
            Debug.Assert(1 <= inLen && inLen < 8);

            s ^= Pack.LE_To_UInt64_Low(input, inOff, inLen);
            Pack.UInt64_To_LE_Low(s, output, outOff, inLen);
        }
#endif

        private void Reset(bool clearMac)
        {
            if (clearMac)
            {
                m_mac = null;
            }

            Array.Clear(m_buf, 0, m_buf.Length);
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
                throw new InvalidOperationException($"{AlgorithmName} needs to be initialized");
            }

            // NOTE: No caching since the key and/or nonce should change for every operation
            InitState();

            if (m_initialAssociatedText != null)
            {
#if NETCOREAPP2_1_OR_GREATER || NETSTANDARD2_1_OR_GREATER
                ProcessAadBytes(m_initialAssociatedText);
#else
                ProcessAadBytes(m_initialAssociatedText, 0, m_initialAssociatedText.Length);
#endif
            }
        }

#if NETSTANDARD1_0_OR_GREATER || NETCOREAPP1_0_OR_GREATER
        [MethodImpl(MethodImplOptions.AggressiveInlining)]
#endif
        private void Round(ulong c)
        {
            ulong SX = S2 ^ c;
            ulong t0 = S0 ^ S1 ^ SX ^ S3 ^ (S1 & (S0 ^ SX ^ S4));
            ulong t1 = S0 ^ SX ^ S3 ^ S4 ^ ((S1 ^ SX) & (S1 ^ S3));
            ulong t2 = S1 ^ SX ^ S4 ^ (S3 & S4);
            ulong t3 = S0 ^ S1 ^ SX ^ (~S0 & (S3 ^ S4));
            ulong t4 = S1 ^ S3 ^ S4 ^ ((S0 ^ S4) & S1);
            S0 = t0 ^ Longs.RotateRight(t0, 19) ^ Longs.RotateRight(t0, 28);
            S1 = t1 ^ Longs.RotateRight(t1, 39) ^ Longs.RotateRight(t1, 61);
            S2 = ~(t2 ^ Longs.RotateRight(t2, 1) ^ Longs.RotateRight(t2, 6));
            S3 = t3 ^ Longs.RotateRight(t3, 10) ^ Longs.RotateRight(t3, 17);
            S4 = t4 ^ Longs.RotateRight(t4, 7) ^ Longs.RotateRight(t4, 41);
        }

#if NETSTANDARD1_0_OR_GREATER || NETCOREAPP1_0_OR_GREATER
        [MethodImpl(MethodImplOptions.AggressiveInlining)]
#endif
        private static ulong Pad(int i) => 0x01UL << (i << 3);
    }
}
