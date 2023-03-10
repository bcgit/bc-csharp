using System;
using System.Diagnostics;
#if NETSTANDARD1_0_OR_GREATER || NETCOREAPP1_0_OR_GREATER
using System.Runtime.CompilerServices;
#endif

using Org.BouncyCastle.Crypto.Modes;
using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.Crypto.Utilities;
using Org.BouncyCastle.Utilities;

namespace Org.BouncyCastle.Crypto.Engines
{
    /// <summary>ASCON v1.2 AEAD, https://ascon.iaik.tugraz.at/ .</summary>
    /// <remarks>
    /// https://csrc.nist.gov/CSRC/media/Projects/lightweight-cryptography/documents/finalist-round/updated-spec-doc/ascon-spec-final.pdf<br/>
    /// ASCON v1.2 AEAD with reference to C Reference Impl from: https://github.com/ascon/ascon-c .
    /// </remarks>
    public sealed class AsconEngine
        : IAeadCipher
    {
        public enum AsconParameters
        {
            ascon80pq,
            ascon128a,
            ascon128,
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

        private readonly AsconParameters asconParameters;
        private readonly int CRYPTO_KEYBYTES;
        private readonly int CRYPTO_ABYTES;
        private readonly int ASCON_AEAD_RATE;
        private readonly int nr;
        private byte[] mac;
        private ulong K0;
        private ulong K1;
        private ulong K2;
        private ulong N0;
        private ulong N1;
        private readonly ulong ASCON_IV;
        private ulong x0;
        private ulong x1;
        private ulong x2;
        private ulong x3;
        private ulong x4;
        private string algorithmName;
        private State m_state = State.Uninitialized;
        private byte[] initialAssociatedText;

        private readonly int m_bufferSizeDecrypt;
        private readonly byte[] m_buf;
        private int m_bufPos = 0;

        public AsconEngine(AsconParameters asconParameters)
        {
            this.asconParameters = asconParameters;
            switch (asconParameters)
            {
            case AsconParameters.ascon80pq:
                CRYPTO_KEYBYTES = 20;
                CRYPTO_ABYTES = 16;
                ASCON_AEAD_RATE = 8;
                ASCON_IV = 0xa0400c0600000000UL;
                algorithmName = "Ascon-80pq AEAD";
                break;
            case AsconParameters.ascon128a:
                CRYPTO_KEYBYTES = 16;
                CRYPTO_ABYTES = 16;
                ASCON_AEAD_RATE = 16;
                ASCON_IV = 0x80800c0800000000UL;
                algorithmName = "Ascon-128a AEAD";
                break;
            case AsconParameters.ascon128:
                CRYPTO_KEYBYTES = 16;
                CRYPTO_ABYTES = 16;
                ASCON_AEAD_RATE = 8;
                ASCON_IV = 0x80400c0600000000UL;
                algorithmName = "Ascon-128 AEAD";
                break;
            default:
                throw new ArgumentException("invalid parameter setting for ASCON AEAD");
            }
            nr = (ASCON_AEAD_RATE == 8) ? 6 : 8;

            m_bufferSizeDecrypt = ASCON_AEAD_RATE + CRYPTO_ABYTES;
            m_buf = new byte[m_bufferSizeDecrypt];
        }

        public int GetKeyBytesSize()
        {
            return CRYPTO_KEYBYTES;
        }

        public int GetIVBytesSize()
        {
            return CRYPTO_ABYTES;
        }

        public string AlgorithmName => algorithmName;

        public void Init(bool forEncryption, ICipherParameters parameters)
        {
            KeyParameter key;
            byte[] npub;

            if (parameters is AeadParameters aeadParameters)
            {
                key = aeadParameters.Key;
                npub = aeadParameters.GetNonce();
                initialAssociatedText = aeadParameters.GetAssociatedText();

                int macSizeBits = aeadParameters.MacSize;
                if (macSizeBits != CRYPTO_ABYTES * 8)
                    throw new ArgumentException("Invalid value for MAC size: " + macSizeBits);
            }
            else if (parameters is ParametersWithIV withIV)
            {
                key = withIV.Parameters as KeyParameter;
                npub = withIV.GetIV();
                initialAssociatedText = null;
            }
            else
            {
                throw new ArgumentException("invalid parameters passed to Ascon");
            }

            if (key == null)
                throw new ArgumentException("Ascon Init parameters must include a key");
            if (npub == null || npub.Length != CRYPTO_ABYTES)
                throw new ArgumentException(asconParameters + " requires exactly " + CRYPTO_ABYTES + " bytes of IV");

#if NETCOREAPP2_1_OR_GREATER || NETSTANDARD2_1_OR_GREATER
            var k = key.Key;
#else
            byte[] k = key.GetKey();
#endif

            if (k.Length != CRYPTO_KEYBYTES)
                throw new ArgumentException(asconParameters + " key must be " + CRYPTO_KEYBYTES + " bytes long");

            N0 = Pack.BE_To_UInt64(npub, 0);
            N1 = Pack.BE_To_UInt64(npub, 8);

            if (CRYPTO_KEYBYTES == 16)
            {
#if NETCOREAPP2_1_OR_GREATER || NETSTANDARD2_1_OR_GREATER
                K1 = Pack.BE_To_UInt64(k);
                K2 = Pack.BE_To_UInt64(k[8..]);
#else
                K1 = Pack.BE_To_UInt64(k, 0);
                K2 = Pack.BE_To_UInt64(k, 8);
#endif
            }
            else if (CRYPTO_KEYBYTES == 20)
            {
#if NETCOREAPP2_1_OR_GREATER || NETSTANDARD2_1_OR_GREATER
                K0 = Pack.BE_To_UInt32(k);
                K1 = Pack.BE_To_UInt64(k[4..]);
                K2 = Pack.BE_To_UInt64(k[12..]);
#else
                K0 = Pack.BE_To_UInt32(k, 0);
                K1 = Pack.BE_To_UInt64(k, 4);
                K2 = Pack.BE_To_UInt64(k, 12);
#endif
            }
            else
            {
                throw new InvalidOperationException();
            }

            m_state = forEncryption ? State.EncInit : State.DecInit;

            Reset(true);
        }

        public void ProcessAadByte(byte input)
        {
            CheckAad();

            m_buf[m_bufPos] = input;
            if (++m_bufPos == ASCON_AEAD_RATE)
            {
#if NETCOREAPP2_1_OR_GREATER || NETSTANDARD2_1_OR_GREATER
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
                int available = ASCON_AEAD_RATE - m_bufPos;
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

            while (len >= ASCON_AEAD_RATE)
            {
                ProcessBufferAad(inBytes, inOff);
                inOff += ASCON_AEAD_RATE;
                len -= ASCON_AEAD_RATE;
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
                int available = ASCON_AEAD_RATE - m_bufPos;
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

            while (input.Length >= ASCON_AEAD_RATE)
            {
                ProcessBufferAad(input);
                input = input[ASCON_AEAD_RATE..];
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
                    int available = ASCON_AEAD_RATE - m_bufPos;
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
                    resultLength = ASCON_AEAD_RATE;
                    //m_bufPos = 0;
                }

                while (len >= ASCON_AEAD_RATE)
                {
                    ProcessBufferEncrypt(inBytes, inOff, outBytes, outOff + resultLength);
                    inOff += ASCON_AEAD_RATE;
                    len -= ASCON_AEAD_RATE;
                    resultLength += ASCON_AEAD_RATE;
                }
            }
            else
            {
                int available = m_bufferSizeDecrypt - m_bufPos;
                if (len < available)
                {
                    Array.Copy(inBytes, inOff, m_buf, m_bufPos, len);
                    m_bufPos += len;
                    return 0;
                }

                if (m_bufPos >= ASCON_AEAD_RATE)
                {
                    ProcessBufferDecrypt(m_buf, 0, outBytes, outOff);
                    m_bufPos -= ASCON_AEAD_RATE;
                    Array.Copy(m_buf, ASCON_AEAD_RATE, m_buf, 0, m_bufPos);
                    resultLength = ASCON_AEAD_RATE;

                    available += ASCON_AEAD_RATE;
                    if (len < available)
                    {
                        Array.Copy(inBytes, inOff, m_buf, m_bufPos, len);
                        m_bufPos += len;
                        return resultLength;
                    }
                }

                available = ASCON_AEAD_RATE - m_bufPos;
                Array.Copy(inBytes, inOff, m_buf, m_bufPos, available);
                inOff += available;
                len -= available;
                ProcessBufferDecrypt(m_buf, 0, outBytes, outOff + resultLength);
                resultLength += ASCON_AEAD_RATE;
                //m_bufPos = 0;

                while (len >= m_bufferSizeDecrypt)
                {
                    ProcessBufferDecrypt(inBytes, inOff, outBytes, outOff + resultLength);
                    inOff += ASCON_AEAD_RATE;
                    len -= ASCON_AEAD_RATE;
                    resultLength += ASCON_AEAD_RATE;
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
                    int available = ASCON_AEAD_RATE - m_bufPos;
                    if (input.Length < available)
                    {
                        input.CopyTo(m_buf.AsSpan(m_bufPos));
                        m_bufPos += input.Length;
                        return 0;
                    }

                    input[..available].CopyTo(m_buf.AsSpan(m_bufPos));
                    input = input[available..];

                    ProcessBufferEncrypt(m_buf, output);
                    resultLength = ASCON_AEAD_RATE;
                    //m_bufPos = 0;
                }

                while (input.Length >= ASCON_AEAD_RATE)
                {
                    ProcessBufferEncrypt(input, output[resultLength..]);
                    input = input[ASCON_AEAD_RATE..];
                    resultLength += ASCON_AEAD_RATE;
                }
            }
            else
            {
                int available = m_bufferSizeDecrypt - m_bufPos;
                if (input.Length < available)
                {
                    input.CopyTo(m_buf.AsSpan(m_bufPos));
                    m_bufPos += input.Length;
                    return 0;
                }

                if (m_bufPos >= ASCON_AEAD_RATE)
                {
                    ProcessBufferDecrypt(m_buf, output);
                    m_bufPos -= ASCON_AEAD_RATE;
                    m_buf.AsSpan(0, m_bufPos).CopyFrom(m_buf.AsSpan(ASCON_AEAD_RATE));
                    resultLength = ASCON_AEAD_RATE;

                    available += ASCON_AEAD_RATE;
                    if (input.Length < available)
                    {
                        input.CopyTo(m_buf.AsSpan(m_bufPos));
                        m_bufPos += input.Length;
                        return resultLength;
                    }
                }

                available = ASCON_AEAD_RATE - m_bufPos;
                input[..available].CopyTo(m_buf.AsSpan(m_bufPos));
                input = input[available..];
                ProcessBufferDecrypt(m_buf, output[resultLength..]);
                resultLength += ASCON_AEAD_RATE;
                //m_bufPos = 0;

                while (input.Length >= m_bufferSizeDecrypt)
                {
                    ProcessBufferDecrypt(input, output[resultLength..]);
                    input = input[ASCON_AEAD_RATE..];
                    resultLength += ASCON_AEAD_RATE;
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
                resultLength = m_bufPos + CRYPTO_ABYTES;
                Check.OutputLength(outBytes, outOff, resultLength, "output buffer too short");

                ProcessFinalEncrypt(m_buf, 0, m_bufPos, outBytes, outOff);

                mac = new byte[CRYPTO_ABYTES];
                Pack.UInt64_To_BE(x3, mac, 0);
                Pack.UInt64_To_BE(x4, mac, 8);
                Array.Copy(mac, 0, outBytes, outOff + m_bufPos, CRYPTO_ABYTES);

                Reset(false);
            }
            else
            {
                if (m_bufPos < CRYPTO_ABYTES)
                    throw new InvalidCipherTextException("data too short");

                m_bufPos -= CRYPTO_ABYTES;

                resultLength = m_bufPos;
                Check.OutputLength(outBytes, outOff, resultLength, "output buffer too short");

                ProcessFinalDecrypt(m_buf, 0, m_bufPos, outBytes, outOff);

                x3 ^= Pack.BE_To_UInt64(m_buf, m_bufPos);
                x4 ^= Pack.BE_To_UInt64(m_buf, m_bufPos + 8);
                if ((x3 | x4) != 0UL)
                    throw new InvalidCipherTextException("mac check in " + AlgorithmName + " failed");

                Reset(true);
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
                resultLength = m_bufPos + CRYPTO_ABYTES;
                Check.OutputLength(output, resultLength, "output buffer too short");

                ProcessFinalEncrypt(m_buf.AsSpan(0, m_bufPos), output);

                mac = new byte[CRYPTO_ABYTES];
                Pack.UInt64_To_BE(x3, mac.AsSpan());
                Pack.UInt64_To_BE(x4, mac.AsSpan(8));
                mac.CopyTo(output[m_bufPos..]);

                Reset(false);
            }
            else
            {
                if (m_bufPos < CRYPTO_ABYTES)
                    throw new InvalidCipherTextException("data too short");

                m_bufPos -= CRYPTO_ABYTES;

                resultLength = m_bufPos;
                Check.OutputLength(output, resultLength, "output buffer too short");

                ProcessFinalDecrypt(m_buf.AsSpan(0, m_bufPos), output);

                x3 ^= Pack.BE_To_UInt64(m_buf.AsSpan(m_bufPos));
                x4 ^= Pack.BE_To_UInt64(m_buf.AsSpan(m_bufPos + 8));
                if ((x3 | x4) != 0UL)
                    throw new InvalidCipherTextException("mac check in " + AlgorithmName + " failed");

                Reset(true);
            }
            return resultLength;
        }
#endif

        public byte[] GetMac()
        {
            return mac;
        }

        public int GetUpdateOutputSize(int len)
        {
            int total = System.Math.Max(0, len);

            switch (m_state)
            {
            case State.DecInit:
            case State.DecAad:
                total = System.Math.Max(0, total - CRYPTO_ABYTES);
                break;
            case State.DecData:
            case State.DecFinal:
                total = System.Math.Max(0, total + m_bufPos - CRYPTO_ABYTES);
                break;
            case State.EncData:
            case State.EncFinal:
                total += m_bufPos;
                break;
            default:
                break;
            }

            return total - total % ASCON_AEAD_RATE;
        }

        public int GetOutputSize(int len)
        {
            int total = System.Math.Max(0, len);

            switch (m_state)
            {
            case State.DecInit:
            case State.DecAad:
                return System.Math.Max(0, total - CRYPTO_ABYTES);
            case State.DecData:
            case State.DecFinal:
                return System.Math.Max(0, total + m_bufPos - CRYPTO_ABYTES);
            case State.EncData:
            case State.EncFinal:
                return total + m_bufPos + CRYPTO_ABYTES;
            default:
                return total + CRYPTO_ABYTES;
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
                m_buf[m_bufPos] = 0x80;

                if (m_bufPos >= 8) // ASCON_AEAD_RATE == 16 is implied
                {
                    x0 ^= Pack.BE_To_UInt64(m_buf, 0);
                    x1 ^= Pack.BE_To_UInt64(m_buf, 8) & (ulong.MaxValue << (56 - ((m_bufPos - 8) << 3)));
                }
                else
                {
                    x0 ^= Pack.BE_To_UInt64(m_buf, 0) & (ulong.MaxValue << (56 - (m_bufPos << 3)));
                }

                P(nr);
                break;
            }
            }

            // domain separation
            x4 ^= 1UL;

            m_bufPos = 0;
            m_state = nextState;
        }

        private void FinishData(State nextState)
        {
            switch (asconParameters)
            {
            case AsconParameters.ascon128:
                x1 ^= K1;
                x2 ^= K2;
                break;
            case AsconParameters.ascon128a:
                x2 ^= K1;
                x3 ^= K2;
                break;
            case AsconParameters.ascon80pq:
                x1 ^= (K0 << 32 | K1 >> 32);
                x2 ^= (K1 << 32 | K2 >> 32);
                x3 ^=  K2 << 32;
                break;
            default:
                throw new InvalidOperationException();
            }
            P(12);
            x3 ^= K1;
            x4 ^= K2;

            m_state = nextState;
        }

        private void P(int nr)
        {
            if (nr >= 8)
            {
                if (nr == 12)
                {
                    ROUND(0xf0UL);
                    ROUND(0xe1UL);
                    ROUND(0xd2UL);
                    ROUND(0xc3UL);
                }
                ROUND(0xb4UL);
                ROUND(0xa5UL);
            }
            ROUND(0x96UL);
            ROUND(0x87UL);
            ROUND(0x78UL);
            ROUND(0x69UL);
            ROUND(0x5aUL);
            ROUND(0x4bUL);
        }

#if NETSTANDARD1_0_OR_GREATER || NETCOREAPP1_0_OR_GREATER
        [MethodImpl(MethodImplOptions.AggressiveInlining)]
#endif
        private void ROUND(ulong c)
        {
            ulong t0 = x0 ^ x1 ^ x2 ^ x3 ^ c ^ (x1 & (x0 ^ x2 ^ x4 ^ c));
            ulong t1 = x0 ^ x2 ^ x3 ^ x4 ^ c ^ ((x1 ^ x2 ^ c) & (x1 ^ x3));
            ulong t2 = x1 ^ x2 ^ x4 ^ c ^ (x3 & x4);
            ulong t3 = x0 ^ x1 ^ x2 ^ c ^ ((~x0) & (x3 ^ x4));
            ulong t4 = x1 ^ x3 ^ x4 ^ ((x0 ^ x4) & x1);
            x0 = t0 ^ Longs.RotateRight(t0, 19) ^ Longs.RotateRight(t0, 28);
            x1 = t1 ^ Longs.RotateRight(t1, 39) ^ Longs.RotateRight(t1, 61);
            x2 = ~(t2 ^ Longs.RotateRight(t2, 1) ^ Longs.RotateRight(t2, 6));
            x3 = t3 ^ Longs.RotateRight(t3, 10) ^ Longs.RotateRight(t3, 17);
            x4 = t4 ^ Longs.RotateRight(t4, 7) ^ Longs.RotateRight(t4, 41);
        }

        private void ascon_aeadinit()
        {
            x0 = ASCON_IV;
            if (CRYPTO_KEYBYTES == 20)
            {
                x0 ^= K0;
            }
            x1 = K1;
            x2 = K2;
            x3 = N0;
            x4 = N1;
            P(12);
            if (CRYPTO_KEYBYTES == 20)
            {
                x2 ^= K0;
            }
            x3 ^= K1;
            x4 ^= K2;
        }

#if NETCOREAPP2_1_OR_GREATER || NETSTANDARD2_1_OR_GREATER
        private void ProcessBufferAad(ReadOnlySpan<byte> buffer)
        {
            Debug.Assert(buffer.Length >= ASCON_AEAD_RATE);

            x0 ^= Pack.BE_To_UInt64(buffer);
            if (ASCON_AEAD_RATE == 16)
            {
                x1 ^= Pack.BE_To_UInt64(buffer[8..]);
            }
            P(nr);
        }

        private void ProcessBufferDecrypt(ReadOnlySpan<byte> buffer, Span<byte> output)
        {
            Debug.Assert(buffer.Length >= ASCON_AEAD_RATE);

            Check.OutputLength(output, ASCON_AEAD_RATE, "output buffer too short");

            {
                ulong c0 = Pack.BE_To_UInt64(buffer);
                Pack.UInt64_To_BE(x0 ^ c0, output);
                x0 = c0;
            }
            if (ASCON_AEAD_RATE == 16)
            {
                ulong c1 = Pack.BE_To_UInt64(buffer[8..]);
                Pack.UInt64_To_BE(x1 ^ c1, output[8..]);
                x1 = c1;
            }
            P(nr);
        }

        private void ProcessBufferEncrypt(ReadOnlySpan<byte> buffer, Span<byte> output)
        {
            Debug.Assert(buffer.Length >= ASCON_AEAD_RATE);

            Check.OutputLength(output, ASCON_AEAD_RATE, "output buffer too short");

            {
                x0 ^= Pack.BE_To_UInt64(buffer);
                Pack.UInt64_To_BE(x0, output);
            }
            if (ASCON_AEAD_RATE == 16)
            {
                x1 ^= Pack.BE_To_UInt64(buffer[8..]);
                Pack.UInt64_To_BE(x1, output[8..]);
            }
            P(nr);
        }

        private void ProcessFinalDecrypt(ReadOnlySpan<byte> input, Span<byte> output)
        {
            Debug.Assert(input.Length < ASCON_AEAD_RATE);

            if (input.Length >= 8) // ASCON_AEAD_RATE == 16 is implied
            {
                ulong cx = Pack.BE_To_UInt64(input);
                x0 ^= cx;
                Pack.UInt64_To_BE(x0, output);
                x0 = cx;
                input = input[8..];
                output = output[8..];
                x1 ^= PAD(input.Length);
                if (!input.IsEmpty)
                {
                    cx = Pack.BE_To_UInt64_High(input);
                    x1 ^= cx;
                    Pack.UInt64_To_BE_High(x1, output[..input.Length]);
                    x1 &= ulong.MaxValue >> (input.Length << 3);
                    x1 ^= cx;
                }
            }
            else
            {
                x0 ^= PAD(input.Length);
                if (!input.IsEmpty)
                {
                    ulong cx = Pack.BE_To_UInt64_High(input);
                    x0 ^= cx;
                    Pack.UInt64_To_BE_High(x0, output[..input.Length]);
                    x0 &= ulong.MaxValue >> (input.Length << 3);
                    x0 ^= cx;
                }
            }

            FinishData(State.DecFinal);
        }

        private void ProcessFinalEncrypt(ReadOnlySpan<byte> input, Span<byte> output)
        {
            Debug.Assert(input.Length < ASCON_AEAD_RATE);

            if (input.Length >= 8) // ASCON_AEAD_RATE == 16 is implied
            {
                x0 ^= Pack.BE_To_UInt64(input);
                Pack.UInt64_To_BE(x0, output);
                input = input[8..];
                output = output[8..];
                x1 ^= PAD(input.Length);
                if (!input.IsEmpty)
                {
                    x1 ^= Pack.BE_To_UInt64_High(input);
                    Pack.UInt64_To_BE_High(x1, output[..input.Length]);
                }
            }
            else
            {
                x0 ^= PAD(input.Length);
                if (!input.IsEmpty)
                {
                    x0 ^= Pack.BE_To_UInt64_High(input);
                    Pack.UInt64_To_BE_High(x0, output[..input.Length]);
                }
            }

            FinishData(State.EncFinal);
        }
#else
        private void ProcessBufferAad(byte[] buffer, int bufOff)
        {
            Debug.Assert(bufOff <= buffer.Length - ASCON_AEAD_RATE);

            x0 ^= Pack.BE_To_UInt64(buffer, bufOff);

            if (ASCON_AEAD_RATE == 16)
            {
                x1 ^= Pack.BE_To_UInt64(buffer, bufOff + 8);
            }

            P(nr);
        }

        private void ProcessBufferDecrypt(byte[] buffer, int bufOff, byte[] output, int outOff)
        {
            Debug.Assert(bufOff <= buffer.Length - ASCON_AEAD_RATE);

            Check.OutputLength(output, outOff, ASCON_AEAD_RATE, "output buffer too short");

            ulong t0 = Pack.BE_To_UInt64(buffer, bufOff);
            Pack.UInt64_To_BE(x0 ^ t0, output, outOff);
            x0 = t0;

            if (ASCON_AEAD_RATE == 16)
            {
                ulong t1 = Pack.BE_To_UInt64(buffer, bufOff + 8);
                Pack.UInt64_To_BE(x1 ^ t1, output, outOff + 8);
                x1 = t1;
            }

            P(nr);
        }

        private void ProcessBufferEncrypt(byte[] buffer, int bufOff, byte[] output, int outOff)
        {
            Debug.Assert(bufOff <= buffer.Length - ASCON_AEAD_RATE);

            Check.OutputLength(output, outOff, ASCON_AEAD_RATE, "output buffer too short");

            x0 ^= Pack.BE_To_UInt64(buffer, bufOff);
            Pack.UInt64_To_BE(x0, output, outOff);

            if (ASCON_AEAD_RATE == 16)
            {
                x1 ^= Pack.BE_To_UInt64(buffer, bufOff + 8);
                Pack.UInt64_To_BE(x1, output, outOff + 8);
            }

            P(nr);
        }

        private void ProcessFinalDecrypt(byte[] input, int inOff, int inLen, byte[] output, int outOff)
        {
            Debug.Assert(inLen < ASCON_AEAD_RATE);

            if (inLen >= 8) // ASCON_AEAD_RATE == 16 is implied
            {
                ulong c0 = Pack.BE_To_UInt64(input, inOff);
                x0 ^= c0;
                Pack.UInt64_To_BE(x0, output, outOff);
                x0 = c0;
                inOff += 8;
                outOff += 8;
                inLen -= 8;
                x1 ^= PAD(inLen);
                if (inLen != 0)
                {
                    ulong c1 = Pack.BE_To_UInt64_High(input, inOff, inLen);
                    x1 ^= c1;
                    Pack.UInt64_To_BE_High(x1, output, outOff, inLen);
                    x1 &= ulong.MaxValue >> (inLen << 3);
                    x1 ^= c1;
                }
            }
            else
            {
                x0 ^= PAD(inLen);
                if (inLen != 0)
                {
                    ulong c0 = Pack.BE_To_UInt64_High(input, inOff, inLen);
                    x0 ^= c0;
                    Pack.UInt64_To_BE_High(x0, output, outOff, inLen);
                    x0 &= ulong.MaxValue >> (inLen << 3);
                    x0 ^= c0;
                }
            }

            FinishData(State.DecFinal);
        }

        private void ProcessFinalEncrypt(byte[] input, int inOff, int inLen, byte[] output, int outOff)
        {
            Debug.Assert(inLen < ASCON_AEAD_RATE);

            if (inLen >= 8) // ASCON_AEAD_RATE == 16 is implied
            {
                x0 ^= Pack.BE_To_UInt64(input, inOff);
                Pack.UInt64_To_BE(x0, output, outOff);
                inOff += 8;
                outOff += 8;
                inLen -= 8;
                x1 ^= PAD(inLen);
                if (inLen != 0)
                {
                    x1 ^= Pack.BE_To_UInt64_High(input, inOff, inLen);
                    Pack.UInt64_To_BE_High(x1, output, outOff, inLen);
                }
            }
            else
            {
                x0 ^= PAD(inLen);
                if (inLen != 0)
                {
                    x0 ^= Pack.BE_To_UInt64_High(input, inOff, inLen);
                    Pack.UInt64_To_BE_High(x0, output, outOff, inLen);
                }
            }

            FinishData(State.EncFinal);
        }
#endif

        private void Reset(bool clearMac)
        {
            if (clearMac)
            {
                mac = null;
            }

            Arrays.Clear(m_buf);
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

            ascon_aeadinit();

            if (initialAssociatedText != null)
            {
#if NETCOREAPP2_1_OR_GREATER || NETSTANDARD2_1_OR_GREATER
                ProcessAadBytes(initialAssociatedText);
#else
                ProcessAadBytes(initialAssociatedText, 0, initialAssociatedText.Length);
#endif
            }
        }

        private static ulong PAD(int i)
        {
            return 0x8000000000000000UL >> (i << 3);
        }
    }
}
