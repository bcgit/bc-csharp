using System;
using System.IO;
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
            ascon128
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

        private readonly MemoryStream aadData = new MemoryStream();
        private readonly MemoryStream message = new MemoryStream();

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
            if (!(parameters is ParametersWithIV withIV))
                throw new ArgumentException("ASCON Init parameters must include an IV");

            byte[] npub = withIV.GetIV();
            if (npub == null || npub.Length != CRYPTO_ABYTES)
                throw new ArgumentException(asconParameters + " requires exactly " + CRYPTO_ABYTES + " bytes of IV");

            if (!(withIV.Parameters is KeyParameter key))
                throw new ArgumentException("ASCON Init parameters must include a key");

            byte[] k = key.GetKey();
            if (k.Length != CRYPTO_KEYBYTES)
                throw new ArgumentException(asconParameters + " key must be " + CRYPTO_KEYBYTES + " bytes long");

            N0 = Pack.BE_To_UInt64(npub, 0);
            N1 = Pack.BE_To_UInt64(npub, 8);
            if (CRYPTO_KEYBYTES == 16)
            {
                K1 = Pack.BE_To_UInt64(k, 0);
                K2 = Pack.BE_To_UInt64(k, 8);
            }
            else if (CRYPTO_KEYBYTES == 20)
            {
                K0 = Pack.BE_To_UInt32(k, 0);
                K1 = Pack.BE_To_UInt64(k, 4);
                K2 = Pack.BE_To_UInt64(k, 12);
            }
            else
            {
                throw new InvalidOperationException();
            }

            m_state = forEncryption ? State.EncInit : State.DecInit;

            Reset(false);
        }

        public void ProcessAadByte(byte input)
        {
            CheckAad();

            aadData.WriteByte(input);
        }

        public void ProcessAadBytes(byte[] inBytes, int inOff, int len)
        {
            Check.DataLength(inBytes, inOff, len, "input buffer too short");

            CheckAad();

            aadData.Write(inBytes, inOff, len);
        }

#if NETCOREAPP2_1_OR_GREATER || NETSTANDARD2_1_OR_GREATER
        public void ProcessAadBytes(ReadOnlySpan<byte> input)
        {
            CheckAad();

            aadData.Write(input);
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

            message.Write(inBytes, inOff, len);

            return ProcessBytes(forEncryption, outBytes, outOff);
#endif
        }

#if NETCOREAPP2_1_OR_GREATER || NETSTANDARD2_1_OR_GREATER
        public int ProcessBytes(ReadOnlySpan<byte> input, Span<byte> output)
        {
            bool forEncryption = CheckData();

            message.Write(input);

            return ProcessBytes(forEncryption, output);
        }
#endif

        public int DoFinal(byte[] outBytes, int outOff)
        {
#if NETCOREAPP2_1_OR_GREATER || NETSTANDARD2_1_OR_GREATER
            return DoFinal(outBytes.AsSpan(outOff));
#else
            bool forEncryption = CheckData();

            byte[] input = message.GetBuffer();
            int len = Convert.ToInt32(message.Length);

            if (forEncryption)
            {
                Check.OutputLength(outBytes, outOff, len + CRYPTO_ABYTES, "output buffer too short");
                ascon_final(true, outBytes, outOff, input, 0, len);
                mac = new byte[16];
                Pack.UInt64_To_BE(x3, mac, 0);
                Pack.UInt64_To_BE(x4, mac, 8);
                Array.Copy(mac, 0, outBytes, len + outOff, 16);
                Reset(false);
                return len + CRYPTO_ABYTES;
            }
            else
            {
                // TODO Check for underflow i.e. total input < CRYPTO_ABYTES
                Check.OutputLength(outBytes, outOff, len - CRYPTO_ABYTES, "output buffer too short");
                len -= CRYPTO_ABYTES;
                ascon_final(false, outBytes, outOff, input, 0, len);
                x3 ^= Pack.BE_To_UInt64(input, len);
                x4 ^= Pack.BE_To_UInt64(input, len + 8);
                ulong result = x3 | x4;

                if (result != 0UL)
                    throw new InvalidCipherTextException("mac check in " + AlgorithmName + " failed");

                Reset(true);
                return len;
            }
#endif
        }

#if NETCOREAPP2_1_OR_GREATER || NETSTANDARD2_1_OR_GREATER
        public int DoFinal(Span<byte> output)
        {
            bool forEncryption = CheckData();

            byte[] input = message.GetBuffer();
            int len = Convert.ToInt32(message.Length);

            if (forEncryption)
            {
                Check.OutputLength(output, len + CRYPTO_ABYTES, "output buffer too short");
                ascon_final(true, output, input.AsSpan(0, len));
                mac = new byte[CRYPTO_ABYTES];
                Pack.UInt64_To_BE(x3, mac, 0);
                Pack.UInt64_To_BE(x4, mac, 8);

                FinishData(State.EncFinal);

                mac.AsSpan(0, CRYPTO_ABYTES).CopyTo(output[len..]);
                Reset(false);
                return len + CRYPTO_ABYTES;
            }
            else
            {
                // TODO Check for underflow i.e. total input < CRYPTO_ABYTES
                Check.OutputLength(output, len - CRYPTO_ABYTES, "output buffer too short");
                len -= CRYPTO_ABYTES;
                ascon_final(false, output, input.AsSpan(0, len));
                x3 ^= Pack.BE_To_UInt64(input, len);
                x4 ^= Pack.BE_To_UInt64(input, len + 8);
                ulong result = x3 | x4;

                FinishData(State.DecFinal);

                if (result != 0UL)
                    throw new InvalidCipherTextException("mac check in " + AlgorithmName + " failed");

                Reset(true);
                return len;
            }
        }
#endif

        public byte[] GetMac()
        {
            return mac;
        }

        public int GetUpdateOutputSize(int len)
        {
            int total = Convert.ToInt32(message.Length + System.Math.Max(0, len));

            switch (m_state)
            {
            case State.DecInit:
            case State.DecAad:
            case State.DecData:
            case State.DecFinal:
                total = System.Math.Max(0, total - CRYPTO_ABYTES);
                break;
            default:
                break;
            }

            return total - total % ASCON_AEAD_RATE;
        }

        public int GetOutputSize(int len)
        {
            int total = Convert.ToInt32(message.Length + System.Math.Max(0, len));

            switch (m_state)
            {
            case State.DecInit:
            case State.DecAad:
            case State.DecData:
            case State.DecFinal:
                return System.Math.Max(0, total - CRYPTO_ABYTES);
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
                throw new InvalidOperationException();
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
                throw new InvalidOperationException();
            }
        }

        private void FinishAad(State nextState)
        {
            byte[] aad = aadData.GetBuffer();
            int aadLen = Convert.ToInt32(aadData.Length);

#if NETCOREAPP2_1_OR_GREATER || NETSTANDARD2_1_OR_GREATER
            ascon_adata(aad.AsSpan(0, aadLen));
#else
            ascon_adata(aad, 0, aadLen);
#endif

            m_state = nextState;
        }

        private void FinishData(State nextState)
        {
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
        private int ProcessBytes(bool forEncryption, Span<byte> output)
        {
            int msgLen = Convert.ToInt32(message.Length);
            int outLen = 0;
            if (forEncryption)
            {
                if (msgLen >= ASCON_AEAD_RATE)
                {
                    byte[] input = message.GetBuffer();
                    outLen = (msgLen / ASCON_AEAD_RATE) * ASCON_AEAD_RATE;
                    Check.OutputLength(output, outLen, "output buffer is too short");
                    ascon_encrypt(output, input.AsSpan(0, outLen));
                    message.SetLength(0);
                    message.Write(input, outLen, msgLen - outLen);
                }
            }
            else
            {
                if (msgLen - CRYPTO_ABYTES >= ASCON_AEAD_RATE)
                {
                    byte[] input = message.GetBuffer();
                    outLen = ((msgLen - CRYPTO_ABYTES) / ASCON_AEAD_RATE) * ASCON_AEAD_RATE;
                    Check.OutputLength(output, outLen, "output buffer is too short");
                    ascon_decrypt(output, input.AsSpan(0, outLen));
                    message.SetLength(0);
                    message.Write(input, outLen, msgLen - outLen);
                }
            }
            return outLen;
        }

        private void ascon_adata(ReadOnlySpan<byte> aad)
        {
            if (!aad.IsEmpty)
            {
                /* full associated data blocks */
                while (aad.Length >= ASCON_AEAD_RATE)
                {
                    x0 ^= Pack.BE_To_UInt64(aad);
                    if (ASCON_AEAD_RATE == 16)
                    {
                        x1 ^= Pack.BE_To_UInt64(aad[8..]);
                    }
                    P(nr);
                    aad = aad[ASCON_AEAD_RATE..];
                }
                /* final associated data block */
                if (ASCON_AEAD_RATE == 16 && aad.Length >= 8)
                {
                    x0 ^= Pack.BE_To_UInt64(aad);
                    aad = aad[8..];
                    x1 ^= PAD(aad.Length);
                    if (!aad.IsEmpty)
                    {
                        x1 ^= Pack.BE_To_UInt64_High(aad);
                    }
                }
                else
                {
                    x0 ^= PAD(aad.Length);
                    if (!aad.IsEmpty)
                    {
                        x0 ^= Pack.BE_To_UInt64_High(aad);
                    }
                }
                P(nr);
            }
            /* domain separation */
            x4 ^= 1UL;
        }

        private void ascon_encrypt(Span<byte> c, ReadOnlySpan<byte> m)
        {
            /* full plaintext blocks */
            while (m.Length >= ASCON_AEAD_RATE)
            {
                x0 ^= Pack.BE_To_UInt64(m);
                Pack.UInt64_To_BE(x0, c);
                if (ASCON_AEAD_RATE == 16)
                {
                    x1 ^= Pack.BE_To_UInt64(m[8..]);
                    Pack.UInt64_To_BE(x1, c[8..]);
                }
                P(nr);
                m = m[ASCON_AEAD_RATE..];
                c = c[ASCON_AEAD_RATE..];
            }
        }

        private void ascon_decrypt(Span<byte> m, ReadOnlySpan<byte> c)
        {
            /* full ciphertext blocks */
            while (c.Length >= ASCON_AEAD_RATE)
            {
                ulong cx = Pack.BE_To_UInt64(c);
                x0 ^= cx;
                Pack.UInt64_To_BE(x0, m);
                x0 = cx;
                if (ASCON_AEAD_RATE == 16)
                {
                    cx = Pack.BE_To_UInt64(c[8..]);
                    x1 ^= cx;
                    Pack.UInt64_To_BE(x1, m[8..]);
                    x1 = cx;
                }
                P(nr);
                c = c[ASCON_AEAD_RATE..];
                m = m[ASCON_AEAD_RATE..];
            }
        }

        private void ascon_final(bool forEncryption, Span<byte> output, ReadOnlySpan<byte> input)
        {
            if (forEncryption)
            {
                /* final plaintext block */
                if (ASCON_AEAD_RATE == 16 && input.Length >= 8)
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
            }
            else
            {
                /* final ciphertext block */
                if (ASCON_AEAD_RATE == 16 && input.Length >= 8)
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
            }
            /* finalize */
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
            }
            P(12);
            x3 ^= K1;
            x4 ^= K2;
        }
#else
        private int ProcessBytes(bool forEncryption, byte[] output, int outOff)
        {
            int msgLen = Convert.ToInt32(message.Length);
            int outLen = 0;
            if (forEncryption)
            {
                if (msgLen >= ASCON_AEAD_RATE)
                {
                    byte[] input = message.GetBuffer();
                    outLen = (msgLen / ASCON_AEAD_RATE) * ASCON_AEAD_RATE;
                    Check.OutputLength(output, outOff, outLen, "output buffer is too short");
                    ascon_encrypt(output, outOff, input, 0, outLen);
                    message.SetLength(0);
                    message.Write(input, outLen, msgLen - outLen);
                }
            }
            else
            {
                if (msgLen - CRYPTO_ABYTES >= ASCON_AEAD_RATE)
                {
                    byte[] input = message.GetBuffer();
                    outLen = ((msgLen - CRYPTO_ABYTES) / ASCON_AEAD_RATE) * ASCON_AEAD_RATE;
                    Check.OutputLength(output, outOff, outLen, "output buffer is too short");
                    ascon_decrypt(output, outOff, input, 0, outLen);
                    message.SetLength(0);
                    message.Write(input, outLen, msgLen - outLen);
                }
            }
            return outLen;
        }

        private void ascon_adata(byte[] aad, int aadOff, int aadLen)
        {
            if (aadLen != 0)
            {
                /* full associated data blocks */
                while (aadLen >= ASCON_AEAD_RATE)
                {
                    x0 ^= Pack.BE_To_UInt64(aad, aadOff);
                    if (ASCON_AEAD_RATE == 16)
                    {
                        x1 ^= Pack.BE_To_UInt64(aad, aadOff + 8);
                    }
                    P(nr);
                    aadOff += ASCON_AEAD_RATE;
                    aadLen -= ASCON_AEAD_RATE;
                }
                /* final associated data block */
                if (ASCON_AEAD_RATE == 16 && aadLen >= 8)
                {
                    x0 ^= Pack.BE_To_UInt64(aad, aadOff);
                    aadOff += 8;
                    aadLen -= 8;
                    x1 ^= PAD(aadLen);
                    if (aadLen != 0)
                    {
                        x1 ^= Pack.BE_To_UInt64_High(aad, aadOff, aadLen);
                    }
                }
                else
                {
                    x0 ^= PAD(aadLen);
                    if (aadLen != 0)
                    {
                        x0 ^= Pack.BE_To_UInt64_High(aad, aadOff, aadLen);
                    }
                }
                P(nr);
            }
            /* domain separation */
            x4 ^= 1UL;
        }

        private void ascon_encrypt(byte[] c, int cOff, byte[] m, int mOff, int mlen)
        {
            /* full plaintext blocks */
            while (mlen >= ASCON_AEAD_RATE)
            {
                x0 ^= Pack.BE_To_UInt64(m, mOff);
                Pack.UInt64_To_BE(x0, c, cOff);
                if (ASCON_AEAD_RATE == 16)
                {
                    x1 ^= Pack.BE_To_UInt64(m, mOff + 8);
                    Pack.UInt64_To_BE(x1, c, cOff + 8);
                }
                P(nr);
                mOff += ASCON_AEAD_RATE;
                cOff += ASCON_AEAD_RATE;
                mlen -= ASCON_AEAD_RATE;
            }
        }

        private void ascon_decrypt(byte[] m, int mOff, byte[] c, int cOff, int clen)
        {
            /* full ciphertext blocks */
            while (clen >= ASCON_AEAD_RATE)
            {
                ulong cx = Pack.BE_To_UInt64(c, cOff);
                x0 ^= cx;
                Pack.UInt64_To_BE(x0, m, mOff);
                x0 = cx;
                if (ASCON_AEAD_RATE == 16)
                {
                    cx = Pack.BE_To_UInt64(c, cOff + 8);
                    x1 ^= cx;
                    Pack.UInt64_To_BE(x1, m, mOff + 8);
                    x1 = cx;
                }
                P(nr);
                mOff += ASCON_AEAD_RATE;
                cOff += ASCON_AEAD_RATE;
                clen -= ASCON_AEAD_RATE;
            }
        }

        private void ascon_final(bool forEncryption, byte[] c, int cOff, byte[] m, int mOff, int mlen)
        {
            if (forEncryption)
            {
                /* final plaintext block */
                if (ASCON_AEAD_RATE == 16 && mlen >= 8)
                {
                    x0 ^= Pack.BE_To_UInt64(m, mOff);
                    Pack.UInt64_To_BE(x0, c, cOff);
                    mOff += 8;
                    cOff += 8;
                    mlen -= 8;
                    x1 ^= PAD(mlen);
                    if (mlen != 0)
                    {
                        x1 ^= Pack.BE_To_UInt64_High(m, mOff, mlen);
                        Pack.UInt64_To_BE_High(x1, c, cOff, mlen);
                    }
                }
                else
                {
                    x0 ^= PAD(mlen);
                    if (mlen != 0)
                    {
                        x0 ^= Pack.BE_To_UInt64_High(m, mOff, mlen);
                        Pack.UInt64_To_BE_High(x0, c, cOff, mlen);
                    }
                }
            }
            else
            {
                /* final ciphertext block */
                if (ASCON_AEAD_RATE == 16 && mlen >= 8)
                {
                    ulong cx = Pack.BE_To_UInt64(m, mOff);
                    x0 ^= cx;
                    Pack.UInt64_To_BE(x0, c, cOff);
                    x0 = cx;
                    mOff += 8;
                    cOff += 8;
                    mlen -= 8;
                    x1 ^= PAD(mlen);
                    if (mlen != 0)
                    {
                        cx = Pack.BE_To_UInt64_High(m, mOff, mlen);
                        x1 ^= cx;
                        Pack.UInt64_To_BE_High(x1, c, cOff, mlen);
                        x1 &= ulong.MaxValue >> (mlen << 3);
                        x1 ^= cx;
                    }
                }
                else
                {
                    x0 ^= PAD(mlen);
                    if (mlen != 0)
                    {
                        ulong cx = Pack.BE_To_UInt64_High(m, mOff, mlen);
                        x0 ^= cx;
                        Pack.UInt64_To_BE_High(x0, c, cOff, mlen);
                        x0 &= ulong.MaxValue >> (mlen << 3);
                        x0 ^= cx;
                    }
                }
            }
            /* finalize */
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
            }
            P(12);
            x3 ^= K1;
            x4 ^= K2;
        }
#endif

        private void Reset(bool clearMac)
        {
            if (clearMac)
            {
                mac = null;
            }

            aadData.SetLength(0);
            message.SetLength(0);

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
                throw new InvalidOperationException();
            }

            ascon_aeadinit();
        }

        private static ulong PAD(int i)
        {
            return 0x8000000000000000UL >> (i << 3);
        }
    }
}
