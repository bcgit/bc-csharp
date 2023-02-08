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
    /**
    * ASCON AEAD v1.2, https://ascon.iaik.tugraz.at/
    * https://csrc.nist.gov/CSRC/media/Projects/lightweight-cryptography/documents/finalist-round/updated-spec-doc/ascon-spec-final.pdf
    * <p>
    * ASCON AEAD v1.2 with reference to C Reference Impl from: https://github.com/ascon/ascon-c
    * </p>
    */
    public sealed class AsconEngine
        : IAeadCipher
    {
        public enum AsconParameters
        {
            ascon80pq,
            ascon128a,
            ascon128
        }

        private readonly AsconParameters asconParameters;
        private readonly MemoryStream aadData = new MemoryStream();
        private readonly MemoryStream message = new MemoryStream();
        private bool encrypted;
        private bool initialised;
        private bool forEncryption;
        private bool aadFinished;
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

        public string AlgorithmName => algorithmName;

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
            initialised = false;
        }

        public int GetKeyBytesSize()
        {
            return CRYPTO_KEYBYTES;
        }

        public int GetIVBytesSize()
        {
            return CRYPTO_ABYTES;
        }

        public void Init(bool forEncryption, ICipherParameters parameters)
        {
            this.forEncryption = forEncryption;
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
            initialised = true;
            /*Mask-Gen*/
            Reset(false);
        }

        public void ProcessAadByte(byte input)
        {
            if (aadFinished)
            {
                throw new ArgumentException("AAD cannot be added after reading a full block(" + ASCON_AEAD_RATE +
                    " bytes) of input for " + (forEncryption ? "encryption" : "decryption"));
            }

            aadData.WriteByte(input);
        }

        public void ProcessAadBytes(byte[] inBytes, int inOff, int len)
        {
            if (aadFinished)
            {
                throw new ArgumentException("AAD cannot be added after reading a full block(" + ASCON_AEAD_RATE +
                    " bytes) of input for " + (forEncryption ? "encryption" : "decryption"));
            }

            Check.DataLength(inBytes, inOff, len, "input buffer too short");

            aadData.Write(inBytes, inOff, len);
        }

#if NETCOREAPP2_1_OR_GREATER || NETSTANDARD2_1_OR_GREATER
        public void ProcessAadBytes(ReadOnlySpan<byte> input)
        {
            if (aadFinished)
            {
                throw new ArgumentException("AAD cannot be added after reading a full block(" + ASCON_AEAD_RATE +
                    " bytes) of input for " + (forEncryption ? "encryption" : "decryption"));
            }

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
            if (!initialised)
                throw new ArgumentException("Need to call Init function before encryption/decryption");

            message.Write(inBytes, inOff, len);
            int rv = ProcessBytes(outBytes, outOff);
            encrypted = true;
            return rv;
#endif
        }

#if NETCOREAPP2_1_OR_GREATER || NETSTANDARD2_1_OR_GREATER
        public int ProcessBytes(ReadOnlySpan<byte> input, Span<byte> output)
        {
            if (!initialised)
                throw new ArgumentException("Need to call Init function before encryption/decryption");

            message.Write(input);
            int rv = ProcessBytes(output);
            encrypted = true;
            return rv;
        }
#endif

        public int DoFinal(byte[] outBytes, int outOff)
        {
#if NETCOREAPP2_1_OR_GREATER || NETSTANDARD2_1_OR_GREATER
            return DoFinal(outBytes.AsSpan(outOff));
#else
            if (!initialised)
                throw new ArgumentException("Need call init function before encryption/decryption");

            if (!aadFinished)
            {
                ProcessAad();
            }
            if (!encrypted)
            {
                ProcessBytes(Array.Empty<byte>(), 0, 0, Array.Empty<byte>(), 0);
            }
            byte[] input = message.GetBuffer();
            int len = Convert.ToInt32(message.Length);
            if (forEncryption)
            {
                Check.OutputLength(outBytes, outOff, len + CRYPTO_ABYTES, "output buffer too short");
            }
            else
            {
                Check.OutputLength(outBytes, outOff, len - CRYPTO_ABYTES, "output buffer too short");
            }
            if (forEncryption)
            {
                ascon_final(outBytes, outOff, input, 0, len);
                /* set tag */
                mac = new byte[16];
                Pack.UInt64_To_BE(x3, mac, 0);
                Pack.UInt64_To_BE(x4, mac, 8);
                Array.Copy(mac, 0, outBytes, len + outOff, 16);
                Reset(false);
                return len + CRYPTO_ABYTES;
            }
            else
            {
                len -= CRYPTO_ABYTES;
                ascon_final(outBytes, outOff, input, 0, len);
                x3 ^= Pack.BE_To_UInt64(input, len);
                x4 ^= Pack.BE_To_UInt64(input, len + 8);
                ulong result = x3 | x4;
                Reset(true);

                if (result != 0UL)
                    throw new ArgumentException("Mac does not match");

                return len;
            }
#endif
        }

#if NETCOREAPP2_1_OR_GREATER || NETSTANDARD2_1_OR_GREATER
        public int DoFinal(Span<byte> output)
        {
            if (!initialised)
                throw new ArgumentException("Need call init function before encryption/decryption");

            if (!aadFinished)
            {
                ProcessAad();
            }
            if (!encrypted)
            {
                ProcessBytes(Array.Empty<byte>(), 0, 0, Array.Empty<byte>(), 0);
            }
            byte[] input = message.GetBuffer();
            int len = Convert.ToInt32(message.Length);
            if (forEncryption)
            {
                Check.OutputLength(output, len + CRYPTO_ABYTES, "output buffer too short");
            }
            else
            {
                Check.OutputLength(output, len - CRYPTO_ABYTES, "output buffer too short");
            }
            if (forEncryption)
            {
                ascon_final(output, input.AsSpan(0, len));
                /* set tag */
                mac = new byte[CRYPTO_ABYTES];
                Pack.UInt64_To_BE(x3, mac, 0);
                Pack.UInt64_To_BE(x4, mac, 8);
                mac.AsSpan(0, CRYPTO_ABYTES).CopyTo(output[len..]);
                Reset(false);
                return len + CRYPTO_ABYTES;
            }
            else
            {
                len -= CRYPTO_ABYTES;
                ascon_final(output, input.AsSpan(0, len));
                x3 ^= Pack.BE_To_UInt64(input, len);
                x4 ^= Pack.BE_To_UInt64(input, len + 8);
                ulong result = x3 | x4;
                Reset(true);

                if (result != 0UL)
                    throw new ArgumentException("Mac does not match");

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
            return len;
        }

        public int GetOutputSize(int len)
        {
            return len + CRYPTO_ABYTES;
        }

        public void Reset()
        {
            Reset(true);
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

        private void ProcessAad()
        {
            if (!aadFinished)
            {
                byte[] ad = aadData.GetBuffer();
                int adlen = Convert.ToInt32(aadData.Length);
                /* perform ascon computation */
#if NETCOREAPP2_1_OR_GREATER || NETSTANDARD2_1_OR_GREATER
                ascon_adata(ad.AsSpan(0, adlen));
#else
                ascon_adata(ad, 0, adlen);
#endif
                aadFinished = true;
            }
        }

        private void ascon_aeadinit()
        {
            /* initialize */
            x0 ^= ASCON_IV;
            if (CRYPTO_KEYBYTES == 20)
            {
                x0 ^= K0;
            }
            x1 ^= K1;
            x2 ^= K2;
            x3 ^= N0;
            x4 ^= N1;
            P(12);
            if (CRYPTO_KEYBYTES == 20)
            {
                x2 ^= K0;
            }
            x3 ^= K1;
            x4 ^= K2;
        }

#if NETCOREAPP2_1_OR_GREATER || NETSTANDARD2_1_OR_GREATER
        private int ProcessBytes(Span<byte> output)
        {
            int len_orig = Convert.ToInt32(message.Length);
            int len = 0;
            if (forEncryption)
            {
                if (len_orig >= ASCON_AEAD_RATE)
                {
                    ProcessAad();
                    byte[] input = message.GetBuffer();
                    len = (len_orig / ASCON_AEAD_RATE) * ASCON_AEAD_RATE;
                    Check.OutputLength(output, len, "output buffer is too short");
                    ascon_encrypt(output, input.AsSpan(0, len));
                    message.SetLength(0);
                    message.Write(input, len, len_orig - len);
                }
            }
            else
            {
                if (len_orig - CRYPTO_ABYTES >= ASCON_AEAD_RATE)
                {
                    ProcessAad();
                    byte[] input = message.GetBuffer();
                    len = ((len_orig - CRYPTO_ABYTES) / ASCON_AEAD_RATE) * ASCON_AEAD_RATE;
                    Check.OutputLength(output, len, "output buffer is too short");
                    ascon_decrypt(output, input.AsSpan(0, len));
                    message.SetLength(0);
                    message.Write(input, len, len_orig - len);
                }
            }
            return len;
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

        private void ascon_final(Span<byte> output, ReadOnlySpan<byte> input)
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
        private int ProcessBytes(byte[] output, int outOff)
        {
            int len_orig = Convert.ToInt32(message.Length);
            int len = 0;
            if (forEncryption)
            {
                if (len_orig >= ASCON_AEAD_RATE)
                {
                    ProcessAad();
                    byte[] input = message.GetBuffer();
                    len = (len_orig / ASCON_AEAD_RATE) * ASCON_AEAD_RATE;
                    Check.OutputLength(output, outOff, len, "output buffer is too short");
                    ascon_encrypt(output, outOff, input, 0, len);
                    message.SetLength(0);
                    message.Write(input, len, len_orig - len);
                }
            }
            else
            {
                if (len_orig - CRYPTO_ABYTES >= ASCON_AEAD_RATE)
                {
                    ProcessAad();
                    byte[] input = message.GetBuffer();
                    len = ((len_orig - CRYPTO_ABYTES) / ASCON_AEAD_RATE) * ASCON_AEAD_RATE;
                    Check.OutputLength(output, outOff, len, "output buffer is too short");
                    ascon_decrypt(output, outOff, input, 0, len);
                    message.SetLength(0);
                    message.Write(input, len, len_orig - len);
                }
            }
            return len;
        }

        private void ascon_adata(byte[] ad, int adOff, int adlen)
        {
            if (adlen != 0)
            {
                /* full associated data blocks */
                while (adlen >= ASCON_AEAD_RATE)
                {
                    x0 ^= Pack.BE_To_UInt64(ad, adOff);
                    if (ASCON_AEAD_RATE == 16)
                    {
                        x1 ^= Pack.BE_To_UInt64(ad, adOff + 8);
                    }
                    P(nr);
                    adOff += ASCON_AEAD_RATE;
                    adlen -= ASCON_AEAD_RATE;
                }
                /* final associated data block */
                if (ASCON_AEAD_RATE == 16 && adlen >= 8)
                {
                    x0 ^= Pack.BE_To_UInt64(ad, adOff);
                    adOff += 8;
                    adlen -= 8;
                    x1 ^= PAD(adlen);
                    if (adlen != 0)
                    {
                        x1 ^= Pack.BE_To_UInt64_High(ad, adOff, adlen);
                    }
                }
                else
                {
                    x0 ^= PAD(adlen);
                    if (adlen != 0)
                    {
                        x0 ^= Pack.BE_To_UInt64_High(ad, adOff, adlen);
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

        private void ascon_final(byte[] c, int cOff, byte[] m, int mOff, int mlen)
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
            if (!initialised)
                throw new ArgumentException("Need call init function before encryption/decryption");

            x0 = x1 = x2 = x3 = x4 = 0;
            ascon_aeadinit();
            aadData.SetLength(0);
            message.SetLength(0);
            encrypted = false;
            aadFinished = false;
            if (clearMac)
            {
                mac = null;
            }
        }

        private static ulong PAD(int i)
        {
            return 0x8000000000000000UL >> (i << 3);
        }
    }
}
