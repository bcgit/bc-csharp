using System;
using System.IO;
using Org.BouncyCastle.Crypto.Modes;
using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.Crypto.Utilities;
using Org.BouncyCastle.Utilities;

/**
* ASCON AEAD v1.2, https://ascon.iaik.tugraz.at/
* https://csrc.nist.gov/CSRC/media/Projects/lightweight-cryptography/documents/finalist-round/updated-spec-doc/ascon-spec-final.pdf
* <p>
* ASCON AEAD v1.2 with reference to C Reference Impl from: https://github.com/ascon/ascon-c
* </p>
*/
namespace Org.BouncyCastle.Crypto.Engines
{
    public class AsconEngine : IAeadBlockCipher
    {
        public enum AsconParameters
        {
            ascon80pq,
            ascon128a,
            ascon128
        }

        private readonly AsconParameters asconParameters;
        private readonly MemoryStream aadData = new MemoryStream();
        private bool encrypted;
        private readonly int CRYPTO_KEYBYTES;
        private readonly int CRYPTO_ABYTES;
        private readonly int ASCON_AEAD_RATE;
        private readonly int nr;
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

        public IBlockCipher UnderlyingCipher => throw new NotImplementedException();

        public string AlgorithmName => "ASCON AEAD";

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
                    break;
                case AsconParameters.ascon128a:
                    CRYPTO_KEYBYTES = 16;
                    CRYPTO_ABYTES = 16;
                    ASCON_AEAD_RATE = 16;
                    ASCON_IV = 0x80800c0800000000UL;
                    break;
                case AsconParameters.ascon128:
                    CRYPTO_KEYBYTES = 16;
                    CRYPTO_ABYTES = 16;
                    ASCON_AEAD_RATE = 8;
                    ASCON_IV = 0x80400c0600000000UL;
                    break;
                default:
                    throw new ArgumentException("invalid parameter setting for ASCON AEAD");
            }
            nr = (ASCON_AEAD_RATE == 8) ? 6 : 8;
        }

        private ulong U64BIG(ulong x)
        {
            return (((0x00000000000000FFUL & (x)) << 56) |
            ((0x000000000000FF00UL & (x)) << 40) |
            ((0x0000000000FF0000UL & (x)) << 24) |
            ((0x00000000FF000000UL & (x)) << 8) |
            ((0x000000FF00000000UL & (x)) >> 8) |
            ((0x0000FF0000000000UL & (x)) >> 24) |
            ((0x00FF000000000000UL & (x)) >> 40) |
            ((0xFF00000000000000UL & (x)) >> 56));
        }

        private ulong ROR(ulong x, int n)
        {
            return x >> n | x << (64 - n);
        }

        private ulong KEYROT(ulong lo2hi, ulong hi2lo)
        {
            return lo2hi << 32 | hi2lo >> 32;
        }

        private ulong PAD(int i)
        {
            return 0x80UL << (56 - (i << 3));
        }

        private ulong MASK(int n)
        {
            /* undefined for n == 0 */
            return ~0UL >> (64 - (n << 3));
        }

        private ulong LOAD(byte[] bytes, int inOff, int n)
        {
            ulong x = 0;
            int len = System.Math.Min(8, bytes.Length - inOff);
            for (int i = 0; i < len; ++i)
            {
                x |= (bytes[i + inOff] & 0xFFUL) << (i << 3);
            }
            return U64BIG(x & MASK(n));
        }

        private void STORE(byte[] bytes, int inOff, ulong w, int n)
        {
            ulong x = Pack.LE_To_UInt64(bytes, inOff);
            x &= ~MASK(n);
            x |= U64BIG(w);
            Pack.UInt64_To_LE(x, bytes, inOff);
        }

        private ulong LOADBYTES(byte[] bytes, int inOff, int n)
        {
            ulong x = 0;
            for (int i = 0; i < n; ++i)
            {
                x |= (bytes[i + inOff] & 0xFFUL) << ((7 - i) << 3);
            }
            return x;
        }

        private void STOREBYTES(byte[] bytes, int inOff, ulong w, int n)
        {
            for (int i = 0; i < n; ++i)
            {
                bytes[i + inOff] = (byte)(w >> ((7 - i) << 3));
            }
        }

        private void ROUND(ulong C)
        {
            ulong t0 = x0 ^ x1 ^ x2 ^ x3 ^ C ^ (x1 & (x0 ^ x2 ^ x4 ^ C));
            ulong t1 = x0 ^ x2 ^ x3 ^ x4 ^ C ^ ((x1 ^ x2 ^ C) & (x1 ^ x3));
            ulong t2 = x1 ^ x2 ^ x4 ^ C ^ (x3 & x4);
            ulong t3 = x0 ^ x1 ^ x2 ^ C ^ ((~x0) & (x3 ^ x4));
            ulong t4 = x1 ^ x3 ^ x4 ^ ((x0 ^ x4) & x1);
            x0 = t0 ^ ROR(t0, 19) ^ ROR(t0, 28);
            x1 = t1 ^ ROR(t1, 39) ^ ROR(t1, 61);
            x2 = ~(t2 ^ ROR(t2, 1) ^ ROR(t2, 6));
            x3 = t3 ^ ROR(t3, 10) ^ ROR(t3, 17);
            x4 = t4 ^ ROR(t4, 7) ^ ROR(t4, 41);
        }

        private void P(int nr)
        {
            if (nr == 12)
            {
                ROUND(0xf0UL);
                ROUND(0xe1UL);
                ROUND(0xd2UL);
                ROUND(0xc3UL);
            }
            if (nr >= 8)
            {
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

        private void ascon_adata(byte[] ad, int adOff, int adlen)
        {
            if (adlen != 0)
            {
                /* full associated data blocks */
                while (adlen >= ASCON_AEAD_RATE)
                {
                    x0 ^= LOAD(ad, adOff, 8);
                    if (ASCON_AEAD_RATE == 16)
                    {
                        x1 ^= LOAD(ad, adOff + 8, 8);
                    }
                    P(nr);
                    adOff += ASCON_AEAD_RATE;
                    adlen -= ASCON_AEAD_RATE;
                }
                /* readonly associated data block */
                if (ASCON_AEAD_RATE == 16 && adlen >= 8)
                {
                    x0 ^= LOAD(ad, adOff, 8);
                    adOff += 8;
                    adlen -= 8;
                    x1 ^= PAD(adlen);
                    if (adlen != 0)
                    {
                        x1 ^= LOAD(ad, adOff, adlen);
                    }
                }
                else
                {
                    x0 ^= PAD(adlen);
                    if (adlen != 0)
                    {
                        x0 ^= LOAD(ad, adOff, adlen);
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
                x0 ^= LOAD(m, mOff, 8);
                STORE(c, cOff, x0, 8);
                if (ASCON_AEAD_RATE == 16)
                {
                    x1 ^= LOAD(m, mOff + 8, 8);
                    STORE(c, cOff + 8, x1, 8);
                }
                P(nr);
                mOff += ASCON_AEAD_RATE;
                cOff += ASCON_AEAD_RATE;
                mlen -= ASCON_AEAD_RATE;
            }
            /* readonly plaintext block */
            if (ASCON_AEAD_RATE == 16 && mlen >= 8)
            {
                x0 ^= LOAD(m, mOff, 8);
                STORE(c, cOff, x0, 8);
                mOff += 8;
                cOff += 8;
                mlen -= 8;
                x1 ^= PAD(mlen);
                if (mlen != 0)
                {
                    x1 ^= LOAD(m, mOff, mlen);
                    STORE(c, cOff, x1, mlen);
                }
            }
            else
            {
                x0 ^= PAD(mlen);
                if (mlen != 0)
                {
                    x0 ^= LOAD(m, mOff, mlen);
                    STORE(c, cOff, x0, mlen);
                }
            }
        }

        private void ascon_final()
        {
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
                    x1 ^= KEYROT(K0, K1);
                    x2 ^= KEYROT(K1, K2);
                    x3 ^= KEYROT(K2, 0UL);
                    break;
            }
            P(12);
            x3 ^= K1;
            x4 ^= K2;
        }

        public void Init(bool forEncryption, ICipherParameters param)
        {
            /**
            * ASCON encryption and decryption is completely symmetrical, so the
            * 'forEncryption' is irrelevant.
*/
            if (!(param is ParametersWithIV))
            {
                throw new ArgumentException(
                "ASCON init parameters must include an IV");
            }
            ParametersWithIV ivParams = (ParametersWithIV)param;
            byte[] npub = ivParams.GetIV();
            if (npub == null || npub.Length != CRYPTO_ABYTES)
            {
                throw new ArgumentException(asconParameters + " requires exactly " + CRYPTO_ABYTES + " bytes of IV");
            }
            if (!(ivParams.Parameters is KeyParameter))
            {
                throw new ArgumentException(
                "ASCON init parameters must include a key");
            }
            KeyParameter key = (KeyParameter)ivParams.Parameters;
            byte[] k = key.GetKey();
            if (k.Length != CRYPTO_KEYBYTES)
            {
                throw new ArgumentException(asconParameters + " key must be " + CRYPTO_KEYBYTES + " bytes long");
            }
            N0 = LOAD(npub, 0, 8);
            N1 = LOAD(npub, 8, 8);
            if (CRYPTO_KEYBYTES == 16)
            {
                K1 = LOAD(k, 0, 8);
                K2 = LOAD(k, 8, 8);
            }
            else if (CRYPTO_KEYBYTES == 20)
            {
                K0 = KEYROT(0, LOADBYTES(k, 0, 4));
                K1 = LOADBYTES(k, 4, 8);
                K2 = LOADBYTES(k, 12, 8);
            }
            /*Mask-Gen*/
            Reset();
        }

        public void ProcessAadByte(byte input)
        {
            aadData.Write(new byte[] { input }, 0, 1);
        }


        public void ProcessAadBytes(byte[] input, int inOff, int len)
        {
            aadData.Write(input, inOff, len);
        }


        public int ProcessByte(byte input, byte[] output, int outOff)
        {
            return ProcessBytes(new byte[] { input }, 0, 1, output, outOff);
        }


        public int ProcessBytes(byte[] input, int inOff, int len, byte[] output, int outOff)
        {
            if (encrypted)
            {
                throw new ArgumentException("ProcessBytes for ASCONcan be called once only");
            }
            byte[] ad = aadData.GetBuffer();
            int adlen = (int)aadData.Length;
            /* perform ascon computation */
            //ascon_aeadinit();
            ascon_adata(ad, 0, adlen);
            ascon_encrypt(output, outOff, input, inOff, len);
            ascon_final();
            encrypted = true;
            return len;
        }


        public int DoFinal(byte[] output, int outOff)
        {
            if (!encrypted)
            {
                ProcessBytes(new byte[] { }, 0, 0, new byte[] { }, 0);
            }
            /* set tag */
            STOREBYTES(output, outOff, x3, 8);
            STOREBYTES(output, outOff + 8, x4, 8);
            Reset();
            return CRYPTO_ABYTES;
        }


        public byte[] GetMac()
        {
            if (!encrypted)
            {
                ProcessBytes(new byte[] { }, 0, 0, new byte[] { }, 0);
            }
            byte[] output = new byte[CRYPTO_ABYTES];
            STOREBYTES(output, 0, x3, 8);
            STOREBYTES(output, 8, x4, 8);
            return output;
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
            x0 = x1 = x2 = x3 = x4 = 0;
            ascon_aeadinit();
            aadData.SetLength(0);
            encrypted = false;
        }

#if NETCOREAPP2_1_OR_GREATER || NETSTANDARD2_1_OR_GREATER
        public void ProcessAadBytes(ReadOnlySpan<byte> input)
        {
            aadData.Write(input);
        }

        public int ProcessByte(byte input, Span<byte> output)
        {
            byte[] rv = new byte[1];
            ProcessBytes(new byte[] { input }, 0, 1, rv, 0);
            rv.AsSpan(0, 1).CopyTo(output);
            return 1;
        }

        public int ProcessBytes(ReadOnlySpan<byte> input, Span<byte> output)
        {
            byte[] rv = new byte[input.Length];
            ProcessBytes(input.ToArray(), 0, rv.Length, rv, 0);
            rv.AsSpan(0, rv.Length).CopyTo(output);
            return rv.Length;
        }

        public int DoFinal(Span<byte> output)
        {
            byte[] tag = GetMac();
            tag.AsSpan(0, tag.Length).CopyTo(output);
            Reset();
            return tag.Length;
        }
#endif
        public int GetBlockSize()
        {
            return ASCON_AEAD_RATE;
        }
    }
}


