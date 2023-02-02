using System;
using System.IO;

using Org.BouncyCastle.Crypto.Modes;
using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.Utilities;

namespace Org.BouncyCastle.Crypto.Engines
{
    /**
     * Elephant AEAD v2, based on the current round 3 submission, https://www.esat.kuleuven.be/cosic/elephant/
     * Reference C implementation: https://github.com/TimBeyne/Elephant
     * Specification: https://csrc.nist.gov/CSRC/media/Projects/lightweight-cryptography/documents/finalist-round/updated-spec-doc/elephant-spec-final.pdf
     */
    public class ElephantEngine
        : IAeadBlockCipher
    {
        public enum ElephantParameters
        {
            elephant160,
            elephant176,
            elephant200
        }

        private bool forEncryption;
        private readonly string algorithmName;
        private ElephantParameters parameters;
        private int BLOCK_SIZE;
        private int nBits;
        private int nSBox;
        private int nRounds;
        private byte lfsrIV;
        private byte[] npub;
        private byte[] expanded_key;
        private byte[] tag;
        private byte CRYPTO_KEYBYTES = 16;
        private byte CRYPTO_NPUBBYTES = 12;
        private byte CRYPTO_ABYTES;
        private bool initialised;
        private MemoryStream aadData = new MemoryStream();
        private MemoryStream message = new MemoryStream();

        private readonly byte[] sBoxLayer = {
        (byte)0xee, (byte)0xed, (byte)0xeb, (byte)0xe0, (byte)0xe2, (byte)0xe1, (byte)0xe4, (byte)0xef, (byte)0xe7, (byte)0xea, (byte)0xe8, (byte)0xe5, (byte)0xe9, (byte)0xec, (byte)0xe3, (byte)0xe6,
        (byte)0xde, (byte)0xdd, (byte)0xdb, (byte)0xd0, (byte)0xd2, (byte)0xd1, (byte)0xd4, (byte)0xdf, (byte)0xd7, (byte)0xda, (byte)0xd8, (byte)0xd5, (byte)0xd9, (byte)0xdc, (byte)0xd3, (byte)0xd6,
        (byte)0xbe, (byte)0xbd, (byte)0xbb, (byte)0xb0, (byte)0xb2, (byte)0xb1, (byte)0xb4, (byte)0xbf, (byte)0xb7, (byte)0xba, (byte)0xb8, (byte)0xb5, (byte)0xb9, (byte)0xbc, (byte)0xb3, (byte)0xb6,
        (byte)0x0e, (byte)0x0d, (byte)0x0b, (byte)0x00, (byte)0x02, (byte)0x01, (byte)0x04, (byte)0x0f, (byte)0x07, (byte)0x0a, (byte)0x08, (byte)0x05, (byte)0x09, (byte)0x0c, (byte)0x03, (byte)0x06,
        (byte)0x2e, (byte)0x2d, (byte)0x2b, (byte)0x20, (byte)0x22, (byte)0x21, (byte)0x24, (byte)0x2f, (byte)0x27, (byte)0x2a, (byte)0x28, (byte)0x25, (byte)0x29, (byte)0x2c, (byte)0x23, (byte)0x26,
        (byte)0x1e, (byte)0x1d, (byte)0x1b, (byte)0x10, (byte)0x12, (byte)0x11, (byte)0x14, (byte)0x1f, (byte)0x17, (byte)0x1a, (byte)0x18, (byte)0x15, (byte)0x19, (byte)0x1c, (byte)0x13, (byte)0x16,
        (byte)0x4e, (byte)0x4d, (byte)0x4b, (byte)0x40, (byte)0x42, (byte)0x41, (byte)0x44, (byte)0x4f, (byte)0x47, (byte)0x4a, (byte)0x48, (byte)0x45, (byte)0x49, (byte)0x4c, (byte)0x43, (byte)0x46,
        (byte)0xfe, (byte)0xfd, (byte)0xfb, (byte)0xf0, (byte)0xf2, (byte)0xf1, (byte)0xf4, (byte)0xff, (byte)0xf7, (byte)0xfa, (byte)0xf8, (byte)0xf5, (byte)0xf9, (byte)0xfc, (byte)0xf3, (byte)0xf6,
        (byte)0x7e, (byte)0x7d, (byte)0x7b, (byte)0x70, (byte)0x72, (byte)0x71, (byte)0x74, (byte)0x7f, (byte)0x77, (byte)0x7a, (byte)0x78, (byte)0x75, (byte)0x79, (byte)0x7c, (byte)0x73, (byte)0x76,
        (byte)0xae, (byte)0xad, (byte)0xab, (byte)0xa0, (byte)0xa2, (byte)0xa1, (byte)0xa4, (byte)0xaf, (byte)0xa7, (byte)0xaa, (byte)0xa8, (byte)0xa5, (byte)0xa9, (byte)0xac, (byte)0xa3, (byte)0xa6,
        (byte)0x8e, (byte)0x8d, (byte)0x8b, (byte)0x80, (byte)0x82, (byte)0x81, (byte)0x84, (byte)0x8f, (byte)0x87, (byte)0x8a, (byte)0x88, (byte)0x85, (byte)0x89, (byte)0x8c, (byte)0x83, (byte)0x86,
        (byte)0x5e, (byte)0x5d, (byte)0x5b, (byte)0x50, (byte)0x52, (byte)0x51, (byte)0x54, (byte)0x5f, (byte)0x57, (byte)0x5a, (byte)0x58, (byte)0x55, (byte)0x59, (byte)0x5c, (byte)0x53, (byte)0x56,
        (byte)0x9e, (byte)0x9d, (byte)0x9b, (byte)0x90, (byte)0x92, (byte)0x91, (byte)0x94, (byte)0x9f, (byte)0x97, (byte)0x9a, (byte)0x98, (byte)0x95, (byte)0x99, (byte)0x9c, (byte)0x93, (byte)0x96,
        (byte)0xce, (byte)0xcd, (byte)0xcb, (byte)0xc0, (byte)0xc2, (byte)0xc1, (byte)0xc4, (byte)0xcf, (byte)0xc7, (byte)0xca, (byte)0xc8, (byte)0xc5, (byte)0xc9, (byte)0xcc, (byte)0xc3, (byte)0xc6,
        (byte)0x3e, (byte)0x3d, (byte)0x3b, (byte)0x30, (byte)0x32, (byte)0x31, (byte)0x34, (byte)0x3f, (byte)0x37, (byte)0x3a, (byte)0x38, (byte)0x35, (byte)0x39, (byte)0x3c, (byte)0x33, (byte)0x36,
        (byte)0x6e, (byte)0x6d, (byte)0x6b, (byte)0x60, (byte)0x62, (byte)0x61, (byte)0x64, (byte)0x6f, (byte)0x67, (byte)0x6a, (byte)0x68, (byte)0x65, (byte)0x69, (byte)0x6c, (byte)0x63, (byte)0x66
    };

        private readonly byte[] KeccakRoundConstants = {
        (byte)0x01, (byte)0x82, (byte)0x8a, (byte)0x00, (byte)0x8b, (byte)0x01, (byte)0x81, (byte)0x09, (byte)0x8a,
        (byte)0x88, (byte)0x09, (byte)0x0a, (byte)0x8b, (byte)0x8b, (byte)0x89, (byte)0x03, (byte)0x02, (byte)0x80
    };

        private readonly int[] KeccakRhoOffsets = { 0, 1, 6, 4, 3, 4, 4, 6, 7, 4, 3, 2, 3, 1, 7, 1, 5, 7, 5, 0, 2, 2, 5, 0, 6 };

        public ElephantEngine(ElephantParameters parameters)
        {
            switch (parameters)
            {
                case ElephantParameters.elephant160:
                    BLOCK_SIZE = 20;
                    nBits = 160;
                    nSBox = 20;
                    nRounds = 80;
                    lfsrIV = 0x75;
                    CRYPTO_ABYTES = 8;
                    algorithmName = "Elephant 160 AEAD";
                    break;
                case ElephantParameters.elephant176:
                    BLOCK_SIZE = 22;
                    nBits = 176;
                    nSBox = 22;
                    nRounds = 90;
                    lfsrIV = 0x45;
                    CRYPTO_ABYTES = 8;
                    algorithmName = "Elephant 176 AEAD";
                    break;
                case ElephantParameters.elephant200:
                    BLOCK_SIZE = 25;
                    nRounds = 18;
                    CRYPTO_ABYTES = 16;
                    algorithmName = "Elephant 200 AEAD";
                    break;
                default:
                    throw new ArgumentException("Invalid parameter settings for Elephant");
            }
            this.parameters = parameters;
            initialised = false;
            reset(false);
        }

        private void permutation(byte[] state)
        {
            switch (parameters)
            {
                case ElephantParameters.elephant160:
                case ElephantParameters.elephant176:
                    byte IV = lfsrIV;
                    byte[] tmp = new byte[nSBox];
                    for (int i = 0; i < nRounds; i++)
                    {
                        /* Add counter values */
                        state[0] ^= IV;
                        state[nSBox - 1] ^= (byte)(((IV & 0x01) << 7) | ((IV & 0x02) << 5) | ((IV & 0x04) << 3) | ((IV & 0x08)
                            << 1) | ((IV & 0x10) >> 1) | ((IV & 0x20) >> 3) | ((IV & 0x40) >> 5) | ((IV & 0x80) >> 7));
                        IV = (byte)(((IV << 1) | (((0x40 & IV) >> 6) ^ ((0x20 & IV) >> 5))) & 0x7f);
                        /* sBoxLayer layer */
                        for (int j = 0; j < nSBox; j++)
                        {
                            state[j] = sBoxLayer[(state[j] & 0xFF)];
                        }
                        /* pLayer */
                        int PermutedBitNo;
                        Arrays.Fill(tmp, (byte)0);
                        for (int j = 0; j < nSBox; j++)
                        {
                            for (int k = 0; k < 8; k++)
                            {
                                PermutedBitNo = (j << 3) + k;
                                if (PermutedBitNo != nBits - 1)
                                {
                                    PermutedBitNo = ((PermutedBitNo * nBits) >> 2) % (nBits - 1);
                                }
                                tmp[PermutedBitNo >> 3] ^= (byte)((((state[j] & 0xFF) >> k) & 0x1) << (PermutedBitNo & 7));
                            }
                        }
                        Array.Copy(tmp, 0, state, 0, nSBox);
                    }
                    break;
                case ElephantParameters.elephant200:
                    for (int i = 0; i < nRounds; i++)
                    {
                        KeccakP200Round(state, i);
                    }
                    break;
            }
        }

        private byte rotl(byte b)
        {
            return (byte)(((b & 0xFF) << 1) | ((b & 0xFF) >> 7));
        }

        private byte ROL8(byte a, int offset)
        {
            return (byte)((offset != 0) ? (((a & 0xFF) << offset) ^ ((a & 0xFF) >> (8 - offset))) : a);
        }

        private int index(int x, int y)
        {
            return x + y * 5;
        }

        private void KeccakP200Round(byte[] state, int indexRound)
        {
            int x, y;
            byte[] tempA = new byte[25];
            //theta
            for (x = 0; x < 5; x++)
            {
                for (y = 0; y < 5; y++)
                {
                    tempA[x] ^= state[index(x, y)];
                }
            }
            for (x = 0; x < 5; x++)
            {
                tempA[x + 5] = (byte)(ROL8(tempA[(x + 1) % 5], 1) ^ tempA[(x + 4) % 5]);
            }
            for (x = 0; x < 5; x++)
            {
                for (y = 0; y < 5; y++)
                {
                    state[index(x, y)] ^= tempA[x + 5];
                }
            }
            //rho
            for (x = 0; x < 5; x++)
            {
                for (y = 0; y < 5; y++)
                {
                    tempA[index(x, y)] = ROL8(state[index(x, y)], KeccakRhoOffsets[index(x, y)]);
                }
            }
            //pi
            for (x = 0; x < 5; x++)
            {
                for (y = 0; y < 5; y++)
                {
                    state[index(y, (2 * x + 3 * y) % 5)] = tempA[index(x, y)];
                }
            }
            //chi
            for (y = 0; y < 5; y++)
            {
                for (x = 0; x < 5; x++)
                {
                    tempA[x] = (byte)(state[index(x, y)] ^ ((~state[index((x + 1) % 5, y)]) & state[index((x + 2) % 5, y)]));
                }
                for (x = 0; x < 5; x++)
                {
                    state[index(x, y)] = tempA[x];
                }
            }
            //iota
            state[index(0, 0)] ^= KeccakRoundConstants[indexRound];
        }


        // State should be BLOCK_SIZE bytes long
        // Note: input may be equal to output
        private void lfsr_step(byte[] output, byte[] input)
        {
            switch (parameters)
            {
                case ElephantParameters.elephant160:
                    output[BLOCK_SIZE - 1] = (byte)((((input[0] & 0xFF) << 3) | ((input[0] & 0xFF) >> 5)) ^
                        ((input[3] & 0xFF) << 7) ^ ((input[13] & 0xFF) >> 7));
                    break;
                case ElephantParameters.elephant176:
                    output[BLOCK_SIZE - 1] = (byte)(rotl(input[0]) ^ ((input[3] & 0xFF) << 7) ^ ((input[19] & 0xFF) >> 7));
                    break;
                case ElephantParameters.elephant200:
                    output[BLOCK_SIZE - 1] = (byte)(rotl(input[0]) ^ rotl(input[2]) ^ (input[13] << 1));
                    break;
            }
            Array.Copy(input, 1, output, 0, BLOCK_SIZE - 1);
        }

        private void xor_block(byte[] state, byte[] block, int bOff, int size)
        {
            for (int i = 0; i < size; ++i)
            {
                state[i] ^= block[i + bOff];
            }
        }

        // Write the ith assocated data block to "output".
        // The nonce is prepended and padding is added as required.
        // adlen is the length of the associated data in bytes
        private void get_ad_block(byte[] output, byte[] ad, int adlen, byte[] npub, int i)
        {
            int len = 0;
            // First block contains nonce
            // Remark: nonce may not be longer then BLOCK_SIZE
            if (i == 0)
            {
                Array.Copy(npub, 0, output, 0, CRYPTO_NPUBBYTES);
                len += CRYPTO_NPUBBYTES;
            }
            int block_offset = i * BLOCK_SIZE - ((i != 0) ? 1 : 0) * CRYPTO_NPUBBYTES;
            // If adlen is divisible by BLOCK_SIZE, add an additional padding block
            if (i != 0 && block_offset == adlen)
            {
                Arrays.Fill(output, 0, BLOCK_SIZE, (byte)0);
                output[0] = 0x01;
                return;
            }
            int r_outlen = BLOCK_SIZE - len;
            int r_adlen = adlen - block_offset;
            // Fill with associated data if available
            if (r_outlen <= r_adlen)
            { // enough AD
                Array.Copy(ad, block_offset, output, len, r_outlen);
            }
            else
            { // not enough AD, need to pad
                if (r_adlen > 0) // ad might be nullptr
                {
                    Array.Copy(ad, block_offset, output, len, r_adlen);
                }
                Arrays.Fill(output, len + r_adlen, len + r_outlen, (byte)0);
                output[len + r_adlen] = 0x01;
            }
        }

        // Return the ith ciphertext block.
        // clen is the length of the ciphertext in bytes
        private void get_c_block(byte[] output, byte[] c, int cOff, int clen, int i)
        {
            int block_offset = i * BLOCK_SIZE;
            // If clen is divisible by BLOCK_SIZE, add an additional padding block
            if (block_offset == clen)
            {
                Arrays.Fill(output, 0, BLOCK_SIZE, (byte)0);
                output[0] = 0x01;
                return;
            }
            int r_clen = clen - block_offset;
            // Fill with ciphertext if available
            if (BLOCK_SIZE <= r_clen)
            { // enough ciphertext
                Array.Copy(c, cOff + block_offset, output, 0, BLOCK_SIZE);
            }
            else
            { // not enough ciphertext, need to pad
                if (r_clen > 0) // c might be nullptr
                {
                    Array.Copy(c, cOff + block_offset, output, 0, r_clen);
                }
                Arrays.Fill(output, r_clen, BLOCK_SIZE, (byte)0);
                output[r_clen] = 0x01;
            }
        }



        public void Init(bool forEncryption, ICipherParameters param)
        {
            this.forEncryption = forEncryption;
            if (!(param is ParametersWithIV))
            {
                throw new ArgumentException(
                    "Elephant init parameters must include an IV");
            }

            ParametersWithIV ivParams = (ParametersWithIV)param;

            npub = ivParams.GetIV();

            if (npub == null || npub.Length != 12)
            {
                throw new ArgumentException(
                    "Elephant requires exactly 12 bytes of IV");
            }

            if (!(ivParams.Parameters is KeyParameter))
            {
                throw new ArgumentException(
                    "Elephant init parameters must include a key");
            }

            KeyParameter key = (KeyParameter)ivParams.Parameters;
            byte[] k = key.GetKey();
            if (k.Length != 16)
            {
                throw new ArgumentException(
                    "Elephant key must be 128 bits long");
            }
            // Storage for the expanded key L
            expanded_key = new byte[BLOCK_SIZE];
            Array.Copy(k, 0, expanded_key, 0, CRYPTO_KEYBYTES);
            permutation(expanded_key);
            initialised = true;
            reset(false);
        }


        public string AlgorithmName => algorithmName;

        public IBlockCipher UnderlyingCipher => throw new NotImplementedException();

        public void ProcessAadByte(byte input)
        {
            aadData.Write(new byte[] { input }, 0, 1);
        }


        public void ProcessAadBytes(byte[] input, int inOff, int len)
        {
            if (inOff + len > input.Length)
            {
                throw new DataLengthException("input buffer too short");
            }
            aadData.Write(input, inOff, len);
        }


        public int ProcessByte(byte input, byte[] output, int outOff)
        {
            message.Write(new byte[] { input }, 0, 1);
            return 0;
        }


        public int ProcessBytes(byte[] input, int inOff, int len, byte[] output, int outOff)
        {
            if (inOff + len > input.Length)
            {
                throw new DataLengthException("input buffer too short");
            }
            message.Write(input, inOff, len);
            return 0;
        }


        public int DoFinal(byte[] output, int outOff)
        {
            if (!initialised)
            {
                throw new ArgumentException("Need call init function before encryption/decryption");
            }
            int mlen = (int)message.Length - (forEncryption ? 0 : CRYPTO_ABYTES);
            if ((forEncryption && mlen + outOff + CRYPTO_ABYTES > output.Length) ||
            (!forEncryption && mlen + outOff - CRYPTO_ABYTES > output.Length))
            {
                throw new OutputLengthException("output buffer is too short");
            }
            byte[] tag_buffer = new byte[BLOCK_SIZE];
            byte[] m = message.GetBuffer();
            byte[] ad = aadData.GetBuffer();
            int adlen = (int)aadData.Length;
            int nblocks_c = 1 + mlen / BLOCK_SIZE;
            int nblocks_m = (mlen % BLOCK_SIZE) != 0 ? nblocks_c : nblocks_c - 1;
            int nblocks_ad = 1 + (CRYPTO_NPUBBYTES + adlen) / BLOCK_SIZE;
            int nb_it = System.Math.Max(nblocks_c + 1, nblocks_ad - 1);
            // Buffers for storing previous, current and next mask
            byte[] previous_mask = new byte[BLOCK_SIZE];
            byte[] current_mask = new byte[BLOCK_SIZE];
            byte[] next_mask = new byte[BLOCK_SIZE];
            Array.Copy(expanded_key, 0, current_mask, 0, BLOCK_SIZE);
            // Buffer to store current ciphertext/AD block
            byte[] buffer = new byte[BLOCK_SIZE];
            // Tag buffer and initialization of tag to first AD block
            get_ad_block(tag_buffer, ad, adlen, npub, 0);
            int offset = 0;
            for (int i = 0; i < nb_it; ++i)
            {
                // Compute mask for the next message
                lfsr_step(next_mask, current_mask);
                if (i < nblocks_m)
                {
                    // Compute ciphertext block
                    Array.Copy(npub, 0, buffer, 0, CRYPTO_NPUBBYTES);
                    Arrays.Fill(buffer, CRYPTO_NPUBBYTES, BLOCK_SIZE, (byte)0);
                    xor_block(buffer, current_mask, 0, BLOCK_SIZE);
                    xor_block(buffer, next_mask, 0, BLOCK_SIZE);
                    permutation(buffer);
                    xor_block(buffer, current_mask, 0, BLOCK_SIZE);
                    xor_block(buffer, next_mask, 0, BLOCK_SIZE);
                    int r_size = (i == nblocks_m - 1) ? mlen - offset : BLOCK_SIZE;
                    xor_block(buffer, m, offset, r_size);
                    Array.Copy(buffer, 0, output, offset + outOff, r_size);
                }
                if (i > 0 && i <= nblocks_c)
                {
                    // Compute tag for ciphertext block
                    if (forEncryption)
                    {
                        get_c_block(buffer, output, outOff, mlen, i - 1);
                    }
                    else
                    {
                        get_c_block(buffer, m, 0, mlen, i - 1);
                    }
                    xor_block(buffer, previous_mask, 0, BLOCK_SIZE);
                    xor_block(buffer, next_mask, 0, BLOCK_SIZE);
                    permutation(buffer);
                    xor_block(buffer, previous_mask, 0, BLOCK_SIZE);
                    xor_block(buffer, next_mask, 0, BLOCK_SIZE);
                    xor_block(tag_buffer, buffer, 0, BLOCK_SIZE);
                }
                // If there is any AD left, compute tag for AD block
                if (i + 1 < nblocks_ad)
                {
                    get_ad_block(buffer, ad, adlen, npub, i + 1);
                    xor_block(buffer, next_mask, 0, BLOCK_SIZE);
                    permutation(buffer);
                    xor_block(buffer, next_mask, 0, BLOCK_SIZE);
                    xor_block(tag_buffer, buffer, 0, BLOCK_SIZE);
                }
                // Cyclically shift the mask buffers
                // Value of next_mask will be computed in the next iteration
                byte[] temp = previous_mask;
                previous_mask = current_mask;
                current_mask = next_mask;
                next_mask = temp;
                offset += BLOCK_SIZE;
            }
            outOff += mlen;
            tag = new byte[CRYPTO_ABYTES];
            xor_block(tag_buffer, expanded_key, 0, BLOCK_SIZE);
            permutation(tag_buffer);
            xor_block(tag_buffer, expanded_key, 0, BLOCK_SIZE);
            if (forEncryption)
            {
                Array.Copy(tag_buffer, 0, tag, 0, CRYPTO_ABYTES);
                Array.Copy(tag, 0, output, outOff, tag.Length);
                mlen += CRYPTO_ABYTES;
            }
            else
            {
                for (int i = 0; i < CRYPTO_ABYTES; ++i)
                {
                    if (tag_buffer[i] != m[mlen + i])
                    {
                        throw new ArgumentException("Mac does not match");
                    }
                }
            }
            reset(false);
            return mlen;
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
            return len + CRYPTO_ABYTES;
        }


        public void Reset()
        {
            reset(true);
        }

        private void reset(bool clearMac)
        {
            if (clearMac)
            {
                tag = null;
            }
            aadData.SetLength(0);
            message.SetLength(0);
        }

#if NETCOREAPP2_1_OR_GREATER || NETSTANDARD2_1_OR_GREATER
        public void ProcessAadBytes(ReadOnlySpan<byte> input)
        {
            aadData.Write(input);
        }

        public int ProcessByte(byte input, Span<byte> output)
        {
            message.Write(new byte[] { input });
            return 0;
        }

        public int ProcessBytes(ReadOnlySpan<byte> input, Span<byte> output)
        {
            message.Write(input.ToArray());
            return 0;
        }

        public int DoFinal(Span<byte> output)
        {
            byte[] rv;
            if (forEncryption)
            {
                rv = new byte[message.Length + CRYPTO_ABYTES];
            }
            else
            {
                rv = new byte[message.Length - CRYPTO_ABYTES];
            }
            int len = DoFinal(rv, 0);
            rv.AsSpan(0, len).CopyTo(output);
            return rv.Length;

        }
#endif

        public int GetKeyBytesSize()
        {
            return CRYPTO_KEYBYTES;
        }

        public int GetIVBytesSize()
        {
            return CRYPTO_NPUBBYTES;
        }

        public int GetBlockSize()
        {
            return BLOCK_SIZE;
        }
    }
}

