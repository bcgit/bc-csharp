using System;
using System.IO;
using Org.BouncyCastle.Crypto.Modes;
using Org.BouncyCastle.Crypto.Parameters;

/**
 * Photon-Beetle, https://www.isical.ac.in/~lightweight/beetle/
 * https://csrc.nist.gov/CSRC/media/Projects/lightweight-cryptography/documents/readonlyist-round/updated-spec-doc/photon-beetle-spec-readonly.pdf
 * <p>
 * Photon-Beetle with reference to C Reference Impl from: https://github.com/PHOTON-Beetle/Software
 * </p>
 */

namespace Org.BouncyCastle.Crypto.Engines
{
    public class PhotonBeetleEngine : IAeadBlockCipher
    {
        public enum PhotonBeetleParameters
        {
            pb32,
            pb128
        }
        private bool input_empty;
        private bool forEncryption;
        private bool initialised;
        private byte[] K;
        private byte[] N;
        private byte[] state;
        private byte[][] state_2d;
        private byte[] A;
        private byte[] T;
        private MemoryStream aadData = new MemoryStream();
        private MemoryStream message = new MemoryStream();
        private readonly int CRYPTO_KEYBYTES = 16;
        private readonly int CRYPTO_NPUBBYTES = 16;
        private readonly int RATE_INBYTES;
        private readonly int RATE_INBYTES_HALF;
        private int STATE_INBYTES;
        private int TAG_INBYTES = 16;
        private int LAST_THREE_BITS_OFFSET;
        private int ROUND = 12;
        private int D = 8;
        private int Dq = 3;
        private int Dr = 7;
        private int DSquare = 64;
        private int S = 4;
        private int S_1 = 3;
        private byte[][] RC = {
            new byte[]{1, 3, 7, 14, 13, 11, 6, 12, 9, 2, 5, 10},
            new byte[]{0, 2, 6, 15, 12, 10, 7, 13, 8, 3, 4, 11},
            new byte[]{2, 0, 4, 13, 14, 8, 5, 15, 10, 1, 6, 9},
            new byte[]{6, 4, 0, 9, 10, 12, 1, 11, 14, 5, 2, 13},
            new byte[]{14, 12, 8, 1, 2, 4, 9, 3, 6, 13, 10, 5},
            new byte[]{15, 13, 9, 0, 3, 5, 8, 2, 7, 12, 11, 4},
            new byte[]{13, 15, 11, 2, 1, 7, 10, 0, 5, 14, 9, 6},
            new byte[]{9, 11, 15, 6, 5, 3, 14, 4, 1, 10, 13, 2}
    };
        private byte[][] MixColMatrix = {
            new byte[]{2, 4, 2, 11, 2, 8, 5, 6},
            new byte[]{12, 9, 8, 13, 7, 7, 5, 2},
            new byte[]{4, 4, 13, 13, 9, 4, 13, 9},
            new byte[]{1, 6, 5, 1, 12, 13, 15, 14},
            new byte[]{15, 12, 9, 13, 14, 5, 14, 13},
            new byte[]{9, 14, 5, 15, 4, 12, 9, 6},
            new byte[]{12, 2, 2, 10, 3, 1, 1, 14},
            new byte[]{15, 1, 13, 10, 5, 10, 2, 3}
    };

        private byte[] sbox = { 12, 5, 6, 11, 9, 0, 10, 13, 3, 14, 15, 8, 4, 7, 1, 2 };
        public PhotonBeetleEngine(PhotonBeetleParameters pbp)
        {
            int CAPACITY_INBITS = 0, RATE_INBITS = 0;
            switch (pbp)
            {
                case PhotonBeetleParameters.pb32:
                    RATE_INBITS = 32;
                    CAPACITY_INBITS = 224;
                    break;
                case PhotonBeetleParameters.pb128:
                    RATE_INBITS = 128;
                    CAPACITY_INBITS = 128;
                    break;
            }
            RATE_INBYTES = (RATE_INBITS + 7) >> 3;
            RATE_INBYTES_HALF = RATE_INBYTES >> 1;
            int STATE_INBITS = RATE_INBITS + CAPACITY_INBITS;
            STATE_INBYTES = (STATE_INBITS + 7) >> 3;
            LAST_THREE_BITS_OFFSET = (STATE_INBITS - ((STATE_INBYTES - 1) << 3) - 3);
            initialised = false;
        }

        public string AlgorithmName => "Photon-Beetle AEAD";

        public IBlockCipher UnderlyingCipher => throw new NotImplementedException();

        public byte[] GetMac()
        {
            return T;
        }

        public int GetOutputSize(int len)
        {
            return len + TAG_INBYTES;
        }

        public int GetUpdateOutputSize(int len)
        {
            return len;
        }

        public void Init(bool forEncryption, ICipherParameters parameters)
        {
            this.forEncryption = forEncryption;
            if (!(parameters is ParametersWithIV param))
            {
                throw new ArgumentException("Photon-Beetle AEAD init parameters must include an IV");
            }
            ParametersWithIV ivParams = param;
            N = ivParams.GetIV();
            if (N == null || N.Length != CRYPTO_NPUBBYTES)
            {
                throw new ArgumentException("Photon-Beetle AEAD requires exactly 16 bytes of IV");
            }
            if (!(ivParams.Parameters is KeyParameter))
            {
                throw new ArgumentException("Photon-Beetle AEAD init parameters must include a key");
            }
            KeyParameter key = (KeyParameter)ivParams.Parameters;
            K = key.GetKey();
            if (K.Length != CRYPTO_KEYBYTES)
            {
                throw new ArgumentException("Photon-Beetle AEAD key must be 128 bits long");
            }

            state = new byte[STATE_INBYTES];
            state_2d = new byte[D][];
            for (int i = 0; i < D; ++i)
            {
                state_2d[i] = new byte[D];
            }
            T = new byte[TAG_INBYTES];
            initialised = true;
            reset(false);
        }

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

        public void Reset()
        {
            if (!initialised)
            {
                throw new ArgumentException("Need call init function before encryption/decryption");
            }
            reset(true);
        }

        private void reset(bool clearMac)
        {
            if (clearMac)
            {
                T = null;
            }
            input_empty = true;
            aadData.SetLength(0);
            message.SetLength(0);
            Array.Copy(K, 0, state, 0, K.Length);
            Array.Copy(N, 0, state, K.Length, N.Length);
        }

        void PHOTON_Permutation()
        {
            int i, j, k, l;
            for (i = 0; i < DSquare; i++)
            {
                state_2d[i >> Dq][i & Dr] = (byte)(((state[i >> 1] & 0xFF) >> (4 * (i & 1))) & 0xf);
            }
            for (int round = 0; round < ROUND; round++)
            {
                //AddKey
                for (i = 0; i < D; i++)
                {
                    state_2d[i][0] ^= RC[i][round];
                }
                //SubCell
                for (i = 0; i < D; i++)
                {
                    for (j = 0; j < D; j++)
                    {
                        state_2d[i][j] = sbox[state_2d[i][j]];
                    }
                }
                //ShiftRow
                for (i = 1; i < D; i++)
                {
                    Array.Copy(state_2d[i], 0, state, 0, D);
                    Array.Copy(state, i, state_2d[i], 0, D - i);
                    Array.Copy(state, 0, state_2d[i], D - i, i);
                }
                //MixColumn
                for (j = 0; j < D; j++)
                {
                    for (i = 0; i < D; i++)
                    {
                        byte sum = 0;
                        for (k = 0; k < D; k++)
                        {
                            int x = MixColMatrix[i][k], ret = 0, b = state_2d[k][j];
                            for (l = 0; l < S; l++)
                            {
                                if (((b >> l) & 1) != 0)
                                {
                                    ret ^= x;
                                }
                                if (((x >> S_1) & 1) != 0)
                                {
                                    x <<= 1;
                                    x ^= 0x3;
                                }
                                else
                                {
                                    x <<= 1;
                                }
                            }
                            sum ^= (byte)(ret & 15);
                        }
                        state[i] = sum;
                    }
                    for (i = 0; i < D; i++)
                    {
                        state_2d[i][j] = state[i];
                    }
                }
            }
            for (i = 0; i < DSquare; i += 2)
            {
                state[i >> 1] = (byte)(((state_2d[i >> Dq][i & Dr] & 0xf)) | ((state_2d[i >> Dq][(i + 1) & Dr] & 0xf) << 4));
            }
        }

        private byte select(bool condition1, bool condition2, byte option3, byte option4)
        {
            if (condition1 && condition2)
            {
                return 1;
            }
            if (condition1)
            {
                return 2;
            }
            if (condition2)
            {
                return option3;
            }
            return option4;
        }

        void rhoohr(byte[] ciphertext, int offset, byte[] plaintext, int inOff, int DBlen_inbytes)
        {
            byte[] OuterState_part1_ROTR1 = state_2d[0];
            int i, loop_end = System.Math.Min(DBlen_inbytes, RATE_INBYTES_HALF);
            for (i = 0; i < RATE_INBYTES_HALF - 1; i++)
            {
                OuterState_part1_ROTR1[i] = (byte)(((state[i] & 0xFF) >> 1) | ((state[(i + 1)] & 1) << 7));
            }
            OuterState_part1_ROTR1[RATE_INBYTES_HALF - 1] = (byte)(((state[i] & 0xFF) >> 1) | ((state[0] & 1) << 7));
            i = 0;
            while (i < loop_end)
            {
                ciphertext[i + offset] = (byte)(state[i + RATE_INBYTES_HALF] ^ plaintext[i++ + inOff]);
            }
            while (i < DBlen_inbytes)
            {
                ciphertext[i + offset] = (byte)(OuterState_part1_ROTR1[i - RATE_INBYTES_HALF] ^ plaintext[i++ + inOff]);
            }
            if (forEncryption)
            {
                XOR(plaintext, inOff, DBlen_inbytes);
            }
            else
            {
                XOR(ciphertext, inOff, DBlen_inbytes);
            }
        }

        void XOR(byte[] in_right, int rOff, int iolen_inbytes)
        {
            for (int i = 0; i < iolen_inbytes; i++)
            {
                state[i] ^= in_right[rOff++];
            }
        }

        public int DoFinal(byte[] output, int outOff)
        {
            if (!initialised)
            {
                throw new ArgumentException("Need call init function before encryption/decryption");
            }
            int len = (int)message.Length - (forEncryption ? 0 : TAG_INBYTES);
            if ((forEncryption && len + TAG_INBYTES + outOff > output.Length) ||
                (!forEncryption && len + outOff > output.Length))
            {
                throw new OutputLengthException("output buffer too short");
            }
            byte[] input = message.GetBuffer();
            int inOff = 0;
            A = aadData.GetBuffer();
            int adlen = (int)aadData.Length, i;
            if (adlen != 0 || len != 0)
            {
                input_empty = false;
            }
            byte c0 = select((len != 0), ((adlen % RATE_INBYTES) == 0), (byte)3, (byte)4);
            byte c1 = select((adlen != 0), ((len % RATE_INBYTES) == 0), (byte)5, (byte)6);
            int Dlen_inblocks, LastDBlocklen;
            if (adlen != 0)
            {
                Dlen_inblocks = (adlen + RATE_INBYTES - 1) / RATE_INBYTES;
                for (i = 0; i < Dlen_inblocks - 1; i++)
                {
                    PHOTON_Permutation();
                    XOR(A, i * RATE_INBYTES, RATE_INBYTES);
                }
                PHOTON_Permutation();
                LastDBlocklen = adlen - i * RATE_INBYTES;
                XOR(A, i * RATE_INBYTES, LastDBlocklen);
                if (LastDBlocklen < RATE_INBYTES)
                {
                    state[LastDBlocklen] ^= 0x01; // ozs
                }
                state[STATE_INBYTES - 1] ^= (byte)(c0 << LAST_THREE_BITS_OFFSET);
            }
            if (len != 0)
            {
                Dlen_inblocks = (len + RATE_INBYTES - 1) / RATE_INBYTES;
                for (i = 0; i < Dlen_inblocks - 1; i++)
                {
                    PHOTON_Permutation();
                    rhoohr(output, outOff + i * RATE_INBYTES, input, inOff + i * RATE_INBYTES, RATE_INBYTES);
                }
                PHOTON_Permutation();
                LastDBlocklen = len - i * RATE_INBYTES;
                rhoohr(output, outOff + i * RATE_INBYTES, input, inOff + i * RATE_INBYTES, LastDBlocklen);
                if (LastDBlocklen < RATE_INBYTES)
                {
                    state[LastDBlocklen] ^= 0x01; // ozs
                }
                state[STATE_INBYTES - 1] ^= (byte)(c1 << LAST_THREE_BITS_OFFSET);
            }
            outOff += len;
            if (input_empty)
            {
                state[STATE_INBYTES - 1] ^= (byte)(1 << LAST_THREE_BITS_OFFSET);
            }
            PHOTON_Permutation();
            T = new byte[TAG_INBYTES];
            Array.Copy(state, 0, T, 0, TAG_INBYTES);
            if (forEncryption)
            {
                Array.Copy(T, 0, output, outOff, TAG_INBYTES);
                len += TAG_INBYTES;
            }
            else
            {
                for (i = 0; i < TAG_INBYTES; ++i)
                {
                    if (T[i] != input[len + i])
                    {
                        throw new ArgumentException("Mac does not match");
                    }
                }
            }
            reset(false);
            return len;
        }

        public int GetBlockSize()
        {
            return RATE_INBYTES;
        }

        public int GetKeyBytesSize()
        {
            return CRYPTO_KEYBYTES;
        }

        public int GetIVBytesSize()
        {
            return CRYPTO_NPUBBYTES;
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
                rv = new byte[message.Length + 16];
            }
            else
            {
                rv = new byte[message.Length - 16];
            }
            int len = DoFinal(rv, 0);
            rv.AsSpan(0, len).CopyTo(output);
            return rv.Length;
        }
#endif
    }
}
