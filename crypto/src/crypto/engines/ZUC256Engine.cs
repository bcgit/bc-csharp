using System;
using System.Drawing;
using System.Text;
using Org.BouncyCastle.Crypto;


#if NETSTANDARD1_0_OR_GREATER || NETCOREAPP1_0_OR_GREATER
using System.Runtime.CompilerServices;
#endif
#if NETCOREAPP3_0_OR_GREATER
using System.Runtime.InteropServices;
using System.Runtime.Intrinsics;
using System.Runtime.Intrinsics.X86;
#endif

using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.Crypto.Utilities;
using Org.BouncyCastle.Utilities;

namespace Org.BouncyCastle.Crypto.Engines
{
    public class ZUC256Engine : IStreamCipher
    {
        public string AlgorithmName => "ZUC256";
        public int IVSize => 25;
        public int KeySize => 32;

        internal uint[] LFSR = new uint[16];
        internal uint R1;
        internal uint R2;
        internal uint index = 0;
        internal uint[] keyStream;

        private ushort[] KD = {
            0x44D7,0x26BC,0x626B,0x135E,0x5789,0x35E2,0x7135,0x09AF,
            0x4D78,0x2F13,0x6BC4,0x1AF1,0x5E26,0x3C4D,0x789A,0x47AC,
        };

        private byte[] S0 = {
            0x3e,0x72,0x5b,0x47,0xca,0xe0,0x00,0x33,0x04,0xd1,0x54,0x98,0x09,0xb9,0x6d,0xcb,
            0x7b,0x1b,0xf9,0x32,0xaf,0x9d,0x6a,0xa5,0xb8,0x2d,0xfc,0x1d,0x08,0x53,0x03,0x90,
            0x4d,0x4e,0x84,0x99,0xe4,0xce,0xd9,0x91,0xdd,0xb6,0x85,0x48,0x8b,0x29,0x6e,0xac,
            0xcd,0xc1,0xf8,0x1e,0x73,0x43,0x69,0xc6,0xb5,0xbd,0xfd,0x39,0x63,0x20,0xd4,0x38,
            0x76,0x7d,0xb2,0xa7,0xcf,0xed,0x57,0xc5,0xf3,0x2c,0xbb,0x14,0x21,0x06,0x55,0x9b,
            0xe3,0xef,0x5e,0x31,0x4f,0x7f,0x5a,0xa4,0x0d,0x82,0x51,0x49,0x5f,0xba,0x58,0x1c,
            0x4a,0x16,0xd5,0x17,0xa8,0x92,0x24,0x1f,0x8c,0xff,0xd8,0xae,0x2e,0x01,0xd3,0xad,
            0x3b,0x4b,0xda,0x46,0xeb,0xc9,0xde,0x9a,0x8f,0x87,0xd7,0x3a,0x80,0x6f,0x2f,0xc8,
            0xb1,0xb4,0x37,0xf7,0x0a,0x22,0x13,0x28,0x7c,0xcc,0x3c,0x89,0xc7,0xc3,0x96,0x56,
            0x07,0xbf,0x7e,0xf0,0x0b,0x2b,0x97,0x52,0x35,0x41,0x79,0x61,0xa6,0x4c,0x10,0xfe,
            0xbc,0x26,0x95,0x88,0x8a,0xb0,0xa3,0xfb,0xc0,0x18,0x94,0xf2,0xe1,0xe5,0xe9,0x5d,
            0xd0,0xdc,0x11,0x66,0x64,0x5c,0xec,0x59,0x42,0x75,0x12,0xf5,0x74,0x9c,0xaa,0x23,
            0x0e,0x86,0xab,0xbe,0x2a,0x02,0xe7,0x67,0xe6,0x44,0xa2,0x6c,0xc2,0x93,0x9f,0xf1,
            0xf6,0xfa,0x36,0xd2,0x50,0x68,0x9e,0x62,0x71,0x15,0x3d,0xd6,0x40,0xc4,0xe2,0x0f,
            0x8e,0x83,0x77,0x6b,0x25,0x05,0x3f,0x0c,0x30,0xea,0x70,0xb7,0xa1,0xe8,0xa9,0x65,
            0x8d,0x27,0x1a,0xdb,0x81,0xb3,0xa0,0xf4,0x45,0x7a,0x19,0xdf,0xee,0x78,0x34,0x60,
        };

        private byte[] S1 = {
            0x55,0xc2,0x63,0x71,0x3b,0xc8,0x47,0x86,0x9f,0x3c,0xda,0x5b,0x29,0xaa,0xfd,0x77,
            0x8c,0xc5,0x94,0x0c,0xa6,0x1a,0x13,0x00,0xe3,0xa8,0x16,0x72,0x40,0xf9,0xf8,0x42,
            0x44,0x26,0x68,0x96,0x81,0xd9,0x45,0x3e,0x10,0x76,0xc6,0xa7,0x8b,0x39,0x43,0xe1,
            0x3a,0xb5,0x56,0x2a,0xc0,0x6d,0xb3,0x05,0x22,0x66,0xbf,0xdc,0x0b,0xfa,0x62,0x48,
            0xdd,0x20,0x11,0x06,0x36,0xc9,0xc1,0xcf,0xf6,0x27,0x52,0xbb,0x69,0xf5,0xd4,0x87,
            0x7f,0x84,0x4c,0xd2,0x9c,0x57,0xa4,0xbc,0x4f,0x9a,0xdf,0xfe,0xd6,0x8d,0x7a,0xeb,
            0x2b,0x53,0xd8,0x5c,0xa1,0x14,0x17,0xfb,0x23,0xd5,0x7d,0x30,0x67,0x73,0x08,0x09,
            0xee,0xb7,0x70,0x3f,0x61,0xb2,0x19,0x8e,0x4e,0xe5,0x4b,0x93,0x8f,0x5d,0xdb,0xa9,
            0xad,0xf1,0xae,0x2e,0xcb,0x0d,0xfc,0xf4,0x2d,0x46,0x6e,0x1d,0x97,0xe8,0xd1,0xe9,
            0x4d,0x37,0xa5,0x75,0x5e,0x83,0x9e,0xab,0x82,0x9d,0xb9,0x1c,0xe0,0xcd,0x49,0x89,
            0x01,0xb6,0xbd,0x58,0x24,0xa2,0x5f,0x38,0x78,0x99,0x15,0x90,0x50,0xb8,0x95,0xe4,
            0xd0,0x91,0xc7,0xce,0xed,0x0f,0xb4,0x6f,0xa0,0xcc,0xf0,0x02,0x4a,0x79,0xc3,0xde,
            0xa3,0xef,0xea,0x51,0xe6,0x6b,0x18,0xec,0x1b,0x2c,0x80,0xf7,0x74,0xe7,0xff,0x21,
            0x5a,0x6a,0x54,0x1e,0x41,0x31,0x92,0x35,0xc4,0x33,0x07,0x0a,0xba,0x7e,0x0e,0x34,
            0x88,0xb1,0x98,0x7c,0xf3,0x3d,0x60,0x6c,0x7b,0xca,0xd3,0x1f,0x32,0x65,0x04,0x28,
            0x64,0xbe,0x85,0x9b,0x2f,0x59,0x8a,0xd7,0xb0,0x25,0xac,0xaf,0x12,0x03,0xe2,0xf2,
        };

        private byte[][] ZUC256_D = {
            new byte[]{ 0x22,0x2F,0x24,0x2A,0x6D,0x40,0x40,0x40,
             0x40,0x40,0x40,0x40,0x40,0x52,0x10,0x30},
            new byte[]{0x22,0x2F,0x25,0x2A,0x6D,0x40,0x40,0x40,
             0x40,0x40,0x40,0x40,0x40,0x52,0x10,0x30 },
            new byte[]{0x23,0x2F,0x24,0x2A,0x6D,0x40,0x40,0x40,
             0x40,0x40,0x40,0x40,0x40,0x52,0x10,0x30 },
            new byte[]{0x23,0x2F,0x25,0x2A,0x6D,0x40,0x40,0x40,
             0x40,0x40,0x40,0x40,0x40,0x52,0x10,0x30 },
        };

        public void Init(bool forEncryption, ICipherParameters parameters)
        {
            ParametersWithIV ivParams = parameters as ParametersWithIV;
            if (ivParams == null)
                throw new ArgumentException(AlgorithmName + " Init requires an IV", "parameters");

            byte[] iv = ivParams.GetIV();
            // 兼容GmSSL的iv
            if (iv == null || (iv.Length != 23 && iv.Length != 25))
                throw new ArgumentException(AlgorithmName + " requires exactly 23 or 25 bytes of IV");

            ICipherParameters keyParam = ivParams.Parameters;
            byte[] key = ((KeyParameter)keyParam).GetKey();
            if (keyParam is KeyParameter)
            {
                if (key == null || key.Length != KeySize)
                    throw new ArgumentException(AlgorithmName + " requires exactly " + KeySize + " bytes of Key");
            }
            else
            {
                throw new ArgumentException(AlgorithmName + " Init parameters must contain a KeyParameter (or null for re-init)");
            }
            SetKey(key, iv, 0);
        }

        private void SetKey(byte[] K, byte[] IV, int macbits)
        {
            uint r1 = 0, r2 = 0;
            uint x0 = 0, x1 = 0, x2 = 0;
            uint w = 0, u = 0, v = 0;
			byte[] D;
			int i;

			byte IV17 = 0;
			byte IV18 = 0;
			byte IV19 = 0;
			byte IV20 = 0;
			byte IV21 = 0;
			byte IV22 = 0;
			byte IV23 = 0;
            byte IV24 = 0;

            if (IV.Length == 23)
            {
				IV17 = (byte)(IV[17] >> 2);
				IV18 = (byte)(((IV[17] & 0x3) << 4) | (IV[18] >> 4));
				IV19 = (byte)(((IV[18] & 0xf) << 2) | (IV[19] >> 6));
				IV20 = (byte)(IV[19] & 0x3f);
				IV21 = (byte)(IV[20] >> 2);
				IV22 = (byte)(((IV[20] & 0x3) << 4) | (IV[21] >> 4));
				IV23 = (byte)(((IV[21] & 0xf) << 2) | (IV[22] >> 6));
				IV24 = (byte)(IV[22] & 0x3f);
            }
            else
            {
				IV17 = IV[17];
				IV18 = IV[18];
				IV19 = IV[19];
				IV20 = IV[20];
				IV21 = IV[21];
				IV22 = IV[22];
				IV23 = IV[23];
                IV24 = IV[24];
			}

			D = macbits / 32 < 3 ? ZUC256_D[macbits / 32] : ZUC256_D[3];
			LFSR[0] = ZUC256_MAKEU31(K[0], D[0], K[21], K[16]);
			LFSR[1] = ZUC256_MAKEU31(K[1], D[1], K[22], K[17]);
			LFSR[2] = ZUC256_MAKEU31(K[2], D[2], K[23], K[18]);
			LFSR[3] = ZUC256_MAKEU31(K[3], D[3], K[24], K[19]);
			LFSR[4] = ZUC256_MAKEU31(K[4], D[4], K[25], K[20]);
			LFSR[5] = ZUC256_MAKEU31(IV[0], (uint)(D[5] | IV17), K[5], K[26]);
			LFSR[6] = ZUC256_MAKEU31(IV[1], (uint)(D[6] | IV18), K[6], K[27]);
			LFSR[7] = ZUC256_MAKEU31(IV[10], (uint)(D[7] | IV19), K[7], IV[2]);
			LFSR[8] = ZUC256_MAKEU31(K[8], (uint)(D[8] | IV20), IV[3], IV[11]);
			LFSR[9] = ZUC256_MAKEU31(K[9], (uint)(D[9] | IV21), IV[12], IV[4]);
			LFSR[10] = ZUC256_MAKEU31(IV[5], (uint)(D[10] | IV22), K[10], K[28]);
			LFSR[11] = ZUC256_MAKEU31(K[11], (uint)(D[11] | IV23), IV[6], IV[13]);
			LFSR[12] = ZUC256_MAKEU31(K[12], (uint)(D[12] | IV24), IV[7], IV[14]);
			LFSR[13] = ZUC256_MAKEU31(K[13], D[13], IV[15], IV[8]);
			LFSR[14] = ZUC256_MAKEU31(K[14], (uint)(D[14] | (K[31] >> 4)), IV[16], IV[9]);
			LFSR[15] = ZUC256_MAKEU31(K[15], (uint)(D[15] | (K[31] & 0x0F)), K[30], K[29]);

			r1 = 0;
            r2 = 0;
            for (i = 0; i < 32; i++)
            {
                BitReconstruction3(LFSR, ref x0, ref x1, ref x2);
                w = F(ref r1, ref r2, ref u, ref v, x0, x1, x2);
                LFSRWithInitialisationMode(ref LFSR, ref v, w >> 1);
            }

            BitReconstruction2(LFSR, ref x1, ref x2);
            F_(ref r1, ref r2, ref u, ref v, x1, x2);
            LFSRWithWorkMode(ref LFSR, ref v);

            R1 = r1;
            R2 = r2;
        }

        public void ProcessBytes(byte[] input, int inOff, int len, byte[] output, int outOff)
        {
            byte[] block = new byte[4];
            int count = inOff + len;
            GenerateKeyStream((uint)count);
            int grou_count = count / 4;
            int i = 0;

            for (i = 0; i < grou_count; i++)
            {
                PUTU32(ref block, keyStream[i]);
                gmssl_memxor(ref output, i, input, block, block.Length);
            }
            if (input.Length % 4 != 0)
            {
                PUTU32(ref block, keyStream[i]);
                gmssl_memxor(ref output, i, input, block, input.Length % 4);
            }
        }

        private void gmssl_memxor(ref byte[] _out, int index, byte[] _in, byte[] block, int len)
        {
            for (int i = index * block.Length, j = 0; i < index * block.Length + len; i++, j++)
            {
                _out[i] = (byte)(_in[i] ^ block[j]);
            }
        }

#if NETCOREAPP2_1_OR_GREATER || NETSTANDARD2_1_OR_GREATER
        private void gmssl_memxor(ref Span<byte> _out, int index, ReadOnlySpan<byte> _in, byte[] block, int len)
        {
            for (int i = index * block.Length, j = 0; i < index * block.Length + len; i++, j++)
            {
                _out[i] = (byte)(_in[i] ^ block[j]);
            }
        }
#endif

        public byte PUTU32ONE(uint input, int index)
        {
            byte w = 0x00;
            switch ((index + 1) % 4)
            {
                case 1:
                    w = (byte)(input >> 24);
                    break;
                case 2:
                    w = (byte)(input >> 16);
                    break;
                case 3:
                    w = (byte)(input >> 8);
                    break;
                default:
                    w = (byte)input;
                    break;
            };
            return w;
        }

#if NETCOREAPP2_1_OR_GREATER || NETSTANDARD2_1_OR_GREATER
        public void ProcessBytes(ReadOnlySpan<byte> input, Span<byte> output)
        {
            byte[] block = new byte[4];
            int count = input.Length;
            GenerateKeyStream((uint)count);
            int grou_count = count / 4;
            int i = 0;

            for (i = 0; i < grou_count; i++)
            {
                PUTU32(ref block, keyStream[i]);
                gmssl_memxor(ref output, i, input, block, block.Length);
            }
            if (input.Length % 4 != 0)
            {
                PUTU32(ref block, keyStream[i]);
                gmssl_memxor(ref output, i, input, block, input.Length % 4);
            }
        }
#endif

        public void Reset()
        {
            index = 0;
            keyStream = null;
            R1 = R2 = 0;
            Array.Clear(LFSR, 0, LFSR.Length);
        }

        public byte ReturnByte(byte input)
        {
            GenerateKeyWord();

            byte w = 0x00;
            switch (index % 4)
            {
                case 1:
                    w = (byte)(keyStream[index - 1] >> 24);
                    break;
                case 2:
                    w = (byte)(keyStream[index - 1] >> 16);
                    break;
                case 3:
                    w = (byte)(keyStream[index - 1] >> 8);
                    break;
                default:
                    w = (byte)keyStream[index - 1];
                    break;
            };
            byte output = (byte)(w ^ input);

            return output;
        }

        private void GenerateKeyStream(uint _len)
        {
            uint x0 = 0, x1 = 0, x2 = 0, x3 = 0;
            uint u = 0, v = 0;
            int i;
            uint len = _len / 4;
            if (_len % 4 != 0)
            {
                len++;
            }
            keyStream = new uint[len];

            for (i = 0; i < len; i++)
            {
                BitReconstruction4(LFSR, ref x0, ref x1, ref x2, ref x3);
                keyStream[i] = x3 ^ F(ref R1, ref R2, ref u, ref v, x0, x1, x2);
                LFSRWithWorkMode(ref LFSR, ref v);
            }
            index = (uint)len;
        }

        private void GenerateKeyWord()
        {
            uint x0 = 0, x1 = 0, x2 = 0, x3 = 0;
            uint u = 0, v = 0;

            if (index == 0)
            {
                keyStream = new uint[1];
            }
            else
            {
                var _keyStream = new uint[index + 1];
                Array.Copy(keyStream, 0, _keyStream, 0, keyStream.Length);
                keyStream = _keyStream;
            }

            BitReconstruction4(LFSR, ref x0, ref x1, ref x2, ref x3);
            keyStream[index] = x3 ^ F(ref R1, ref R2, ref u, ref v, x0, x1, x2);
            LFSRWithWorkMode(ref LFSR, ref v);

            index++;
        }

        private void PUTU32(ref byte[] block, uint x)
        {
            block[0] = (byte)(x >> 24);
            block[1] = (byte)(x >> 16);
            block[2] = (byte)(x >> 8);
            block[3] = (byte)(x);
        }

        private void ADD31(ref uint a, uint b)
        {
            a += (b);
            a = (a & 0x7fffffff) + (a >> 31);
        }

        private uint ROT31(uint a, int k)
        {
            return ((((a) << (k)) | ((a) >> (31 - (k)))) & 0x7FFFFFFF);
        }

        private uint ROT32(uint a, int k)
        {
            return (((a) << (k)) | ((a) >> (32 - (k))));
        }

        private uint L1(uint x)
        {
            return ((x) ^ ROT32((x), 2) ^ ROT32((x), 10) ^ ROT32((x), 18) ^ ROT32((x), 24));
        }

        private uint L2(uint x)
        {
            return ((x) ^ ROT32((x), 8) ^ ROT32((x), 14) ^ ROT32((x), 22) ^ ROT32((x), 30));
        }

        private void LFSRWithInitialisationMode(ref uint[] LFSR, ref uint v, uint u)
        {
            v = (uint)LFSR[0];
            ADD31(ref v, ROT31((uint)LFSR[0], 8));
            ADD31(ref v, ROT31((uint)LFSR[4], 20));
            ADD31(ref v, ROT31((uint)LFSR[10], 21));
            ADD31(ref v, ROT31((uint)LFSR[13], 17));
            ADD31(ref v, ROT31((uint)LFSR[15], 15));
            ADD31(ref v, u);
            for (int j = 0; j < 15; j++)
            {
                LFSR[j] = LFSR[j + 1];
            }
            LFSR[15] = v;
        }

        private void LFSRWithWorkMode(ref uint[] LFSR, ref uint v)
        {
            int j;
            ulong a = LFSR[0];
            a += ((ulong)LFSR[0]) << 8;
            a += ((ulong)LFSR[4]) << 20;
            a += ((ulong)LFSR[10]) << 21;
            a += ((ulong)LFSR[13]) << 17;
            a += ((ulong)LFSR[15]) << 15;
            a = (a & 0x7fffffff) + (a >> 31);
            v = (uint)((a & 0x7fffffff) + (a >> 31));
            for (j = 0; j < 15; j++)
            {
                LFSR[j] = LFSR[j + 1];
            }
            LFSR[15] = v;
        }

        private void BitReconstruction2(uint[] LFSR, ref uint x1, ref uint x2)
        {
            x1 = (((uint)LFSR[11] & 0xFFFF) << 16) | ((uint)LFSR[9] >> 15);
            x2 = (((uint)LFSR[7] & 0xFFFF) << 16) | ((uint)LFSR[5] >> 15);
        }

        private void BitReconstruction3(uint[] LFSR, ref uint x0, ref uint x1, ref uint x2)
        {
            x0 = (((uint)LFSR[15] & 0x7FFF8000) << 1) | ((uint)LFSR[14] & 0xFFFF);
            BitReconstruction2(LFSR, ref x1, ref x2);
        }

        private void BitReconstruction4(uint[] LFSR, ref uint x0, ref uint x1, ref uint x2, ref uint x3)
        {
            BitReconstruction3(LFSR, ref x0, ref x1, ref x2);
            x3 = (((uint)LFSR[2] & 0xFFFF) << 16) | ((uint)LFSR[0] >> 15);
        }

        private uint MAKEU31(uint k, uint d, uint iv)
        {
            return (((k) << 23) | ((d) << 8) | (iv));
        }

        private uint MAKEU32(uint a, uint b, uint c, uint d)
        {
            return (((a) << 24) | ((b) << 16) | ((c) << 8) | ((d)));
        }

        private void F_(ref uint r1, ref uint r2, ref uint u, ref uint v, uint x1, uint x2)
        {
            uint W1 = r1 + x1;
            uint W2 = r2 ^ x2;
            u = L1((W1 << 16) | (W2 >> 16));
            v = L2((W2 << 16) | (W1 >> 16));
            r1 = MAKEU32((uint)S0[u >> 24], (uint)S1[(u >> 16) & 0xFF], (uint)S0[(u >> 8) & 0xFF], (uint)S1[u & 0xFF]);
            r2 = MAKEU32((uint)S0[v >> 24], (uint)S1[(v >> 16) & 0xFF], (uint)S0[(v >> 8) & 0xFF], (uint)S1[v & 0xFF]);
        }

        private uint F(ref uint r1, ref uint r2, ref uint u, ref uint v, uint x0, uint x1, uint x2)
        {
            uint t = (x0 ^ r1) + r2;
            F_(ref r1, ref r2, ref u, ref v, x1, x2);
            return t;
		}

		private uint ZUC256_MAKEU31(uint a, uint b, uint c, uint d)
		{
			return (a << 23) | (b << 16) | (c << 8) | d;
		}
	}
}
