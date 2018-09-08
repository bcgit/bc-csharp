using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.Crypto.Utilities;
using Org.BouncyCastle.Utilities;
using System;

namespace Org.BouncyCastle.Crypto.Engines
{
    public class SM4Engine
    : IBlockCipher
    {
        private static readonly int BLOCK_SIZE = 16;

        private static readonly byte[] Sbox =
            {
            (byte)0xd6, (byte)0x90, (byte)0xe9, (byte)0xfe, (byte)0xcc, (byte)0xe1, (byte)0x3d, (byte)0xb7, (byte)0x16, (byte)0xb6, (byte)0x14, (byte)0xc2, (byte)0x28, (byte)0xfb, (byte)0x2c, (byte)0x05,
            (byte)0x2b, (byte)0x67, (byte)0x9a, (byte)0x76, (byte)0x2a, (byte)0xbe, (byte)0x04, (byte)0xc3, (byte)0xaa, (byte)0x44, (byte)0x13, (byte)0x26, (byte)0x49, (byte)0x86, (byte)0x06, (byte)0x99,
            (byte)0x9c, (byte)0x42, (byte)0x50, (byte)0xf4, (byte)0x91, (byte)0xef, (byte)0x98, (byte)0x7a, (byte)0x33, (byte)0x54, (byte)0x0b, (byte)0x43, (byte)0xed, (byte)0xcf, (byte)0xac, (byte)0x62,
            (byte)0xe4, (byte)0xb3, (byte)0x1c, (byte)0xa9, (byte)0xc9, (byte)0x08, (byte)0xe8, (byte)0x95, (byte)0x80, (byte)0xdf, (byte)0x94, (byte)0xfa, (byte)0x75, (byte)0x8f, (byte)0x3f, (byte)0xa6,
            (byte)0x47, (byte)0x07, (byte)0xa7, (byte)0xfc, (byte)0xf3, (byte)0x73, (byte)0x17, (byte)0xba, (byte)0x83, (byte)0x59, (byte)0x3c, (byte)0x19, (byte)0xe6, (byte)0x85, (byte)0x4f, (byte)0xa8,
            (byte)0x68, (byte)0x6b, (byte)0x81, (byte)0xb2, (byte)0x71, (byte)0x64, (byte)0xda, (byte)0x8b, (byte)0xf8, (byte)0xeb, (byte)0x0f, (byte)0x4b, (byte)0x70, (byte)0x56, (byte)0x9d, (byte)0x35,
            (byte)0x1e, (byte)0x24, (byte)0x0e, (byte)0x5e, (byte)0x63, (byte)0x58, (byte)0xd1, (byte)0xa2, (byte)0x25, (byte)0x22, (byte)0x7c, (byte)0x3b, (byte)0x01, (byte)0x21, (byte)0x78, (byte)0x87,
            (byte)0xd4, (byte)0x00, (byte)0x46, (byte)0x57, (byte)0x9f, (byte)0xd3, (byte)0x27, (byte)0x52, (byte)0x4c, (byte)0x36, (byte)0x02, (byte)0xe7, (byte)0xa0, (byte)0xc4, (byte)0xc8, (byte)0x9e,
            (byte)0xea, (byte)0xbf, (byte)0x8a, (byte)0xd2, (byte)0x40, (byte)0xc7, (byte)0x38, (byte)0xb5, (byte)0xa3, (byte)0xf7, (byte)0xf2, (byte)0xce, (byte)0xf9, (byte)0x61, (byte)0x15, (byte)0xa1,
            (byte)0xe0, (byte)0xae, (byte)0x5d, (byte)0xa4, (byte)0x9b, (byte)0x34, (byte)0x1a, (byte)0x55, (byte)0xad, (byte)0x93, (byte)0x32, (byte)0x30, (byte)0xf5, (byte)0x8c, (byte)0xb1, (byte)0xe3,
            (byte)0x1d, (byte)0xf6, (byte)0xe2, (byte)0x2e, (byte)0x82, (byte)0x66, (byte)0xca, (byte)0x60, (byte)0xc0, (byte)0x29, (byte)0x23, (byte)0xab, (byte)0x0d, (byte)0x53, (byte)0x4e, (byte)0x6f,
            (byte)0xd5, (byte)0xdb, (byte)0x37, (byte)0x45, (byte)0xde, (byte)0xfd, (byte)0x8e, (byte)0x2f, (byte)0x03, (byte)0xff, (byte)0x6a, (byte)0x72, (byte)0x6d, (byte)0x6c, (byte)0x5b, (byte)0x51,
            (byte)0x8d, (byte)0x1b, (byte)0xaf, (byte)0x92, (byte)0xbb, (byte)0xdd, (byte)0xbc, (byte)0x7f, (byte)0x11, (byte)0xd9, (byte)0x5c, (byte)0x41, (byte)0x1f, (byte)0x10, (byte)0x5a, (byte)0xd8,
            (byte)0x0a, (byte)0xc1, (byte)0x31, (byte)0x88, (byte)0xa5, (byte)0xcd, (byte)0x7b, (byte)0xbd, (byte)0x2d, (byte)0x74, (byte)0xd0, (byte)0x12, (byte)0xb8, (byte)0xe5, (byte)0xb4, (byte)0xb0,
            (byte)0x89, (byte)0x69, (byte)0x97, (byte)0x4a, (byte)0x0c, (byte)0x96, (byte)0x77, (byte)0x7e, (byte)0x65, (byte)0xb9, (byte)0xf1, (byte)0x09, (byte)0xc5, (byte)0x6e, (byte)0xc6, (byte)0x84,
            (byte)0x18, (byte)0xf0, (byte)0x7d, (byte)0xec, (byte)0x3a, (byte)0xdc, (byte)0x4d, (byte)0x20, (byte)0x79, (byte)0xee, (byte)0x5f, (byte)0x3e, (byte)0xd7, (byte)0xcb, (byte)0x39, (byte)0x48
        };

        private static readonly uint[] CK =
            {
            0x00070e15, 0x1c232a31, 0x383f464d, 0x545b6269,
            0x70777e85, 0x8c939aa1, 0xa8afb6bd, 0xc4cbd2d9,
            0xe0e7eef5, 0xfc030a11, 0x181f262d, 0x343b4249,
            0x50575e65, 0x6c737a81, 0x888f969d, 0xa4abb2b9,
            0xc0c7ced5, 0xdce3eaf1, 0xf8ff060d, 0x141b2229,
            0x30373e45, 0x4c535a61, 0x686f767d, 0x848b9299,
            0xa0a7aeb5, 0xbcc3cad1, 0xd8dfe6ed, 0xf4fb0209,
            0x10171e25, 0x2c333a41, 0x484f565d, 0x646b7279
        };

        private static readonly uint[] FK =
            {
            0xa3b1bac6, 0x56aa3350, 0x677d9197, 0xb27022dc
        };

        private static readonly uint[] X = new uint[4];

        private uint[] rk;

        private uint RotateLeft(
            uint x,
            int bits)
        {
            return (x << bits) | (x >> -bits);
        }

        // non-linear substitution tau.
        private uint Tau(
            uint A)
        {
            uint b0 = (uint)Sbox[(A >> 24) & 0xff] & 0xff;
            uint b1 = (uint)Sbox[(A >> 16) & 0xff] & 0xff;
            uint b2 = (uint)Sbox[(A >> 8) & 0xff] & 0xff;
            uint b3 = (uint)Sbox[A & 0xff] & 0xff;

            return (uint)((b0 << 24) | (b1 << 16) | (b2 << 8) | b3);
        }

        private uint L_ap(
            uint B)
        {
            return (B ^ (RotateLeft(B, 13)) ^ (RotateLeft(B, 23)));
        }

        private uint T_ap(
            uint Z)
        {
            return L_ap(Tau(Z));
        }

        // Key expansion
        private uint[] ExpandKey(bool forEncryption, byte[] key)
        {
            uint[] rk = new uint[32];
            uint[] MK = new uint[4];

            MK[0] = Pack.BE_To_UInt32(key, 0);
            MK[1] = Pack.BE_To_UInt32(key, 4);
            MK[2] = Pack.BE_To_UInt32(key, 8);
            MK[3] = Pack.BE_To_UInt32(key, 12);

            int i;
            uint[] K = new uint[4];
            K[0] = MK[0] ^ FK[0];
            K[1] = MK[1] ^ FK[1];
            K[2] = MK[2] ^ FK[2];
            K[3] = MK[3] ^ FK[3];

            if (forEncryption)
            {
                rk[0] = K[0] ^ T_ap(K[1] ^ K[2] ^ K[3] ^ CK[0]);
                rk[1] = K[1] ^ T_ap(K[2] ^ K[3] ^ rk[0] ^ CK[1]);
                rk[2] = K[2] ^ T_ap(K[3] ^ rk[0] ^ rk[1] ^ CK[2]);
                rk[3] = K[3] ^ T_ap(rk[0] ^ rk[1] ^ rk[2] ^ CK[3]);
                for (i = 4; i < 32; i++)
                {
                    rk[i] = rk[i - 4] ^ T_ap(rk[i - 3] ^ rk[i - 2] ^ rk[i - 1] ^ CK[i]);
                }
            }
            else
            {
                rk[31] = K[0] ^ T_ap(K[1] ^ K[2] ^ K[3] ^ CK[0]);
                rk[30] = K[1] ^ T_ap(K[2] ^ K[3] ^ rk[31] ^ CK[1]);
                rk[29] = K[2] ^ T_ap(K[3] ^ rk[31] ^ rk[30] ^ CK[2]);
                rk[28] = K[3] ^ T_ap(rk[31] ^ rk[30] ^ rk[29] ^ CK[3]);
                for (i = 27; i >= 0; i--)
                {
                    rk[i] = rk[i + 4] ^ T_ap(rk[i + 3] ^ rk[i + 2] ^ rk[i + 1] ^ CK[31 - i]);
                }
            }

            return rk;
        }


        // Linear substitution L
        private uint L(uint B)
        {
            uint C;
            C = (B ^ (RotateLeft(B, 2)) ^ (RotateLeft(B, 10)) ^ (RotateLeft(B,
                18)) ^ (RotateLeft(B, 24)));
            return C;
        }

        // Mixer-substitution T
        private uint T(uint Z)
        {
            return L(Tau(Z));
        }

        // reverse substitution
        private void R(uint[] A, int off)
        {
            int off0 = off;
            int off1 = off + 1;
            int off2 = off + 2;
            int off3 = off + 3;

            A[off0] = A[off0] ^ A[off3];
            A[off3] = A[off0] ^ A[off3];
            A[off0] = A[off0] ^ A[off3];
            A[off1] = A[off1] ^ A[off2];
            A[off2] = A[off1] ^ A[off2];
            A[off1] = A[off1] ^ A[off2];
        }

        // The round functions
        private uint F0(uint[] X, uint rk)
        {
            return (X[0] ^ T((uint)(X[1] ^ X[2] ^ X[3] ^ rk)));
        }

        private uint F1(uint[] X, uint rk)
        {
            return (X[1] ^ T((uint)(X[2] ^ X[3] ^ X[0] ^ rk)));
        }

        private uint F2(uint[] X, uint rk)
        {
            return (X[2] ^ T((uint)(X[3] ^ X[0] ^ X[1] ^ rk)));
        }

        private uint F3(uint[] X, uint rk)
        {
            return (X[3] ^ T((uint)(X[0] ^ X[1] ^ X[2] ^ rk)));
        }

        public string AlgorithmName => "SM4";

        public bool IsPartialBlockOkay => false;

        public int GetBlockSize()
        {
            return BLOCK_SIZE;
        }

        public void Init(bool forEncryption, ICipherParameters parameters)
        {
            if (!(parameters is KeyParameter))
                throw new ArgumentException("invalid parameter passed to SM4 init - " + Platform.GetTypeName(parameters));

            byte[] key = ((KeyParameter)parameters).GetKey();
            if (key.Length!=16)
                throw new ArgumentException("SM4 requires a 128 bit key");

            rk = ExpandKey(forEncryption, key);
        }

        public int ProcessBlock(byte[] inBuf, int inOff, byte[] outBuf, int outOff)
        {
            if (rk == null)
                throw new InvalidOperationException("DES engine not initialised");

            Check.DataLength(inBuf, inOff, BLOCK_SIZE, "input buffer too short");
            Check.OutputLength(outBuf, outOff, BLOCK_SIZE, "output buffer too short");

            X[0] = Pack.BE_To_UInt32(inBuf, inOff);
            X[1] = Pack.BE_To_UInt32(inBuf, inOff + 4);
            X[2] = Pack.BE_To_UInt32(inBuf, inOff + 8);
            X[3] = Pack.BE_To_UInt32(inBuf, inOff + 12);

            int i;

            for (i = 0; i < 32; i += 4)
            {
                X[0] = F0(X, rk[i]);
                X[1] = F1(X, rk[i + 1]);
                X[2] = F2(X, rk[i + 2]);
                X[3] = F3(X, rk[i + 3]);
            }
            R(X, 0);

            Pack.UInt32_To_BE(X[0], outBuf, outOff);
            Pack.UInt32_To_BE(X[1], outBuf, outOff + 4);
            Pack.UInt32_To_BE(X[2], outBuf, outOff + 8);
            Pack.UInt32_To_BE(X[3], outBuf, outOff + 12);

            return 16;
        }

        public void Reset()
        {
           
        }
    }
}
