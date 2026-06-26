using System;

using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.Utilities;

namespace Org.BouncyCastle.Crypto.Engines
{
    /// <summary>
    /// An implementation of RC2 as described in RFC 2268 "A Description of the RC2(r) Encryption Algorithm" R. Rivest.
    /// </summary>
    public class RC2Engine
        : IBlockCipher
    {
        // The values used for key expansion (based on the digits of PI)
        private static readonly byte[] PiTable =
        {
            0xd9, 0x78, 0xf9, 0xc4, 0x19, 0xdd, 0xb5, 0xed, 0x28, 0xe9, 0xfd, 0x79, 0x4a, 0xa0, 0xd8, 0x9d,
            0xc6, 0x7e, 0x37, 0x83, 0x2b, 0x76, 0x53, 0x8e, 0x62, 0x4c, 0x64, 0x88, 0x44, 0x8b, 0xfb, 0xa2,
            0x17, 0x9a, 0x59, 0xf5, 0x87, 0xb3, 0x4f, 0x13, 0x61, 0x45, 0x6d, 0x8d, 0x09, 0x81, 0x7d, 0x32,
            0xbd, 0x8f, 0x40, 0xeb, 0x86, 0xb7, 0x7b, 0x0b, 0xf0, 0x95, 0x21, 0x22, 0x5c, 0x6b, 0x4e, 0x82,
            0x54, 0xd6, 0x65, 0x93, 0xce, 0x60, 0xb2, 0x1c, 0x73, 0x56, 0xc0, 0x14, 0xa7, 0x8c, 0xf1, 0xdc,
            0x12, 0x75, 0xca, 0x1f, 0x3b, 0xbe, 0xe4, 0xd1, 0x42, 0x3d, 0xd4, 0x30, 0xa3, 0x3c, 0xb6, 0x26,
            0x6f, 0xbf, 0x0e, 0xda, 0x46, 0x69, 0x07, 0x57, 0x27, 0xf2, 0x1d, 0x9b, 0xbc, 0x94, 0x43, 0x03,
            0xf8, 0x11, 0xc7, 0xf6, 0x90, 0xef, 0x3e, 0xe7, 0x06, 0xc3, 0xd5, 0x2f, 0xc8, 0x66, 0x1e, 0xd7,
            0x08, 0xe8, 0xea, 0xde, 0x80, 0x52, 0xee, 0xf7, 0x84, 0xaa, 0x72, 0xac, 0x35, 0x4d, 0x6a, 0x2a,
            0x96, 0x1a, 0xd2, 0x71, 0x5a, 0x15, 0x49, 0x74, 0x4b, 0x9f, 0xd0, 0x5e, 0x04, 0x18, 0xa4, 0xec,
            0xc2, 0xe0, 0x41, 0x6e, 0x0f, 0x51, 0xcb, 0xcc, 0x24, 0x91, 0xaf, 0x50, 0xa1, 0xf4, 0x70, 0x39,
            0x99, 0x7c, 0x3a, 0x85, 0x23, 0xb8, 0xb4, 0x7a, 0xfc, 0x02, 0x36, 0x5b, 0x25, 0x55, 0x97, 0x31,
            0x2d, 0x5d, 0xfa, 0x98, 0xe3, 0x8a, 0x92, 0xae, 0x05, 0xdf, 0x29, 0x10, 0x67, 0x6c, 0xba, 0xc9,
            0xd3, 0x00, 0xe6, 0xcf, 0xe1, 0x9e, 0xa8, 0x2c, 0x63, 0x16, 0x01, 0x3f, 0x58, 0xe2, 0x89, 0xa9,
            0x0d, 0x38, 0x34, 0x1b, 0xab, 0x33, 0xff, 0xb0, 0xbb, 0x48, 0x0c, 0x5f, 0xb9, 0xb1, 0xcd, 0x2e,
            0xc5, 0xf3, 0xdb, 0x47, 0xe5, 0xa5, 0x9c, 0x77, 0x0a, 0xa6, 0x20, 0x68, 0xfe, 0x7f, 0xc1, 0xad,
        };

        private const int BLOCK_SIZE = 8;

        private int[] workingKey;
        private bool encrypting;

        public virtual string AlgorithmName => "RC2";

        public virtual void Init(bool forEncryption, ICipherParameters parameters)
        {
            this.encrypting = forEncryption;

            if (parameters is RC2Parameters rc2Parameters)
            {
                workingKey = GenerateWorkingKey(rc2Parameters.GetKey(), rc2Parameters.EffectiveKeyBits);
            }
            else if (parameters is KeyParameter keyParameter)
            {
                byte[] key = keyParameter.GetKey();
                workingKey = GenerateWorkingKey(key, key.Length * 8);
            }
            else
            {
                throw new ArgumentException("invalid parameter passed to RC2 init - " + Platform.GetTypeName(parameters));
            }
        }

        public virtual int GetBlockSize() => BLOCK_SIZE;

        public virtual int ProcessBlock(byte[] input, int inOff, byte[] output, int outOff)
        {
            if (workingKey == null)
                throw new InvalidOperationException("RC2 engine not initialised");

            Check.DataLength(input, inOff, BLOCK_SIZE, "input buffer too short");
            Check.OutputLength(output, outOff, BLOCK_SIZE, "output buffer too short");

#if NETCOREAPP2_1_OR_GREATER || NETSTANDARD2_1_OR_GREATER
            if (encrypting)
            {
                EncryptBlock(input.AsSpan(inOff), output.AsSpan(outOff));
            }
            else
            {
                DecryptBlock(input.AsSpan(inOff), output.AsSpan(outOff));
            }
#else
            if (encrypting)
            {
                EncryptBlock(input, inOff, output, outOff);
            }
            else
            {
                DecryptBlock(input, inOff, output, outOff);
            }
#endif

            return BLOCK_SIZE;
        }

#if NETCOREAPP2_1_OR_GREATER || NETSTANDARD2_1_OR_GREATER
        public virtual int ProcessBlock(ReadOnlySpan<byte> input, Span<byte> output)
        {
            if (workingKey == null)
                throw new InvalidOperationException("RC2 engine not initialised");

            Check.DataLength(input, BLOCK_SIZE, "input buffer too short");
            Check.OutputLength(output, BLOCK_SIZE, "output buffer too short");

            if (encrypting)
            {
                EncryptBlock(input, output);
            }
            else
            {
                DecryptBlock(input, output);
            }

            return BLOCK_SIZE;
        }
#endif

#if NETCOREAPP2_1_OR_GREATER || NETSTANDARD2_1_OR_GREATER
        private void EncryptBlock(ReadOnlySpan<byte> input, Span<byte> output)
        {
            int x76, x54, x32, x10;

            x76 = ((input[7] & 0xff) << 8) + (input[6] & 0xff);
            x54 = ((input[5] & 0xff) << 8) + (input[4] & 0xff);
            x32 = ((input[3] & 0xff) << 8) + (input[2] & 0xff);
            x10 = ((input[1] & 0xff) << 8) + (input[0] & 0xff);

            for (int i = 0; i <= 16; i += 4)
            {
                x10 = RotateWordLeft(x10 + (x32 & ~x76) + (x54 & x76) + workingKey[i], 1);
                x32 = RotateWordLeft(x32 + (x54 & ~x10) + (x76 & x10) + workingKey[i + 1], 2);
                x54 = RotateWordLeft(x54 + (x76 & ~x32) + (x10 & x32) + workingKey[i + 2], 3);
                x76 = RotateWordLeft(x76 + (x10 & ~x54) + (x32 & x54) + workingKey[i + 3], 5);
            }

            x10 += workingKey[x76 & 63];
            x32 += workingKey[x10 & 63];
            x54 += workingKey[x32 & 63];
            x76 += workingKey[x54 & 63];

            for (int i = 20; i <= 40; i += 4)
            {
                x10 = RotateWordLeft(x10 + (x32 & ~x76) + (x54 & x76) + workingKey[i], 1);
                x32 = RotateWordLeft(x32 + (x54 & ~x10) + (x76 & x10) + workingKey[i + 1], 2);
                x54 = RotateWordLeft(x54 + (x76 & ~x32) + (x10 & x32) + workingKey[i + 2], 3);
                x76 = RotateWordLeft(x76 + (x10 & ~x54) + (x32 & x54) + workingKey[i + 3], 5);
            }

            x10 += workingKey[x76 & 63];
            x32 += workingKey[x10 & 63];
            x54 += workingKey[x32 & 63];
            x76 += workingKey[x54 & 63];

            for (int i = 44; i < 64; i += 4)
            {
                x10 = RotateWordLeft(x10 + (x32 & ~x76) + (x54 & x76) + workingKey[i], 1);
                x32 = RotateWordLeft(x32 + (x54 & ~x10) + (x76 & x10) + workingKey[i + 1], 2);
                x54 = RotateWordLeft(x54 + (x76 & ~x32) + (x10 & x32) + workingKey[i + 2], 3);
                x76 = RotateWordLeft(x76 + (x10 & ~x54) + (x32 & x54) + workingKey[i + 3], 5);
            }

            output[0] = (byte)x10;
            output[1] = (byte)(x10 >> 8);
            output[2] = (byte)x32;
            output[3] = (byte)(x32 >> 8);
            output[4] = (byte)x54;
            output[5] = (byte)(x54 >> 8);
            output[6] = (byte)x76;
            output[7] = (byte)(x76 >> 8);
        }

        private void DecryptBlock(ReadOnlySpan<byte> input, Span<byte> output)
        {
            int x76, x54, x32, x10;

            x76 = ((input[7] & 0xff) << 8) + (input[6] & 0xff);
            x54 = ((input[5] & 0xff) << 8) + (input[4] & 0xff);
            x32 = ((input[3] & 0xff) << 8) + (input[2] & 0xff);
            x10 = ((input[1] & 0xff) << 8) + (input[0] & 0xff);

            for (int i = 60; i >= 44; i -= 4)
            {
                x76 = RotateWordLeft(x76, 11) - ((x10 & ~x54) + (x32 & x54) + workingKey[i + 3]);
                x54 = RotateWordLeft(x54, 13) - ((x76 & ~x32) + (x10 & x32) + workingKey[i + 2]);
                x32 = RotateWordLeft(x32, 14) - ((x54 & ~x10) + (x76 & x10) + workingKey[i + 1]);
                x10 = RotateWordLeft(x10, 15) - ((x32 & ~x76) + (x54 & x76) + workingKey[i]);
            }

            x76 -= workingKey[x54 & 63];
            x54 -= workingKey[x32 & 63];
            x32 -= workingKey[x10 & 63];
            x10 -= workingKey[x76 & 63];

            for (int i = 40; i >= 20; i -= 4)
            {
                x76 = RotateWordLeft(x76, 11) - ((x10 & ~x54) + (x32 & x54) + workingKey[i + 3]);
                x54 = RotateWordLeft(x54, 13) - ((x76 & ~x32) + (x10 & x32) + workingKey[i + 2]);
                x32 = RotateWordLeft(x32, 14) - ((x54 & ~x10) + (x76 & x10) + workingKey[i + 1]);
                x10 = RotateWordLeft(x10, 15) - ((x32 & ~x76) + (x54 & x76) + workingKey[i]);
            }

            x76 -= workingKey[x54 & 63];
            x54 -= workingKey[x32 & 63];
            x32 -= workingKey[x10 & 63];
            x10 -= workingKey[x76 & 63];

            for (int i = 16; i >= 0; i -= 4)
            {
                x76 = RotateWordLeft(x76, 11) - ((x10 & ~x54) + (x32 & x54) + workingKey[i + 3]);
                x54 = RotateWordLeft(x54, 13) - ((x76 & ~x32) + (x10 & x32) + workingKey[i + 2]);
                x32 = RotateWordLeft(x32, 14) - ((x54 & ~x10) + (x76 & x10) + workingKey[i + 1]);
                x10 = RotateWordLeft(x10, 15) - ((x32 & ~x76) + (x54 & x76) + workingKey[i]);
            }

            output[0] = (byte)x10;
            output[1] = (byte)(x10 >> 8);
            output[2] = (byte)x32;
            output[3] = (byte)(x32 >> 8);
            output[4] = (byte)x54;
            output[5] = (byte)(x54 >> 8);
            output[6] = (byte)x76;
            output[7] = (byte)(x76 >> 8);
        }
#else
        private void EncryptBlock(byte[] input, int inOff, byte[] outBytes, int outOff)
        {
            int x76, x54, x32, x10;

            x76 = ((input[inOff + 7] & 0xff) << 8) + (input[inOff + 6] & 0xff);
            x54 = ((input[inOff + 5] & 0xff) << 8) + (input[inOff + 4] & 0xff);
            x32 = ((input[inOff + 3] & 0xff) << 8) + (input[inOff + 2] & 0xff);
            x10 = ((input[inOff + 1] & 0xff) << 8) + (input[inOff + 0] & 0xff);

            for (int i = 0; i <= 16; i += 4)
            {
                x10 = RotateWordLeft(x10 + (x32 & ~x76) + (x54 & x76) + workingKey[i  ], 1);
                x32 = RotateWordLeft(x32 + (x54 & ~x10) + (x76 & x10) + workingKey[i+1], 2);
                x54 = RotateWordLeft(x54 + (x76 & ~x32) + (x10 & x32) + workingKey[i+2], 3);
                x76 = RotateWordLeft(x76 + (x10 & ~x54) + (x32 & x54) + workingKey[i+3], 5);
            }

            x10 += workingKey[x76 & 63];
            x32 += workingKey[x10 & 63];
            x54 += workingKey[x32 & 63];
            x76 += workingKey[x54 & 63];

            for (int i = 20; i <= 40; i += 4)
            {
                x10 = RotateWordLeft(x10 + (x32 & ~x76) + (x54 & x76) + workingKey[i  ], 1);
                x32 = RotateWordLeft(x32 + (x54 & ~x10) + (x76 & x10) + workingKey[i+1], 2);
                x54 = RotateWordLeft(x54 + (x76 & ~x32) + (x10 & x32) + workingKey[i+2], 3);
                x76 = RotateWordLeft(x76 + (x10 & ~x54) + (x32 & x54) + workingKey[i+3], 5);
            }

            x10 += workingKey[x76 & 63];
            x32 += workingKey[x10 & 63];
            x54 += workingKey[x32 & 63];
            x76 += workingKey[x54 & 63];

            for (int i = 44; i < 64; i += 4)
            {
                x10 = RotateWordLeft(x10 + (x32 & ~x76) + (x54 & x76) + workingKey[i  ], 1);
                x32 = RotateWordLeft(x32 + (x54 & ~x10) + (x76 & x10) + workingKey[i+1], 2);
                x54 = RotateWordLeft(x54 + (x76 & ~x32) + (x10 & x32) + workingKey[i+2], 3);
                x76 = RotateWordLeft(x76 + (x10 & ~x54) + (x32 & x54) + workingKey[i+3], 5);
            }

            outBytes[outOff + 0] = (byte)x10;
            outBytes[outOff + 1] = (byte)(x10 >> 8);
            outBytes[outOff + 2] = (byte)x32;
            outBytes[outOff + 3] = (byte)(x32 >> 8);
            outBytes[outOff + 4] = (byte)x54;
            outBytes[outOff + 5] = (byte)(x54 >> 8);
            outBytes[outOff + 6] = (byte)x76;
            outBytes[outOff + 7] = (byte)(x76 >> 8);
        }

        private void DecryptBlock(byte[] input, int inOff, byte[] outBytes, int outOff)
        {
            int x76, x54, x32, x10;

            x76 = ((input[inOff + 7] & 0xff) << 8) + (input[inOff + 6] & 0xff);
            x54 = ((input[inOff + 5] & 0xff) << 8) + (input[inOff + 4] & 0xff);
            x32 = ((input[inOff + 3] & 0xff) << 8) + (input[inOff + 2] & 0xff);
            x10 = ((input[inOff + 1] & 0xff) << 8) + (input[inOff + 0] & 0xff);

            for (int i = 60; i >= 44; i -= 4)
            {
                x76 = RotateWordLeft(x76, 11) - ((x10 & ~x54) + (x32 & x54) + workingKey[i+3]);
                x54 = RotateWordLeft(x54, 13) - ((x76 & ~x32) + (x10 & x32) + workingKey[i+2]);
                x32 = RotateWordLeft(x32, 14) - ((x54 & ~x10) + (x76 & x10) + workingKey[i+1]);
                x10 = RotateWordLeft(x10, 15) - ((x32 & ~x76) + (x54 & x76) + workingKey[i  ]);
            }

            x76 -= workingKey[x54 & 63];
            x54 -= workingKey[x32 & 63];
            x32 -= workingKey[x10 & 63];
            x10 -= workingKey[x76 & 63];

            for (int i = 40; i >= 20; i -= 4)
            {
                x76 = RotateWordLeft(x76, 11) - ((x10 & ~x54) + (x32 & x54) + workingKey[i+3]);
                x54 = RotateWordLeft(x54, 13) - ((x76 & ~x32) + (x10 & x32) + workingKey[i+2]);
                x32 = RotateWordLeft(x32, 14) - ((x54 & ~x10) + (x76 & x10) + workingKey[i+1]);
                x10 = RotateWordLeft(x10, 15) - ((x32 & ~x76) + (x54 & x76) + workingKey[i  ]);
            }

            x76 -= workingKey[x54 & 63];
            x54 -= workingKey[x32 & 63];
            x32 -= workingKey[x10 & 63];
            x10 -= workingKey[x76 & 63];

            for (int i = 16; i >= 0; i -= 4)
            {
                x76 = RotateWordLeft(x76, 11) - ((x10 & ~x54) + (x32 & x54) + workingKey[i+3]);
                x54 = RotateWordLeft(x54, 13) - ((x76 & ~x32) + (x10 & x32) + workingKey[i+2]);
                x32 = RotateWordLeft(x32, 14) - ((x54 & ~x10) + (x76 & x10) + workingKey[i+1]);
                x10 = RotateWordLeft(x10, 15) - ((x32 & ~x76) + (x54 & x76) + workingKey[i  ]);
            }

            outBytes[outOff + 0] = (byte)x10;
            outBytes[outOff + 1] = (byte)(x10 >> 8);
            outBytes[outOff + 2] = (byte)x32;
            outBytes[outOff + 3] = (byte)(x32 >> 8);
            outBytes[outOff + 4] = (byte)x54;
            outBytes[outOff + 5] = (byte)(x54 >> 8);
            outBytes[outOff + 6] = (byte)x76;
            outBytes[outOff + 7] = (byte)(x76 >> 8);
        }
#endif

        private static int[] GenerateWorkingKey(byte[] key, int bits)
        {
            int x;
            int[] xKey = new int[128];

            for (int i = 0; i != key.Length; i++)
            {
                xKey[i] = key[i] & 0xff;
            }

            // Phase 1: Expand input key to 128 bytes
            int len = key.Length;

            if (len < 128)
            {
                int index = 0;

                x = xKey[len - 1];

                do
                {
                    x = PiTable[(x + xKey[index++]) & 255] & 0xff;
                    xKey[len++] = x;
                }
                while (len < 128);
            }

            // Phase 2 - reduce effective key size to "bits"
            len = (bits + 7) >> 3;
            x = PiTable[xKey[128 - len] & (255 >> (7 & -bits))] & 0xff;
            xKey[128 - len] = x;

            for (int i = 128 - len - 1; i >= 0; i--)
            {
                x = PiTable[x ^ xKey[i + len]] & 0xff;
                xKey[i] = x;
            }

            // Phase 3 - copy to newKey in little-endian order
            int[] newKey = new int[64];

            for (int i = 0; i != newKey.Length; i++)
            {
                newKey[i] = (xKey[2 * i] + (xKey[2 * i + 1] << 8));
            }

            return newKey;
        }

        /// <summary>Return the result of rotating the 16 bit number in x left by y.</summary>
        private static int RotateWordLeft(int x, int y) => (int)Shorts.RotateLeft((ushort)x, y);
    }
}
