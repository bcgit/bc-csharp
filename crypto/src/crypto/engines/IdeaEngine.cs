using System;

using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.Crypto.Utilities;
using Org.BouncyCastle.Utilities;

namespace Org.BouncyCastle.Crypto.Engines
{
    /**
     * A class that provides a basic International Data Encryption Algorithm (IDEA) engine.
     * <p>
     * This implementation is based on the "HOWTO: INTERNATIONAL DATA ENCRYPTION ALGORITHM"
     * implementation summary by Fauzan Mirza (F.U.Mirza@sheffield.ac.uk). (barring 1 typo at the
     * end of the MulInv function!).
     * </p>
     * <p>
     * It can be found at ftp://ftp.funet.fi/pub/crypt/cryptography/symmetric/idea/
     * </p>
     * <p>
     * Note: This algorithm was patented in the USA, Japan and Europe. These patents expired in 2011/2012.
     * </p>
     */
    public class IdeaEngine
        : IBlockCipher
    {
        private const int Base = 0x10001;
        private const int BlockSize = 8;
        private const int Mask = 0xFFFF;

        private int[] m_workingKey;

        /**
         * standard constructor.
         */
        public IdeaEngine()
        {
        }

        /**
         * initialise an IDEA cipher.
         *
         * @param forEncryption whether or not we are for encryption.
         * @param parameters the parameters required to set up the cipher.
         * @exception ArgumentException if the parameters argument is
         * inappropriate.
         */
        public virtual void Init(bool forEncryption, ICipherParameters parameters)
        {
            if (!(parameters is KeyParameter keyParameter))
                throw new ArgumentException("invalid parameter passed to IDEA Init - " + Platform.GetTypeName(parameters));

            m_workingKey = GenerateWorkingKey(forEncryption, keyParameter.GetKey());
        }

        public virtual string AlgorithmName => "IDEA";

        public virtual int GetBlockSize() => BlockSize;

        public virtual int ProcessBlock(byte[] input, int inOff, byte[] output, int outOff)
        {
            if (m_workingKey == null)
                throw new InvalidOperationException("IDEA engine not initialised");

            Check.DataLength(input, inOff, BlockSize, "input buffer too short");
            Check.OutputLength(output, outOff, BlockSize, "output buffer too short");

#if NETCOREAPP2_1_OR_GREATER || NETSTANDARD2_1_OR_GREATER
            IdeaFunc(m_workingKey, input.AsSpan(inOff), output.AsSpan(outOff));
#else
            IdeaFunc(m_workingKey, input, inOff, output, outOff);
#endif
            return BlockSize;
        }

#if NETCOREAPP2_1_OR_GREATER || NETSTANDARD2_1_OR_GREATER
        public virtual int ProcessBlock(ReadOnlySpan<byte> input, Span<byte> output)
        {
            if (m_workingKey == null)
                throw new InvalidOperationException("IDEA engine not initialised");

            Check.DataLength(input, BlockSize, "input buffer too short");
            Check.OutputLength(output, BlockSize, "output buffer too short");

            IdeaFunc(m_workingKey, input, output);
            return BlockSize;
        }
#endif

        /**
         * return x = x * y where the multiplication is done modulo
         * 65537 (0x10001) (as defined in the IDEA specification) and
         * a zero input is taken to be 65536 (0x10000).
         *
         * @param x the x value
         * @param y the y value
         * @return x = x * y
         */
        private int Mul(int x, int y)
        {
            if (x == 0)
            {
                x = Base - y;
            }
            else if (y == 0)
            {
                x = Base - x;
            }
            else
            {
                int p = x * y;
                y = p & Mask;
                x = (int)((uint)p >> 16);
                x = y - x + ((y < x) ? 1 : 0);
            }
            return x & Mask;
        }

#if NETCOREAPP2_1_OR_GREATER || NETSTANDARD2_1_OR_GREATER
        private void IdeaFunc(int[] workingKey, ReadOnlySpan<byte> input, Span<byte> output)
        {
            int x0 = Pack.BE_To_UInt16(input);
            int x1 = Pack.BE_To_UInt16(input[2..]);
            int x2 = Pack.BE_To_UInt16(input[4..]);
            int x3 = Pack.BE_To_UInt16(input[6..]);
            int keyOff = 0, t0, t1;
            for (int round = 0; round < 8; round++)
            {
                x0 = Mul(x0, workingKey[keyOff++]);
                x1 += workingKey[keyOff++];
                x1 &= Mask;
                x2 += workingKey[keyOff++];
                x2 &= Mask;
                x3 = Mul(x3, workingKey[keyOff++]);
                t0 = x1;
                t1 = x2;
                x2 ^= x0;
                x1 ^= x3;
                x2 = Mul(x2, workingKey[keyOff++]);
                x1 += x2;
                x1 &= Mask;
                x1 = Mul(x1, workingKey[keyOff++]);
                x2 += x1;
                x2 &= Mask;
                x0 ^= x1;
                x3 ^= x2;
                x1 ^= t1;
                x2 ^= t0;
            }
            Pack.UInt16_To_BE((ushort)Mul(x0, workingKey[keyOff++]), output);
            Pack.UInt16_To_BE((ushort)(x2 + workingKey[keyOff++]), output[2..]);  /* NB: Order */
            Pack.UInt16_To_BE((ushort)(x1 + workingKey[keyOff++]), output[4..]);
            Pack.UInt16_To_BE((ushort)Mul(x3, workingKey[keyOff]), output[6..]);
        }
#else
        private void IdeaFunc(int[] workingKey, byte[] input, int inOff, byte[] outBytes, int outOff)
        {
            int x0 = Pack.BE_To_UInt16(input, inOff);
            int x1 = Pack.BE_To_UInt16(input, inOff + 2);
            int x2 = Pack.BE_To_UInt16(input, inOff + 4);
            int x3 = Pack.BE_To_UInt16(input, inOff + 6);
            int keyOff = 0, t0, t1;
            for (int round = 0; round < 8; round++)
            {
                x0 = Mul(x0, workingKey[keyOff++]);
                x1 += workingKey[keyOff++];
                x1 &= Mask;
                x2 += workingKey[keyOff++];
                x2 &= Mask;
                x3 = Mul(x3, workingKey[keyOff++]);
                t0 = x1;
                t1 = x2;
                x2 ^= x0;
                x1 ^= x3;
                x2 = Mul(x2, workingKey[keyOff++]);
                x1 += x2;
                x1 &= Mask;
                x1 = Mul(x1, workingKey[keyOff++]);
                x2 += x1;
                x2 &= Mask;
                x0 ^= x1;
                x3 ^= x2;
                x1 ^= t1;
                x2 ^= t0;
            }
            Pack.UInt16_To_BE((ushort)Mul(x0, workingKey[keyOff++]), outBytes, outOff);
            Pack.UInt16_To_BE((ushort)(x2 + workingKey[keyOff++]), outBytes, outOff + 2);  /* NB: Order */
            Pack.UInt16_To_BE((ushort)(x1 + workingKey[keyOff++]), outBytes, outOff + 4);
            Pack.UInt16_To_BE((ushort)Mul(x3, workingKey[keyOff]), outBytes, outOff + 6);
        }
#endif

        /**
         * The following function is used to expand the user key to the encryption
         * subkey. The first 16 bytes are the user key, and the rest of the subkey
         * is calculated by rotating the previous 16 bytes by 25 bits to the left,
         * and so on until the subkey is completed.
         */
        private static int[] ExpandKey(byte[] uKey)
        {
            int[] key = new int[52];
            if (uKey.Length < 16)
            {
                byte[]  tmp = new byte[16];
                Array.Copy(uKey, 0, tmp, tmp.Length - uKey.Length, uKey.Length);
                uKey = tmp;
            }
            for (int i = 0; i < 8; i++)
            {
#if NETCOREAPP2_1_OR_GREATER || NETSTANDARD2_1_OR_GREATER
                key[i] = Pack.BE_To_UInt16(uKey.AsSpan(i * 2));
#else
                key[i] = Pack.BE_To_UInt16(uKey, i * 2);
#endif
            }
            for (int i = 8; i < 52; i++)
            {
                if ((i & 7) < 6)
                {
                    key[i] = ((key[i - 7] & 127) << 9 | key[i - 6] >> 7) & Mask;
                }
                else if ((i & 7) == 6)
                {
                    key[i] = ((key[i - 7] & 127) << 9 | key[i - 14] >> 7) & Mask;
                }
                else
                {
                    key[i] = ((key[i - 15] & 127) << 9 | key[i - 14] >> 7) & Mask;
                }
            }
            return key;
        }

        /**
         * This function computes multiplicative inverse using Euclid's Greatest
         * Common Divisor algorithm. Zero and one are self inverse.
         * <p>
         * i.e. x * MulInv(x) == 1 (modulo BASE)
         * </p>
         */
        private static int MulInv(int x)
        {
            int t0, t1, q, y;

            if (x < 2)
                return x;

            t0 = 1;
            t1 = Base / x;
            y  = Base % x;
            while (y != 1)
            {
                q = x / y;
                x = x % y;
                t0 = (t0 + (t1 * q)) & Mask;
                if (x == 1)
                    return t0;

                q = y / x;
                y = y % x;
                t1 = (t1 + (t0 * q)) & Mask;
            }
            return (1 - t1) & Mask;
        }

        /**
         * Return the additive inverse of x.
         * <p>
         * i.e. x + AddInv(x) == 0
         * </p>
         */
        private static int AddInv(int x) => (0 - x) & Mask;

        /**
         * The function to invert the encryption subkey to the decryption subkey.
         * It also involves the multiplicative inverse and the additive inverse functions.
         */
        private static int[] InvertKey(int[] inKey)
        {
            int[] key = new int[52];
            int inOff = 0, p = 52; // We work backwards

            int t1 = MulInv(inKey[inOff++]);
            int t2 = AddInv(inKey[inOff++]);
            int t3 = AddInv(inKey[inOff++]);
            int t4 = MulInv(inKey[inOff++]);
            key[--p] = t4;
            key[--p] = t3;
            key[--p] = t2;
            key[--p] = t1;

            for (int round = 1; round < 8; round++)
            {
                t1 = inKey[inOff++];
                t2 = inKey[inOff++];
                key[--p] = t2;
                key[--p] = t1;

                t1 = MulInv(inKey[inOff++]);
                t2 = AddInv(inKey[inOff++]);
                t3 = AddInv(inKey[inOff++]);
                t4 = MulInv(inKey[inOff++]);
                key[--p] = t4;
                key[--p] = t2; /* NB: Order */
                key[--p] = t3;
                key[--p] = t1;
            }
            t1 = inKey[inOff++];
            t2 = inKey[inOff++];
            key[--p] = t2;
            key[--p] = t1;

            t1 = MulInv(inKey[inOff++]);
            t2 = AddInv(inKey[inOff++]);
            t3 = AddInv(inKey[inOff++]);
            t4 = MulInv(inKey[inOff]);
            key[--p] = t4;
            key[--p] = t3;
            key[--p] = t2;
            key[--p] = t1;
            return key;
        }

        private static int[] GenerateWorkingKey(bool forEncryption, byte[] userKey)
        {
            int[] expanded = ExpandKey(userKey);
            return forEncryption ? expanded : InvertKey(expanded);
        }
    }
}
