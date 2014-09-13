using System;

using Org.BouncyCastle.Crypto.Generators;
using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.Crypto.Utilities;

namespace Org.BouncyCastle.Crypto.Macs
{

    /// <summary>
    /// Poly1305 message authentication code, designed by D. J. Bernstein.
    /// </summary>
    /// <remarks>
    /// Poly1305 computes a 128-bit (16 bytes) authenticator, using a 128 bit nonce and a 256 bit key
    /// consisting of a 128 bit key applied to an underlying cipher, and a 128 bit key (with 106
    /// effective key bits) used in the authenticator.
    /// 
    /// The polynomial calculation in this implementation is adapted from the public domain <a
    /// href="https://github.com/floodyberry/poly1305-donna">poly1305-donna-unrolled</a> C implementation
    /// by Andrew M (@floodyberry).
    /// </remarks>
    /// <seealso cref="Org.BouncyCastle.Crypto.Generators.Poly1305KeyGenerator"/>
    public class Poly1305
        : IMac
    {
        private const int BLOCK_SIZE = 16;

        private readonly IBlockCipher cipher;

        private readonly byte[] singleByte = new byte[1];

        // Initialised state

        /** Polynomial key */
        private uint r0, r1, r2, r3, r4;

        /** Precomputed 5 * r[1..4] */
        private uint s1, s2, s3, s4;

        /** Encrypted nonce */
        private uint k0, k1, k2, k3;

        // Accumulating state

        /** Current block of buffered input */
        private byte[] currentBlock = new byte[BLOCK_SIZE];

        /** Current offset in input buffer */
        private int currentBlockOffset = 0;

        /** Polynomial accumulator */
        private uint h0, h1, h2, h3, h4;

        /**
         * Constructs a Poly1305 MAC, where the key passed to init() will be used directly.
         */
        public Poly1305()
        {
            this.cipher = null;
        }

        /**
         * Constructs a Poly1305 MAC, using a 128 bit block cipher.
         */
        public Poly1305(IBlockCipher cipher)
        {
            if (cipher.GetBlockSize() != BLOCK_SIZE)
            {
                throw new ArgumentException("Poly1305 requires a 128 bit block cipher.");
            }
            this.cipher = cipher;
        }

        /// <summary>
        /// Initialises the Poly1305 MAC.
        /// </summary>
        /// <param name="parameters">a {@link ParametersWithIV} containing a 128 bit nonce and a {@link KeyParameter} with
        ///          a 256 bit key complying to the {@link Poly1305KeyGenerator Poly1305 key format}.</param>
        public void Init(ICipherParameters parameters)
        {
            byte[] nonce = null;

            if (cipher != null)
            {
                if (!(parameters is ParametersWithIV))
                    throw new ArgumentException("Poly1305 requires an IV when used with a block cipher.", "parameters");

                ParametersWithIV ivParams = (ParametersWithIV)parameters;
                nonce = ivParams.GetIV();
                parameters = ivParams.Parameters;
            }

            if (!(parameters is KeyParameter))
                throw new ArgumentException("Poly1305 requires a key.");

            KeyParameter keyParams = (KeyParameter)parameters;

            SetKey(keyParams.GetKey(), nonce);

            Reset();
        }

        private void SetKey(byte[] key, byte[] nonce)
        {
            if (cipher != null && (nonce == null || nonce.Length != BLOCK_SIZE))
                throw new ArgumentException("Poly1305 requires a 128 bit IV.");

            Poly1305KeyGenerator.CheckKey(key);

            // Extract r portion of key
            uint t0 = Pack.LE_To_UInt32(key, BLOCK_SIZE + 0);
            uint t1 = Pack.LE_To_UInt32(key, BLOCK_SIZE + 4);
            uint t2 = Pack.LE_To_UInt32(key, BLOCK_SIZE + 8);
            uint t3 = Pack.LE_To_UInt32(key, BLOCK_SIZE + 12);

            r0 = t0 & 0x3ffffff; t0 >>= 26; t0 |= t1 << 6;
            r1 = t0 & 0x3ffff03; t1 >>= 20; t1 |= t2 << 12;
            r2 = t1 & 0x3ffc0ff; t2 >>= 14; t2 |= t3 << 18;
            r3 = t2 & 0x3f03fff; t3 >>= 8;
            r4 = t3 & 0x00fffff;

            // Precompute multipliers
            s1 = r1 * 5;
            s2 = r2 * 5;
            s3 = r3 * 5;
            s4 = r4 * 5;

            byte[] kBytes;
            if (cipher == null)
            {
                kBytes = key;
            }
            else
            {
                // Compute encrypted nonce
                kBytes = new byte[BLOCK_SIZE];
                cipher.Init(true, new KeyParameter(key, 0, BLOCK_SIZE));
                cipher.ProcessBlock(nonce, 0, kBytes, 0);
            }

            k0 = Pack.LE_To_UInt32(kBytes, 0);
            k1 = Pack.LE_To_UInt32(kBytes, 4);
            k2 = Pack.LE_To_UInt32(kBytes, 8);
            k3 = Pack.LE_To_UInt32(kBytes, 12);
        }

        public string AlgorithmName
        {
            get { return cipher == null ? "Poly1305" : "Poly1305-" + cipher.AlgorithmName; }
        }

        public int GetMacSize()
        {
            return BLOCK_SIZE;
        }

        public void Update(byte input)
        {
            singleByte[0] = input;
            BlockUpdate(singleByte, 0, 1);
        }

        public void BlockUpdate(byte[] input, int inOff, int len)
        {
            int copied = 0;
            while (len > copied)
            {
                if (currentBlockOffset == BLOCK_SIZE)
                {
                    processBlock();
                    currentBlockOffset = 0;
                }

                int toCopy = System.Math.Min((len - copied), BLOCK_SIZE - currentBlockOffset);
                Array.Copy(input, copied + inOff, currentBlock, currentBlockOffset, toCopy);
                copied += toCopy;
                currentBlockOffset += toCopy;
            }

        }

        private void processBlock()
        {
            if (currentBlockOffset < BLOCK_SIZE)
            {
                currentBlock[currentBlockOffset] = 1;
                for (int i = currentBlockOffset + 1; i < BLOCK_SIZE; i++)
                {
                    currentBlock[i] = 0;
                }
            }

            ulong t0 = Pack.LE_To_UInt32(currentBlock, 0);
            ulong t1 = Pack.LE_To_UInt32(currentBlock, 4);
            ulong t2 = Pack.LE_To_UInt32(currentBlock, 8);
            ulong t3 = Pack.LE_To_UInt32(currentBlock, 12);

            h0 += (uint)(t0 & 0x3ffffffU);
            h1 += (uint)((((t1 << 32) | t0) >> 26) & 0x3ffffff);
            h2 += (uint)((((t2 << 32) | t1) >> 20) & 0x3ffffff);
            h3 += (uint)((((t3 << 32) | t2) >> 14) & 0x3ffffff);
            h4 += (uint)(t3 >> 8);

            if (currentBlockOffset == BLOCK_SIZE)
            {
                h4 += (1 << 24);
            }

            ulong tp0 = mul32x32_64(h0,r0) + mul32x32_64(h1,s4) + mul32x32_64(h2,s3) + mul32x32_64(h3,s2) + mul32x32_64(h4,s1);
            ulong tp1 = mul32x32_64(h0,r1) + mul32x32_64(h1,r0) + mul32x32_64(h2,s4) + mul32x32_64(h3,s3) + mul32x32_64(h4,s2);
            ulong tp2 = mul32x32_64(h0,r2) + mul32x32_64(h1,r1) + mul32x32_64(h2,r0) + mul32x32_64(h3,s4) + mul32x32_64(h4,s3);
            ulong tp3 = mul32x32_64(h0,r3) + mul32x32_64(h1,r2) + mul32x32_64(h2,r1) + mul32x32_64(h3,r0) + mul32x32_64(h4,s4);
            ulong tp4 = mul32x32_64(h0,r4) + mul32x32_64(h1,r3) + mul32x32_64(h2,r2) + mul32x32_64(h3,r1) + mul32x32_64(h4,r0);

            ulong b;
            h0 = (uint)tp0 & 0x3ffffff; b = (tp0 >> 26);
            tp1 += b; h1 = (uint)tp1 & 0x3ffffff; b = (tp1 >> 26);
            tp2 += b; h2 = (uint)tp2 & 0x3ffffff; b = (tp2 >> 26);
            tp3 += b; h3 = (uint)tp3 & 0x3ffffff; b = (tp3 >> 26);
            tp4 += b; h4 = (uint)tp4 & 0x3ffffff; b = (tp4 >> 26);
            h0 += (uint)(b * 5);
        }

        public int DoFinal(byte[] output, int outOff)
        {
            if (outOff + BLOCK_SIZE > output.Length)
            {
                throw new DataLengthException("Output buffer is too short.");
            }

            if (currentBlockOffset > 0)
            {
                // Process padded block
                processBlock();
            }

            ulong f0, f1, f2, f3;

            uint b = h0 >> 26;
            h0 = h0 & 0x3ffffff;
            h1 += b; b = h1 >> 26; h1 = h1 & 0x3ffffff;
            h2 += b; b = h2 >> 26; h2 = h2 & 0x3ffffff;
            h3 += b; b = h3 >> 26; h3 = h3 & 0x3ffffff;
            h4 += b; b = h4 >> 26; h4 = h4 & 0x3ffffff;
            h0 += b * 5;

            uint g0, g1, g2, g3, g4;
            g0 = h0 + 5; b = g0 >> 26; g0 &= 0x3ffffff;
            g1 = h1 + b; b = g1 >> 26; g1 &= 0x3ffffff;
            g2 = h2 + b; b = g2 >> 26; g2 &= 0x3ffffff;
            g3 = h3 + b; b = g3 >> 26; g3 &= 0x3ffffff;
            g4 = h4 + b - (1 << 26);

            b = (g4 >> 31) - 1;
            uint nb = ~b;
            h0 = (h0 & nb) | (g0 & b);
            h1 = (h1 & nb) | (g1 & b);
            h2 = (h2 & nb) | (g2 & b);
            h3 = (h3 & nb) | (g3 & b);
            h4 = (h4 & nb) | (g4 & b);

            f0 = ((h0      ) | (h1 << 26)) + (ulong)k0;
            f1 = ((h1 >> 6 ) | (h2 << 20)) + (ulong)k1;
            f2 = ((h2 >> 12) | (h3 << 14)) + (ulong)k2;
            f3 = ((h3 >> 18) | (h4 << 8 )) + (ulong)k3;

            Pack.UInt32_To_LE((uint)f0, output, outOff);
            f1 += (f0 >> 32);
            Pack.UInt32_To_LE((uint)f1, output, outOff + 4);
            f2 += (f1 >> 32);
            Pack.UInt32_To_LE((uint)f2, output, outOff + 8);
            f3 += (f2 >> 32);
            Pack.UInt32_To_LE((uint)f3, output, outOff + 12);

            Reset();
            return BLOCK_SIZE;
        }

        public void Reset()
        {
            currentBlockOffset = 0;

            h0 = h1 = h2 = h3 = h4 = 0;
        }

        private static ulong mul32x32_64(uint i1, uint i2)
        {
            return ((ulong)i1) * i2;
        }
    }
}
