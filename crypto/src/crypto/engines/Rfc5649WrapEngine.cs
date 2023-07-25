using System;

using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.Crypto.Utilities;
using Org.BouncyCastle.Utilities;

namespace Org.BouncyCastle.Crypto.Engines
{
    /// <summary>An implementation of the AES Key Wrap with Padding specification as described in RFC 5649.</summary>
    /// <remarks>
    /// For further details see: Housley, R. and M. Dworkin, "Advanced Encryption Standard (AES) Key Wrap with Padding Algorithm",
    /// RFC 5649, DOI 10.17487/RFC5649, September 2009, &lt;https://www.rfc-editor.org/info/rfc5649&gt;, and
    /// http://csrc.nist.gov/encryption/kms/key-wrap.pdf.
    /// </remarks>
    public class Rfc5649WrapEngine
        : IWrapper
    {
        // The AIV as defined in the RFC
        private static readonly byte[] DefaultIV = { 0xa6, 0x59, 0x59, 0xa6 };

        private readonly IBlockCipher m_engine;
        private readonly byte[] m_preIV = new byte[4];

        private KeyParameter m_key = null;
        private bool m_forWrapping = true;

        public Rfc5649WrapEngine(IBlockCipher engine)
        {
            m_engine = engine;
        }

        public virtual string AlgorithmName => m_engine.AlgorithmName;

        public virtual void Init(bool forWrapping, ICipherParameters parameters)
        {
            m_forWrapping = forWrapping;

            if (parameters is ParametersWithRandom withRandom)
            {
                parameters = withRandom.Parameters;
            }

            if (parameters is KeyParameter keyParameter)
            {
                m_key = keyParameter;
                Array.Copy(DefaultIV, 0, m_preIV, 0, 4);
            }
            else if (parameters is ParametersWithIV withIV)
            {
                byte[] iv = withIV.GetIV();
                if (iv.Length != 4)
                    throw new ArgumentException("IV length not equal to 4", nameof(parameters));

                m_key = (KeyParameter)withIV.Parameters;
                Array.Copy(iv, 0, m_preIV, 0, 4);
            }
            else
            {
                // TODO Throw an exception for bad parameters?
            }
        }

        public virtual byte[] Wrap(byte[] input, int inOff, int length)
        {
            if (!m_forWrapping)
                throw new InvalidOperationException("not set for wrapping");

            byte[] iv = new byte[8];

            // copy in the fixed portion of the AIV
            Array.Copy(m_preIV, 0, iv, 0, 4);
            // copy in the MLI (size of key to be wrapped) after the AIV
            Pack.UInt32_To_BE((uint)length, iv, 4);

            // get the relevant plaintext to be wrapped
            byte[] relevantPlaintext = new byte[length];
            Array.Copy(input, inOff, relevantPlaintext, 0, length);
            byte[] paddedPlaintext = PadPlaintext(relevantPlaintext);

            if (paddedPlaintext.Length == 8)
            {
                // if the padded plaintext contains exactly 8 octets,
                // then prepend iv and encrypt using AES in ECB mode.

                // prepend the IV to the plaintext
                byte[] paddedPlainTextWithIV = new byte[paddedPlaintext.Length + iv.Length];
                Array.Copy(iv, 0, paddedPlainTextWithIV, 0, iv.Length);
                Array.Copy(paddedPlaintext, 0, paddedPlainTextWithIV, iv.Length, paddedPlaintext.Length);

                m_engine.Init(true, m_key);
                for (int i = 0, blockSize = m_engine.GetBlockSize(); i < paddedPlainTextWithIV.Length; i += blockSize)
                {
                    m_engine.ProcessBlock(paddedPlainTextWithIV, i, paddedPlainTextWithIV, i);
                }

                return paddedPlainTextWithIV;
            }
            else
            {
                // otherwise, apply the RFC 3394 wrap to
                // the padded plaintext with the new IV
                Rfc3394WrapEngine wrapper = new Rfc3394WrapEngine(m_engine);
                ParametersWithIV paramsWithIV = new ParametersWithIV(m_key, iv);
                wrapper.Init(true, paramsWithIV);
                return wrapper.Wrap(paddedPlaintext, 0, paddedPlaintext.Length);
            }
        }

        public virtual byte[] Unwrap(byte[] input, int inOff, int length)
        {
            if (m_forWrapping)
                throw new InvalidOperationException("not set for unwrapping");

            int n = length / 8;

            if ((n * 8) != length)
                throw new InvalidCipherTextException("unwrap data must be a multiple of 8 bytes");

            if (n <= 1)
                throw new InvalidCipherTextException("unwrap data must be at least 16 bytes");

            byte[] relevantCiphertext = new byte[length];
            Array.Copy(input, inOff, relevantCiphertext, 0, length);
            byte[] decrypted = new byte[length];
            byte[] paddedPlaintext;

            byte[] extractedAIV = new byte[8];

            if (n == 2)
            {
                // When there are exactly two 64-bit blocks of ciphertext,
                // they are decrypted as a single block using AES in ECB.
                m_engine.Init(false, m_key);
                for (int i = 0, blockSize = m_engine.GetBlockSize(); i < relevantCiphertext.Length; i += blockSize)
                {
                    m_engine.ProcessBlock(relevantCiphertext, i, decrypted, i);
                }

                // extract the AIV
                Array.Copy(decrypted, 0, extractedAIV, 0, 8);
                paddedPlaintext = new byte[decrypted.Length - 8];
                Array.Copy(decrypted, 8, paddedPlaintext, 0, paddedPlaintext.Length);
            }
            else
            {
                // Otherwise, unwrap as per RFC 3394 but don't check IV the same way
                decrypted = Rfc3394UnwrapNoIvCheck(input, inOff, length, extractedAIV);
                paddedPlaintext = decrypted;
            }

            // Decompose the extracted AIV to the fixed portion and the MLI
            byte[] extractedHighOrderAIV = new byte[4];
            Array.Copy(extractedAIV, 0, extractedHighOrderAIV, 0, 4);
            int mli = (int)Pack.BE_To_UInt32(extractedAIV, 4);

            // Even if a check fails we still continue and check everything 
            // else in order to avoid certain timing based side-channel attacks.

            // Check the fixed portion of the AIV
            bool isValid = Arrays.FixedTimeEquals(extractedHighOrderAIV, m_preIV);

            // Check the MLI against the actual length
            int upperBound = paddedPlaintext.Length;
            int lowerBound = upperBound - 8;
            if (mli <= lowerBound)
            {
                isValid = false;
            }
            if (mli > upperBound)
            {
                isValid = false;
            }

            // Check the number of padding zeros
            int expectedZeros = upperBound - mli;
            if (expectedZeros >= 8 || expectedZeros < 0)
            {
                // We have to pick a "typical" amount of padding to avoid timing attacks.
                isValid = false;
                expectedZeros = 4;
            }

            byte[] zeros = new byte[expectedZeros];
            byte[] pad = new byte[expectedZeros];
            Array.Copy(paddedPlaintext, paddedPlaintext.Length - expectedZeros, pad, 0, expectedZeros);
            if (!Arrays.FixedTimeEquals(pad, zeros))
            {
                isValid = false;
            }

            if (!isValid)
                throw new InvalidCipherTextException("checksum failed");

            // Extract the plaintext from the padded plaintext
            byte[] plaintext = new byte[mli];
            Array.Copy(paddedPlaintext, 0, plaintext, 0, plaintext.Length);

            return plaintext;
        }

        /**
         * Performs steps 1 and 2 of the unwrap process defined in RFC 3394.
         * This code is duplicated from RFC3394WrapEngine because that class
         * will throw an error during unwrap because the IV won't match up.
         *
         * @param in
         * @param inOff
         * @param inLen
         * @return Unwrapped data.
         */
        private byte[] Rfc3394UnwrapNoIvCheck(byte[] input, int inOff, int inLen, byte[] extractedAIV)
        {
            byte[] block = new byte[inLen - 8];
            byte[] buf = new byte[16];

            Array.Copy(input, inOff, buf, 0, 8);
            Array.Copy(input, inOff + 8, block, 0, inLen - 8);

            m_engine.Init(false, m_key);

            int n = inLen / 8;
            n = n - 1;

            for (int j = 5; j >= 0; j--)
            {
                for (int i = n; i >= 1; i--)
                {
                    Array.Copy(block, 8 * (i - 1), buf, 8, 8);

                    uint t = (uint)(n * j + i);
                    for (int k = 1; t != 0U; k++)
                    {
                        buf[8 - k] ^= (byte)t;
                        t >>= 8;
                    }

                    m_engine.ProcessBlock(buf, 0, buf, 0);

                    Array.Copy(buf, 8, block, 8 * (i - 1), 8);
                }
            }

            Array.Copy(buf, 0, extractedAIV, 0, 8);

            return block;
        }

        /**
         * Pads the plaintext (i.e., the key to be wrapped)
         * as per section 4.1 of RFC 5649.
         *
         * @param plaintext The key being wrapped.
         * @return The padded key.
         */
        private static byte[] PadPlaintext(byte[] plaintext)
        {
            int plaintextLength = plaintext.Length;
            int numOfZerosToAppend = (8 - (plaintextLength % 8)) % 8;
            byte[] paddedPlaintext = new byte[plaintextLength + numOfZerosToAppend];
            Array.Copy(plaintext, 0, paddedPlaintext, 0, plaintextLength);
            if (numOfZerosToAppend != 0)
            {
                // plaintext (i.e., key to be wrapped) does not have
                // a multiple of 8 octet blocks so it must be padded
                byte[] zeros = new byte[numOfZerosToAppend];
                Array.Copy(zeros, 0, paddedPlaintext, plaintextLength, numOfZerosToAppend);
            }
            return paddedPlaintext;
        }
    }
}
