using System;
using System.Threading;

using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.Security;
using Org.BouncyCastle.Utilities;

namespace Org.BouncyCastle.Crypto.Encodings
{
    /**
    * this does your basic Pkcs 1 v1.5 padding - whether or not you should be using this
    * depends on your application - see Pkcs1 Version 2 for details.
    */
    public class Pkcs1Encoding
        : IAsymmetricBlockCipher
    {
        /**
         * some providers fail to include the leading zero in PKCS1 encoded blocks. If you need to
         * work with one of these set the system property Org.BouncyCastle.Pkcs1.Strict to false.
         */
        public const string StrictLengthEnabledProperty = "Org.BouncyCastle.Pkcs1.Strict";

        private const int HeaderLength = 10;

        /**
         * The same effect can be achieved by setting the static property directly
         * <p>
         * The static property is checked during construction of the encoding object, it is set to
         * true by default.
         * </p>
         */
        public static bool StrictLengthEnabled
        {
            get { return Convert.ToBoolean(Interlocked.Read(ref m_strictLengthEnabled)); }
            set { Interlocked.Exchange(ref m_strictLengthEnabled, Convert.ToInt64(value)); }
        }

        private static long m_strictLengthEnabled = 0;

        static Pkcs1Encoding()
        {
            string strictProperty = Platform.GetEnvironmentVariable(StrictLengthEnabledProperty);
            bool strictLengthEnabled = strictProperty == null || Platform.EqualsIgnoreCase("true", strictProperty);

            m_strictLengthEnabled = Convert.ToInt64(strictLengthEnabled);
        }


        private SecureRandom random;
        private IAsymmetricBlockCipher engine;
        private bool forEncryption;
        private bool forPrivateKey;
        private bool useStrictLength;
        private int pLen = -1;
        private byte[] fallback = null;
        private byte[] blockBuffer = null;

        /**
         * Basic constructor.
         *
         * @param cipher
         */
        public Pkcs1Encoding(IAsymmetricBlockCipher cipher)
        {
            this.engine = cipher;
            this.useStrictLength = StrictLengthEnabled;
        }

        /**
         * Constructor for decryption with a fixed plaintext length.
         * 
         * @param cipher The cipher to use for cryptographic operation.
         * @param pLen Length of the expected plaintext.
         */
        public Pkcs1Encoding(IAsymmetricBlockCipher cipher, int pLen)
        {
            this.engine = cipher;
            this.useStrictLength = StrictLengthEnabled;
            this.pLen = pLen;
        }

        /**
         * Constructor for decryption with a fixed plaintext length and a fallback
         * value that is returned, if the padding is incorrect.
         * 
         * @param cipher
         *            The cipher to use for cryptographic operation.
         * @param fallback
         *            The fallback value, we don't to a arraycopy here.
         */
        public Pkcs1Encoding(IAsymmetricBlockCipher cipher, byte[] fallback)
        {
            this.engine = cipher;
            this.useStrictLength = StrictLengthEnabled;
            this.fallback = fallback;
            this.pLen = fallback.Length;
        }

        public string AlgorithmName => engine.AlgorithmName + "/PKCS1Padding";

        public IAsymmetricBlockCipher UnderlyingCipher => engine;

        public void Init(bool forEncryption, ICipherParameters parameters)
        {
            AsymmetricKeyParameter kParam;
            if (parameters is ParametersWithRandom withRandom)
            {
                kParam = (AsymmetricKeyParameter)withRandom.Parameters;
                this.random = withRandom.Random;
            }
            else
            {
                kParam = (AsymmetricKeyParameter)parameters;
                this.random = forEncryption && !kParam.IsPrivate ? CryptoServicesRegistrar.GetSecureRandom() : null;
            }

            engine.Init(forEncryption, parameters);

            this.forPrivateKey = kParam.IsPrivate;
            this.forEncryption = forEncryption;
            this.blockBuffer = new byte[engine.GetOutputBlockSize()];
        }

        public int GetInputBlockSize()
        {
            int baseBlockSize = engine.GetInputBlockSize();

            return forEncryption
                ?	baseBlockSize - HeaderLength
                :	baseBlockSize;
        }

        public int GetOutputBlockSize()
        {
            int baseBlockSize = engine.GetOutputBlockSize();

            return forEncryption
                ?	baseBlockSize
                :	baseBlockSize - HeaderLength;
        }

        public byte[] ProcessBlock(byte[] input, int inOff, int length)
        {
            return forEncryption
                ?	EncodeBlock(input, inOff, length)
                :	DecodeBlock(input, inOff, length);
        }

        private byte[] EncodeBlock(byte[] input, int inOff, int inLen)
        {
            if (inLen > GetInputBlockSize())
                throw new ArgumentException("input data too large", "inLen");

            byte[] block = new byte[engine.GetInputBlockSize()];

            int lastPadPos = block.Length - 1 - inLen;
            if (forPrivateKey)
            {
                block[0] = 0x01;                                // type code 1

                for (int i = 1; i < lastPadPos; ++i)
                {
                    block[i] = 0xFF;
                }
            }
            else
            {
                random.NextBytes(block);                        // random fill

                block[0] = 0x02;                                // type code 2

                // a zero byte marks the end of the padding, so all the pad bytes must be non-zero.
                for (int i = 1; i < lastPadPos; ++i)
                {
                    while (block[i] == 0)
                    {
                        block[i] = (byte)random.NextInt();
                    }
                }
            }

            block[lastPadPos] = 0x00;                           // mark the end of the padding
            Array.Copy(input, inOff, block, block.Length - inLen, inLen);

            return engine.ProcessBlock(block, 0, block.Length);
        }

        /**
         * Check the argument is a valid encoding with type 1. Returns the plaintext length if valid, or -1 if invalid.
         */
        private static int CheckPkcs1Encoding1(byte[] buf)
        {
            int foundZeroMask = 0;
            int lastPadPos = 0;

            // The first byte should be 0x01
            int badPadSign = -(buf[0] ^ 0x01);

            // There must be a zero terminator for the padding somewhere
            for (int i = 1; i < buf.Length; ++i)
            {
                int padByte = buf[i];
                int is0x00Mask = ((padByte ^ 0x00) - 1) >> 31;
                int is0xFFMask = ((padByte ^ 0xFF) - 1) >> 31;
                lastPadPos ^= i & ~foundZeroMask & is0x00Mask;
                foundZeroMask |= is0x00Mask;
                badPadSign |= ~(foundZeroMask | is0xFFMask);
            }

            // The header should be at least 10 bytes
            badPadSign |= lastPadPos - 9;

            int plaintextLength = buf.Length - 1 - lastPadPos;
            return plaintextLength | badPadSign >> 31;
        }

        /**
         * Check the argument is a valid encoding with type 2. Returns the plaintext length if valid, or -1 if invalid.
         */
        private static int CheckPkcs1Encoding2(byte[] buf)
        {
            int foundZeroMask = 0;
            int lastPadPos = 0;

            // The first byte should be 0x02
            int badPadSign = -(buf[0] ^ 0x02);

            // There must be a zero terminator for the padding somewhere
            for (int i = 1; i < buf.Length; ++i)
            {
                int padByte = buf[i];
                int is0x00Mask = ((padByte ^ 0x00) - 1) >> 31;
                lastPadPos ^= i & ~foundZeroMask & is0x00Mask;
                foundZeroMask |= is0x00Mask;
            }

            // The header should be at least 10 bytes
            badPadSign |= lastPadPos - 9;

            int plaintextLength = buf.Length - 1 - lastPadPos;
            return plaintextLength | badPadSign >> 31;
        }

        /**
         * Check the argument is a valid encoding with type 2 of a plaintext with the given length. Returns 0 if
         * valid, or -1 if invalid.
         */
        private static int CheckPkcs1Encoding2(byte[] buf, int plaintextLength)
        {
            // The first byte should be 0x02
            int badPadSign = -(buf[0] ^ 0x02);

            int lastPadPos = buf.Length - 1 - plaintextLength;

            // The header should be at least 10 bytes
            badPadSign |= lastPadPos - 9;

            // All pad bytes before the last one should be non-zero
            for (int i = 1; i < lastPadPos; ++i)
            {
                badPadSign |= buf[i] - 1;
            }

            // Last pad byte should be zero
            badPadSign |= -buf[lastPadPos];

            return badPadSign >> 31;
        }

        /**
         * Decode PKCS#1.5 encoding, and return a random value if the padding is not correct.
         * 
         * @param in The encrypted block.
         * @param inOff Offset in the encrypted block.
         * @param inLen Length of the encrypted block.
         * @param pLen Length of the desired output.
         * @return The plaintext without padding, or a random value if the padding was incorrect.
         * @throws InvalidCipherTextException
         */
        private byte[] DecodeBlockOrRandom(byte[] input, int inOff, int inLen)
        {
            if (!forPrivateKey)
                throw new InvalidCipherTextException("sorry, this method is only for decryption, not for signing");

            int plaintextLength = this.pLen;

            byte[] random = fallback;
            if (fallback == null)
            {
                random = SecureRandom.GetNextBytes(this.random, plaintextLength);
            }

            int badPadMask = 0;
            int strictBlockSize = engine.GetOutputBlockSize();
            byte[] block = engine.ProcessBlock(input, inOff, inLen);

            byte[] data = block;
            if (block.Length != strictBlockSize)
            {
                if (useStrictLength || block.Length < strictBlockSize)
                {
                    data = blockBuffer;
                }
            }

            badPadMask |= CheckPkcs1Encoding2(data, plaintextLength);

            /*
             * Now, to a constant time constant memory copy of the decrypted value
             * or the random value, depending on the validity of the padding.
             */
            int dataOff = data.Length - plaintextLength; 
            byte[] result = new byte[plaintextLength];
            for (int i = 0; i < plaintextLength; ++i)
            {
                result[i] = (byte)((data[dataOff + i] & ~badPadMask) | (random[i] & badPadMask));
            }

            Arrays.Fill(block, 0);
            Arrays.Fill(blockBuffer, 0, System.Math.Max(0, blockBuffer.Length - block.Length), 0);

            return result;
        }

        /**
        * @exception InvalidCipherTextException if the decrypted block is not in Pkcs1 format.
        */
        private byte[] DecodeBlock(byte[] input, int inOff, int inLen)
        {
            /*
             * If the length of the expected plaintext is known, we use a constant-time decryption.
             * If the decryption fails, we return a random value.
             */
            if (forPrivateKey && this.pLen != -1)
                return DecodeBlockOrRandom(input, inOff, inLen);

            int strictBlockSize = engine.GetOutputBlockSize();
            byte[] block = engine.ProcessBlock(input, inOff, inLen);

            bool incorrectLength = useStrictLength & (block.Length != strictBlockSize);

            byte[] data = block;
            if (block.Length < strictBlockSize)
            {
                data = blockBuffer;
            }

            int plaintextLength = forPrivateKey ? CheckPkcs1Encoding2(data) : CheckPkcs1Encoding1(data);

            try
            {
                if (plaintextLength < 0)
                    throw new InvalidCipherTextException("block incorrect");
                if (incorrectLength)
                    throw new InvalidCipherTextException("block incorrect size");

                byte[] result = new byte[plaintextLength];
                Array.Copy(data, data.Length - plaintextLength, result, 0, plaintextLength);
                return result;
            }
            finally
            {
                Arrays.Fill(block, 0);
                Arrays.Fill(blockBuffer, 0, System.Math.Max(0, blockBuffer.Length - block.Length), 0);
            }
        }
    }
}
