using System;
using System.IO;

using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Crypto.Macs;
using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.Utilities;
using Org.BouncyCastle.Crypto.Engines;
using Org.BouncyCastle.Security;
using Org.BouncyCastle.Crypto.Utilities;

namespace Org.BouncyCastle.Crypto.Modes
{
    /**
    * Implements the ChaCha20Poly1305 AEAD algorithm detailed in
    * RFC8439.
    */
    public class ChaCha20Poly1305
        : IAeadStreamCipher
    {
        private static readonly byte[] Zeroes = new byte[15];

        protected readonly ChaCha7539Engine cipher;
        private readonly IMac mac;
        private byte[] macBlock;
        private bool forEncryption;
        private byte[] nonce;
        private byte[] initialAssociatedText;
        private ICipherParameters keyParam;
        private readonly MemoryStream associatedText = new MemoryStream();
        private readonly MemoryStream data = new MemoryStream();

        /**
        * Basic constructor.
        */
        public ChaCha20Poly1305()
        {
            this.cipher = new ChaCha7539Engine();
            this.mac = new Poly1305();
        }

        /**
        * return the underlying stream cipher that we are wrapping.
        *
        * @return the underlying stream cipher that we are wrapping.
        */
        public virtual IStreamCipher GetUnderlyingCipher()
        {
            return cipher;
        }

        public virtual void Init(
            bool forEncryption,
            ICipherParameters parameters)
        {
            this.forEncryption = forEncryption;

            ICipherParameters cipherParameters;
            /*if (parameters is AeadParameters)
            {
                AeadParameters param = (AeadParameters)parameters;

                nonce = param.GetNonce();
                initialAssociatedText = param.GetAssociatedText();
                cipherParameters = param.Key;
            }
            else*/ if (parameters is ParametersWithIV)
            {
                ParametersWithIV param = (ParametersWithIV)parameters;

                nonce = param.GetIV();
                initialAssociatedText = null;
                cipherParameters = param.Parameters;
            }
            else
            {
                throw new ArgumentException("invalid parameters passed to ChaCha20Poly1305");
            }

            // NOTE: Very basic support for key re-use, but no performance gain from it
            if (cipherParameters != null)
            {
                keyParam = cipherParameters;
            }

            if (nonce == null || nonce.Length != 12)
                throw new ArgumentException("nonce must have length of 12 octets");

            cipher.Init(forEncryption, parameters);

            Reset();
        }

        public virtual string AlgorithmName
        {
            //TODO: Not sure what this should be?
            get { return cipher.AlgorithmName + "/Poly1305"; }
        }

        public virtual void ProcessAadByte(byte input)
        {
            associatedText.WriteByte(input);
        }

        public virtual void ProcessAadBytes(byte[] inBytes, int inOff, int len)
        {
            associatedText.Write(inBytes, inOff, len);
        }

        public virtual int ProcessByte(
            byte	input,
            byte[]	outBytes,
            int		outOff)
        {
            data.WriteByte(input);

            return 0;
        }

        public virtual int ProcessBytes(
            byte[]	inBytes,
            int		inOff,
            int		inLen,
            byte[]	outBytes,
            int		outOff)
        {
            Check.DataLength(inBytes, inOff, inLen, "Input buffer too short");

            data.Write(inBytes, inOff, inLen);

            return 0;
        }

        public virtual int DoFinal(
            byte[]	outBytes,
            int		outOff)
        {
#if PORTABLE
            byte[] input = data.ToArray();
            int inLen = input.Length;
#else
            byte[] input = data.GetBuffer();
            int inLen = (int)data.Position;
#endif

            int len = ProcessPacket(input, 0, inLen, outBytes, outOff);

            Reset();

            return len;
        }

        public virtual void Reset()
        {
            cipher.Reset();
            mac.Reset();
            associatedText.SetLength(0);
            data.SetLength(0);
        }

        /**
        * Returns a byte array containing the mac calculated as part of the
        * last encrypt or decrypt operation.
        *
        * @return the last mac calculated.
        */
        public virtual byte[] GetMac()
        {
            return Arrays.CopyOfRange(macBlock, 0, mac.GetMacSize());
        }

        public virtual int GetUpdateOutputSize(
            int len)
        {
            return 0;
        }

        public virtual int GetOutputSize(
            int len)
        {
            int totalData = (int)data.Length + len;

            if (forEncryption)
            {
                return totalData + mac.GetMacSize();
            }

            return totalData < mac.GetMacSize() ? 0 : totalData - mac.GetMacSize();
        }

        /**
         * Process a packet of data for either decryption or encryption.
         *
         * @param in data for processing.
         * @param inOff offset at which data starts in the input array.
         * @param inLen length of the data in the input array.
         * @return a byte array containing the processed input..
         * @throws IllegalStateException if the cipher is not appropriately set up.
         * @throws InvalidCipherTextException if the input data is truncated or the mac check fails.
         */
        public virtual byte[] ProcessPacket(byte[] input, int inOff, int inLen)
        {
            byte[] output;

            if (forEncryption)
            {
                output = new byte[inLen + mac.GetMacSize()];
            }
            else
            {
                if (inLen < mac.GetMacSize())
                    throw new InvalidCipherTextException("data too short");

                output = new byte[inLen - mac.GetMacSize()];
            }

            ProcessPacket(input, inOff, inLen, output, 0);

            return output;
        }

        /**
         * Process a packet of data for either decryption or encryption.
         *
         * @param in data for processing.
         * @param inOff offset at which data starts in the input array.
         * @param inLen length of the data in the input array.
         * @param output output array.
         * @param outOff offset into output array to start putting processed bytes.
         * @return the number of bytes added to output.
         * @throws IllegalStateException if the cipher is not appropriately set up.
         * @throws InvalidCipherTextException if the input data is truncated or the mac check fails.
         * @throws DataLengthException if output buffer too short.
         */
        public virtual int ProcessPacket(byte[] input, int inOff, int inLen, byte[] output, int outOff)
        {
            if (keyParam == null)
                throw new InvalidOperationException("ChaCha20 cipher uninitialized.");

            int result = 0;

            if (forEncryption)
            {
                result = EncodePlaintext(input, inOff, inLen, output, outOff);
            }
            else
            {
                result = DecodeCiphertext(input, inOff, inLen, output, outOff);
            }

            return result;
        }

        private int EncodePlaintext(byte[] input, int inOff, int inLen, byte[] output, int outOff)
        {
            KeyParameter macKey = GenerateMacKey(cipher);

            cipher.ProcessBytes(input, inOff, inLen, output, outOff);

            byte[] additionalData = GetAdditionalData();
            byte[] mac = CalculateMac(macKey, additionalData, output, 0, inLen);
            Array.Copy(mac, 0, output, inLen, mac.Length);

            return inLen + mac.Length;
        }

        private int DecodeCiphertext(byte[] input, int inOff, int inLen, byte[] output, int outOff)
        {
            KeyParameter macKey = GenerateMacKey(cipher);

            int plaintextLength = inLen - 16;

            byte[] additionalData = GetAdditionalData();
            byte[] calculatedMac = CalculateMac(macKey, additionalData, input, inOff, plaintextLength);
            byte[] receivedMac = Arrays.CopyOfRange(input, inOff + plaintextLength, inOff + inLen);

            if (!Arrays.ConstantTimeAreEqual(calculatedMac, receivedMac))
                throw new InvalidCipherTextException("bad received mac");

            cipher.ProcessBytes(input, inOff, plaintextLength, output, outOff);

            return plaintextLength;
        }

        private KeyParameter GenerateMacKey(IStreamCipher cipher)
        {
            byte[] firstBlock = new byte[64];
            cipher.ProcessBytes(firstBlock, 0, firstBlock.Length, firstBlock, 0);

            KeyParameter macKey = new KeyParameter(firstBlock, 0, 32);
            Arrays.Fill(firstBlock, (byte)0);
            return macKey;
        }

        private byte[] CalculateMac(KeyParameter macKey, byte[] additionalData, byte[] buf, int off, int len)
        {
            mac.Init(macKey);

            UpdateMacText(mac, additionalData, 0, additionalData.Length);
            UpdateMacText(mac, buf, off, len);
            UpdateMacLength(mac, additionalData.Length);
            UpdateMacLength(mac, len);

            return MacUtilities.DoFinal(mac);
        }

        private void UpdateMacLength(IMac mac, int len)
        {
            byte[] longLen = Pack.UInt64_To_LE((ulong)len);
            mac.BlockUpdate(longLen, 0, longLen.Length);
        }

        private void UpdateMacText(IMac mac, byte[] buf, int off, int len)
        {
            mac.BlockUpdate(buf, off, len);

            int partial = len % 16;
            if (partial != 0)
            {
                mac.BlockUpdate(Zeroes, 0, 16 - partial);
            }
        }

        private int GetAdditionalDataLength()
        {
            return (int)associatedText.Length + ((initialAssociatedText == null) ? 0 : initialAssociatedText.Length);
        }

        private byte[] GetAdditionalData()
        {
            int length = GetAdditionalDataLength();

            byte[] additionalData = new byte[length];

            if (length > 0)
            {
                int initialLength = 0;

                if (initialAssociatedText != null)
                {
                    initialAssociatedText.CopyTo(additionalData, 0);
                    initialLength = initialAssociatedText.Length;
                }

                if (associatedText.Length > 0)
                {
                    byte[] temp = associatedText.ToArray();
                    temp.CopyTo(additionalData, initialLength);
                }
            }

            return additionalData;
        }

    }
}
