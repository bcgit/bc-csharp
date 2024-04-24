using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.Crypto.Utilities;
using Org.BouncyCastle.Utilities;
using Org.BouncyCastle.Utilities.IO;
using System;
using System.IO;

namespace Org.BouncyCastle.Bcpg
{
    internal class AeadInputStream
        : BaseInputStream
    {
        // ported from bc-java

        private readonly Stream inputStream;
        private readonly byte[] buf;
        private readonly BufferedAeadBlockCipher cipher;
        private readonly KeyParameter secretKey;
        private readonly byte[] aaData;
        private readonly byte[] iv;
        private readonly int chunkLength;
        private readonly int tagLen;

        private byte[] data;
        private int dataOff;
        private long chunkIndex = 0;
        private long totalBytes = 0;
        private readonly bool isV5StyleAead;

        private static int GetChunkLength(int chunkSize)
        {
            return 1 << (chunkSize + 6);
        }

        /// <summary>
        /// InputStream for decrypting AEAD encrypted data.
        /// </summary>
        /// <param name="inputStream">underlying InputStream</param>
        /// <param name="cipher">encryption cipher</param>
        /// <param name="secretKey">decryption key</param>
        /// <param name="iv">initialization vector</param>
        /// <param name="aeadAlgorithm">AEAD algorithm</param>
        /// <param name="chunkSize">chunk size of the AEAD encryption</param>
        /// <param name="aaData">associated data</param>
        public AeadInputStream(
            Stream inputStream,
            BufferedAeadBlockCipher cipher,
            KeyParameter secretKey,
            byte[] iv,
            AeadAlgorithmTag aeadAlgorithm,
            int chunkSize,
            byte[] aaData)
            :this(false, inputStream, cipher, secretKey, iv, aeadAlgorithm, chunkSize, aaData)
        {
        }

        /// <summary>
        /// InputStream for decrypting AEAD encrypted data.
        /// </summary>
        /// <param name="isV5StyleAead">flavour of AEAD (OpenPGP v5 or v6)</param>
        /// <param name="inputStream">underlying InputStream</param>
        /// <param name="cipher">encryption cipher</param>
        /// <param name="secretKey">decryption key</param>
        /// <param name="iv">initialization vector</param>
        /// <param name="aeadAlgorithm">AEAD algorithm</param>
        /// <param name="chunkSize">chunk size of the AEAD encryption</param>
        /// <param name="aaData">associated data</param>
        public AeadInputStream(
            bool isV5StyleAead,
            Stream inputStream,
            BufferedAeadBlockCipher cipher,
            KeyParameter secretKey,
            byte[] iv,
            AeadAlgorithmTag aeadAlgorithm,
            int chunkSize,
            byte[] aaData)
        {
            this.inputStream = inputStream;
            this.cipher = cipher;
            this.secretKey = secretKey;
            this.aaData = aaData;
            this.iv = iv;
            this.isV5StyleAead = isV5StyleAead;

            chunkLength = GetChunkLength(chunkSize);
            tagLen = AeadUtils.GetAuthTagLength(aeadAlgorithm);

            buf = new byte[chunkLength + tagLen + tagLen]; // allow room for chunk tag and message tag

            Streams.ReadFully(inputStream, buf, 0, tagLen + tagLen);

            // load the first block
            data = ReadBlock();
            dataOff = 0;
        }

        public override int Read(byte[] buffer, int offset, int count)
        {
            Streams.ValidateBufferArguments(buffer, offset, count);

            if (count == 0)
            {
                return 0;
            }

            if (data != null && dataOff == data.Length)
            {
                data = ReadBlock();
                dataOff = 0;
            }

            if (data == null)
            {
                return 0;
            }

            int available = data.Length - dataOff;
            int supplyLen = count < available ? count : available;
            Array.Copy(data, dataOff, buffer, offset, supplyLen);
            dataOff += supplyLen;

            return supplyLen;
        }

        private byte[] ReadBlock()
        {
            int dataLen = Streams.ReadFully(inputStream, buf, tagLen + tagLen, chunkLength);
            if (dataLen == 0)
            {
                return null;
            }

            byte[] adata = Arrays.Clone(aaData);
            byte[] decData = new byte[dataLen];

            try
            {
                AeadParameters aeadParams = new AeadParameters(
                    secretKey,
                    8 * tagLen,
                    AeadUtils.CreateNonce(iv, chunkIndex),
                    adata);

                cipher.Init(false, aeadParams);

                int len = cipher.ProcessBytes(buf, 0, dataLen + tagLen, decData, 0);

                cipher.DoFinal(decData, len);
            }
            catch (InvalidCipherTextException e)
            {
                throw new IOException($"exception processing chunk {chunkIndex}: {e.Message}");
            }

            totalBytes += decData.Length;
            chunkIndex++;
            Array.Copy(buf, dataLen + tagLen, buf, 0, tagLen); // copy back the "tag"

            if (dataLen != chunkLength)
            {
                // last block
                try
                {
                    adata = AeadUtils.CreateLastBlockAAData(isV5StyleAead, aaData, chunkIndex, totalBytes);
                    AeadParameters aeadParams = new AeadParameters(
                        secretKey,
                        8 * tagLen,
                        AeadUtils.CreateNonce(iv, chunkIndex),
                        adata);

                    cipher.Init(false, aeadParams);

                    cipher.ProcessBytes(buf, 0, tagLen, buf, 0);

                    cipher.DoFinal(buf, 0); // check final tag
                }
                catch (InvalidCipherTextException e)
                {
                    throw new IOException($"exception processing final tag: {e.Message}");
                }
            }
            else
            {
                Streams.ReadFully(inputStream, buf, tagLen, tagLen);   // read the next tag bytes
            }

            return decData;
        }
    }
}