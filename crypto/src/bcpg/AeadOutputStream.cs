using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.Utilities.IO;
using System;
using System.IO;

namespace Org.BouncyCastle.Bcpg
{
    internal class AeadOutputStream
        : BaseOutputStream
    {
        // ported from bc-java

        private readonly bool isV5StyleAead;
        private readonly Stream outputStream;
        private readonly byte[] data;
        private readonly BufferedAeadBlockCipher cipher;
        private readonly KeyParameter secretKey;
        private readonly byte[] aaData;
        private readonly byte[] iv;
        private readonly int chunkLength;
        private readonly int tagLen;

        private int dataOff;
        private long chunkIndex = 0;
        private long totalBytes = 0;

        private static int GetChunkLength(int chunkSize)
        {
            return 1 << (chunkSize + 6);
        }

        /// <summary>
        /// OutputStream for AEAD encryption.
        /// </summary>
        /// <param name="outputStream">underlying OutputStream</param>
        /// <param name="cipher">AEAD cipher</param>
        /// <param name="secretKey">encryption key</param>
        /// <param name="iv">initialization vector</param>
        /// <param name="encAlgorithm">encryption algorithm</param>
        /// <param name="aeadAlgorithm">AEAD algorithm</param>
        /// <param name="chunkSize">chunk size octet of the AEAD encryption</param>
        public AeadOutputStream(
            Stream outputStream,
            BufferedAeadBlockCipher cipher,
            KeyParameter secretKey,
            byte[] iv,
            SymmetricKeyAlgorithmTag encAlgorithm,
            AeadAlgorithmTag aeadAlgorithm,
            int chunkSize)
            :this(false, outputStream, cipher, secretKey, iv, encAlgorithm, aeadAlgorithm, chunkSize)
        {
            
        }

        /// <summary>
        /// OutputStream for AEAD encryption.
        /// </summary>
        /// <param name="isV5StyleAead">flavour of AEAD (OpenPGP v5 or v6)</param>
        /// <param name="outputStream">underlying OutputStream</param>
        /// <param name="cipher">AEAD cipher</param>
        /// <param name="secretKey">encryption key</param>
        /// <param name="iv">initialization vector</param>
        /// <param name="encAlgorithm">encryption algorithm</param>
        /// <param name="aeadAlgorithm">AEAD algorithm</param>
        /// <param name="chunkSize">chunk size octet of the AEAD encryption</param>
        public AeadOutputStream(
            bool isV5StyleAead,
            Stream outputStream,
            BufferedAeadBlockCipher cipher,
            KeyParameter secretKey,
            byte[] iv,
            SymmetricKeyAlgorithmTag encAlgorithm,
            AeadAlgorithmTag aeadAlgorithm,
            int chunkSize)
        {
            this.isV5StyleAead = isV5StyleAead;
            this.outputStream = outputStream;
            this.iv = iv;
            this.chunkLength = GetChunkLength(chunkSize);
            this.tagLen = AeadUtils.GetAuthTagLength(aeadAlgorithm);
            this.data = new byte[chunkLength];
            this.cipher = cipher;
            this.secretKey = secretKey;

            aaData = CreateAAD(isV5StyleAead, encAlgorithm, aeadAlgorithm, chunkSize);
        }

        private static byte[] CreateAAD(bool isV5StyleAEAD, SymmetricKeyAlgorithmTag encAlgorithm, AeadAlgorithmTag aeadAlgorithm, int chunkSize)
        {
            if (isV5StyleAEAD)
            {
                return AeadEncDataPacket.CreateAAData(AeadEncDataPacket.Version1, encAlgorithm, aeadAlgorithm, chunkSize);
            }
            else
            {
                return SymmetricEncIntegrityPacket.CreateAAData(SymmetricEncIntegrityPacket.Version2, encAlgorithm, aeadAlgorithm, chunkSize);
            }
        }

        public override void WriteByte(byte b)
        {
            if (dataOff == data.Length)
            {
                WriteBlock();
            }
            data[dataOff++] = (byte) b;
        }

        public override void Write(byte[] b, int off, int len)
        {
            if (dataOff == data.Length)
            {
                WriteBlock();
            }

            if (len<data.Length - dataOff)
            {
                Array.Copy(b, off, data, dataOff, len);
                dataOff += len;
            }
            else
            {
                int gap = data.Length - dataOff;
                Array.Copy(b, off, data, dataOff, gap);
                dataOff += gap;
                WriteBlock();
                
                len -= gap;
                off += gap;
                while (len >= data.Length)
                {
                    Array.Copy(b, off, data, 0, data.Length);
                    dataOff = data.Length;
                    WriteBlock();
                    len -= data.Length;
                    off += data.Length;
                }
                if (len > 0)
                {
                    Array.Copy(b, off, data, 0, len);
                    dataOff = len;
                }
            }
        }
        
        private void WriteBlock()
        {
            //bool v5StyleAEAD = isV5StyleAEAD;

            //byte[] adata = v5StyleAEAD ? new byte[13] : new byte[aaData.Length];
            byte[] adata = new byte[aaData.Length];
            Array.Copy(aaData, 0, adata, 0, aaData.Length);

            //if (v5StyleAEAD)
            //{
            //    xorChunkId(adata, chunkIndex);
            //}

            try
            {
                AeadParameters aeadParams = new AeadParameters(
                    secretKey,
                    8 * tagLen,
                    AeadUtils.CreateNonce(iv, chunkIndex),
                    adata);

                cipher.Init(true, aeadParams); 

                int len = cipher.ProcessBytes(data, 0, dataOff, data, 0);
                outputStream.Write(data, 0, len);

                len = cipher.DoFinal(data, 0);
                outputStream.Write(data, 0, len);
            }
            catch (InvalidCipherTextException e)
            {
                throw new IOException("exception processing chunk " + chunkIndex + ": " + e.Message);
            }

            totalBytes += dataOff;
            chunkIndex++;
            dataOff = 0;
        }

        private bool disposed = false;
        protected override void Dispose(bool disponing)
        {
            if (!disposed)
            {
                base.Dispose(disponing);
                Finish();
                disposed = true;
            }
        }

        private void Finish()
        {
            if (dataOff > 0)
            {
                WriteBlock();
            }

            byte[] adata = AeadUtils.CreateLastBlockAAData(isV5StyleAead, aaData, chunkIndex, totalBytes);
            try
            {
                AeadParameters aeadParams = new AeadParameters(
                    secretKey,
                    8 * tagLen,
                    AeadUtils.CreateNonce(iv, chunkIndex),
                    adata);

                cipher.Init(true, aeadParams);
                //if (isV5StyleAead)
                //{
                //    cipher.processAADBytes(Pack.longToBigEndian(totalBytes), 0, 8);
                //}
                cipher.DoFinal(data, 0);
                outputStream.Write(data, 0, tagLen); // output final tag
            }
            catch (InvalidCipherTextException e)
            {
                throw new IOException("exception processing final tag: " + e.Message);
            }
            outputStream.Close();
        }
    }
}
