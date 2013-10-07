using System;

using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.Crypto.Tls;
using Org.BouncyCastle.Utilities;

namespace Org.BouncyCastle.Crypto.Tls
{
    public class TlsStreamCipher : TlsCipher
    {
        protected TlsContext context;

        protected IStreamCipher encryptCipher;
        protected IStreamCipher decryptCipher;

        protected TlsMac writeMac;
        protected TlsMac readMac;

        public TlsStreamCipher(TlsContext context, IStreamCipher clientWriteCipher,
            IStreamCipher serverWriteCipher, IDigest clientWriteDigest, IDigest serverWriteDigest, int cipherKeySize)
        {

            bool isServer = context.IsServer;

            this.context = context;

            this.encryptCipher = clientWriteCipher;
            this.decryptCipher = serverWriteCipher;

            int key_block_size = (2 * cipherKeySize) + clientWriteDigest.GetDigestSize()
                + serverWriteDigest.GetDigestSize();

            byte[] key_block = TlsUtilities.CalculateKeyBlock(context, key_block_size);

            int offset = 0;

            // Init MACs
            TlsMac clientWriteMac = new TlsMac(context, clientWriteDigest, key_block, offset,
                clientWriteDigest.GetDigestSize());
            offset += clientWriteDigest.GetDigestSize();
            TlsMac serverWriteMac = new TlsMac(context, serverWriteDigest, key_block, offset,
                serverWriteDigest.GetDigestSize());
            offset += serverWriteDigest.GetDigestSize();

            // Build keys
            KeyParameter clientWriteKey = new KeyParameter(key_block, offset, cipherKeySize);
            offset += cipherKeySize;
            KeyParameter serverWriteKey = new KeyParameter(key_block, offset, cipherKeySize);
            offset += cipherKeySize;

            if (offset != key_block_size)
            {
                throw new TlsFatalAlert(AlertDescription.internal_error);
            }

            ICipherParameters encryptParams, decryptParams;

            if (isServer)
            {
                this.writeMac = serverWriteMac;
                this.readMac = clientWriteMac;
                this.encryptCipher = serverWriteCipher;
                this.decryptCipher = clientWriteCipher;
                encryptParams = serverWriteKey;
                decryptParams = clientWriteKey;
            }
            else
            {
                this.writeMac = clientWriteMac;
                this.readMac = serverWriteMac;
                this.encryptCipher = clientWriteCipher;
                this.decryptCipher = serverWriteCipher;
                encryptParams = clientWriteKey;
                decryptParams = serverWriteKey;
            }

            this.encryptCipher.Init(true, encryptParams);
            this.decryptCipher.Init(false, decryptParams);
        }

        public int GetPlaintextLimit(int ciphertextLimit)
        {
            return ciphertextLimit - writeMac.Size;
        }

        public byte[] EncodePlaintext(long seqNo, ContentType type, byte[] plaintext, int offset, int len, int outputOffset)
        {
            byte[] mac = writeMac.CalculateMac(seqNo, type, plaintext, offset, len);

            byte[] outbuf = new byte[outputOffset + len + mac.Length];

            encryptCipher.ProcessBytes(plaintext, offset, len, outbuf, outputOffset);
            encryptCipher.ProcessBytes(mac, 0, mac.Length, outbuf, outputOffset + len);

            return outbuf;
        }

        public byte[] DecodeCiphertext(long seqNo, ContentType type, byte[] ciphertext, int offset, int len)
        {
            int macSize = readMac.Size;
            if (len < macSize)
            {
                throw new TlsFatalAlert(AlertDescription.decode_error);
            }

            byte[] deciphered = new byte[len];
            decryptCipher.ProcessBytes(ciphertext, offset, len, deciphered, 0);

            int macInputLen = len - macSize;

            byte[] receivedMac = Arrays.CopyOfRange(deciphered, macInputLen, len);
            byte[] computedMac = readMac.CalculateMac(seqNo, type, deciphered, 0, macInputLen);

            if (!Arrays.ConstantTimeAreEqual(receivedMac, computedMac))
            {
                throw new TlsFatalAlert(AlertDescription.bad_record_mac);
            }

            return Arrays.CopyOfRange(deciphered, 0, macInputLen);
        }

        //protected virtual TlsMac CreateTlsMac(IDigest digest, byte[] buf, ref int off)
        //{
        //    int len = digest.GetDigestSize();
        //    TlsMac mac = new TlsMac(digest, buf, off, len);
        //    off += len;
        //    return mac;
        //}

        //protected virtual KeyParameter CreateKeyParameter(byte[] buf, ref int off, int len)
        //{
        //    KeyParameter key = new KeyParameter(buf, off, len);
        //    off += len;
        //    return key;
        //}

        //protected virtual byte[] CopyData(byte[] text, int offset, int len)
        //{
        //    byte[] result = new byte[len];
        //    Array.Copy(text, offset, result, 0, len);
        //    return result;
        //}
    }
}
