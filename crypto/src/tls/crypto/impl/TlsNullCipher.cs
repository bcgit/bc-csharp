using System;
using System.IO;

namespace Org.BouncyCastle.Tls.Crypto.Impl
{
    /// <summary>The NULL cipher.</summary>
    public class TlsNullCipher
        : AbstractTlsCipher
    {
        protected readonly TlsCryptoParameters m_cryptoParams;
        protected readonly TlsSuiteHmac m_readMac, m_writeMac;

        /// <exception cref="IOException"/>
        public TlsNullCipher(TlsCryptoParameters cryptoParams, TlsHmac clientMac, TlsHmac serverMac)
        {
            if (TlsImplUtilities.IsTlsV13(cryptoParams))
                throw new TlsFatalAlert(AlertDescription.internal_error);

            m_cryptoParams = cryptoParams;

            int keyBlockSize = clientMac.MacLength + serverMac.MacLength;

#if NETCOREAPP2_1_OR_GREATER || NETSTANDARD2_1_OR_GREATER
            Span<byte> keyBlock = keyBlockSize <= 512
                ? stackalloc byte[keyBlockSize]
                : new byte[keyBlockSize];
            TlsImplUtilities.CalculateKeyBlock(cryptoParams, keyBlock);

            clientMac.SetKey(keyBlock[..clientMac.MacLength]); keyBlock = keyBlock[clientMac.MacLength..];
            serverMac.SetKey(keyBlock[..serverMac.MacLength]); keyBlock = keyBlock[serverMac.MacLength..];

            if (!keyBlock.IsEmpty)
                throw new TlsFatalAlert(AlertDescription.internal_error);
#else
            byte[] keyBlock = TlsImplUtilities.CalculateKeyBlock(cryptoParams, keyBlockSize);
            int pos = 0;

            clientMac.SetKey(keyBlock, pos, clientMac.MacLength);
            pos += clientMac.MacLength;
            serverMac.SetKey(keyBlock, pos, serverMac.MacLength);
            pos += serverMac.MacLength;

            if (pos != keyBlockSize)
                throw new TlsFatalAlert(AlertDescription.internal_error);
#endif

            if (cryptoParams.IsServer)
            {
                this.m_writeMac = new TlsSuiteHmac(cryptoParams, serverMac);
                this.m_readMac = new TlsSuiteHmac(cryptoParams, clientMac);
            }
            else
            {
                this.m_writeMac = new TlsSuiteHmac(cryptoParams, clientMac);
                this.m_readMac = new TlsSuiteHmac(cryptoParams, serverMac);
            }
        }

        public override int GetCiphertextDecodeLimit(int plaintextLimit)
        {
            return plaintextLimit + m_writeMac.Size;
        }

        public override int GetCiphertextEncodeLimit(int plaintextLength, int plaintextLimit)
        {
            return plaintextLength + m_writeMac.Size;
        }

        public override int GetPlaintextLimit(int ciphertextLimit)
        {
            return ciphertextLimit - m_writeMac.Size;
        }

        public override TlsEncodeResult EncodePlaintext(long seqNo, short contentType, ProtocolVersion recordVersion,
            int headerAllocation, byte[] plaintext, int offset, int len)
        {
            byte[] mac = m_writeMac.CalculateMac(seqNo, contentType, plaintext, offset, len);
            byte[] ciphertext = new byte[headerAllocation + len + mac.Length];
            Array.Copy(plaintext, offset, ciphertext, headerAllocation, len);
            Array.Copy(mac, 0, ciphertext, headerAllocation + len, mac.Length);
            return new TlsEncodeResult(ciphertext, 0, ciphertext.Length, contentType);
        }

#if NETCOREAPP2_1_OR_GREATER || NETSTANDARD2_1_OR_GREATER
        public override TlsEncodeResult EncodePlaintext(long seqNo, short contentType, ProtocolVersion recordVersion,
            int headerAllocation, ReadOnlySpan<byte> plaintext)
        {
            byte[] mac = m_writeMac.CalculateMac(seqNo, contentType, plaintext);
            byte[] ciphertext = new byte[headerAllocation + plaintext.Length + mac.Length];
            plaintext.CopyTo(ciphertext.AsSpan(headerAllocation));
            mac.CopyTo(ciphertext.AsSpan(headerAllocation + plaintext.Length));
            return new TlsEncodeResult(ciphertext, 0, ciphertext.Length, contentType);
        }
#endif

        public override TlsDecodeResult DecodeCiphertext(long seqNo, short recordType, ProtocolVersion recordVersion,
            byte[] ciphertext, int offset, int len)
        {
            int macSize = m_readMac.Size;
            if (len < macSize)
                throw new TlsFatalAlert(AlertDescription.decode_error);

            int macInputLen = len - macSize;

            byte[] expectedMac = m_readMac.CalculateMac(seqNo, recordType, ciphertext, offset, macInputLen);

            bool badMac = !TlsUtilities.ConstantTimeAreEqual(macSize, expectedMac, 0, ciphertext, offset + macInputLen);
            if (badMac)
                throw new TlsFatalAlert(AlertDescription.bad_record_mac);

            return new TlsDecodeResult(ciphertext, offset, macInputLen, recordType);
        }

        public override bool UsesOpaqueRecordType
        {
            get { return false; }
        }
    }
}
