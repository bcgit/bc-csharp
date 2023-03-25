using System;
using System.IO;

using Org.BouncyCastle.Utilities;

namespace Org.BouncyCastle.Tls.Crypto.Impl
{
    /// <summary>The NULL cipher.</summary>
    public class TlsNullCipher
        : AbstractTlsCipher
    {
        protected readonly TlsCryptoParameters m_cryptoParams;
        protected readonly TlsSuiteHmac m_readMac, m_writeMac;
        protected readonly byte[] m_decryptConnectionID, m_encryptConnectionID;
        protected readonly bool m_decryptUseInnerPlaintext, m_encryptUseInnerPlaintext;

        /// <exception cref="IOException"/>
        public TlsNullCipher(TlsCryptoParameters cryptoParams, TlsHmac clientMac, TlsHmac serverMac)
        {
            SecurityParameters securityParameters = cryptoParams.SecurityParameters;
            ProtocolVersion negotiatedVersion = securityParameters.NegotiatedVersion;

            if (TlsImplUtilities.IsTlsV13(negotiatedVersion))
                throw new TlsFatalAlert(AlertDescription.internal_error);

            m_decryptConnectionID = securityParameters.ConnectionIDPeer;
            m_encryptConnectionID = securityParameters.ConnectionIDLocal;

            m_decryptUseInnerPlaintext = !Arrays.IsNullOrEmpty(m_decryptConnectionID);
            m_encryptUseInnerPlaintext = !Arrays.IsNullOrEmpty(m_encryptConnectionID);

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
            int innerPlaintextLimit = plaintextLimit + (m_decryptUseInnerPlaintext ? 1 : 0);

            return innerPlaintextLimit + m_readMac.Size;
        }

        public override int GetCiphertextEncodeLimit(int plaintextLength, int plaintextLimit)
        {
            plaintextLimit = System.Math.Min(plaintextLength, plaintextLimit);

            int innerPlaintextLimit = plaintextLimit + (m_encryptUseInnerPlaintext ? 1 : 0);

            return innerPlaintextLimit + m_writeMac.Size;
        }

        public override int GetPlaintextDecodeLimit(int ciphertextLimit)
        {
            int innerPlaintextLimit = ciphertextLimit - m_readMac.Size;

            return innerPlaintextLimit - (m_decryptUseInnerPlaintext ? 1 : 0);
        }

        public override int GetPlaintextEncodeLimit(int ciphertextLimit)
        {
            int innerPlaintextLimit = ciphertextLimit - m_writeMac.Size;

            return innerPlaintextLimit - (m_encryptUseInnerPlaintext ? 1 : 0);
        }

        public override TlsEncodeResult EncodePlaintext(long seqNo, short contentType, ProtocolVersion recordVersion,
            int headerAllocation, byte[] plaintext, int offset, int len)
        {
#if NETCOREAPP2_1_OR_GREATER || NETSTANDARD2_1_OR_GREATER
            return EncodePlaintext(seqNo, contentType, recordVersion, headerAllocation, plaintext.AsSpan(offset, len));
#else
            int macSize = m_writeMac.Size;

            // TODO[cid] If we support adding padding to DTLSInnerPlaintext, this will need review
            int innerPlaintextLength = len + (m_encryptUseInnerPlaintext ? 1 : 0);

            byte[] ciphertext = new byte[headerAllocation + innerPlaintextLength + macSize];
            Array.Copy(plaintext, offset, ciphertext, headerAllocation, len);

            short recordType = contentType;
            if (m_encryptUseInnerPlaintext)
            {
                ciphertext[headerAllocation + len] = (byte)contentType;
                recordType = ContentType.tls12_cid;
            }

            byte[] mac = m_writeMac.CalculateMac(seqNo, recordType, m_encryptConnectionID, ciphertext, headerAllocation,
                innerPlaintextLength);
            Array.Copy(mac, 0, ciphertext, headerAllocation + innerPlaintextLength, mac.Length);

            return new TlsEncodeResult(ciphertext, 0, ciphertext.Length, recordType);
#endif
        }

#if NETCOREAPP2_1_OR_GREATER || NETSTANDARD2_1_OR_GREATER
        public override TlsEncodeResult EncodePlaintext(long seqNo, short contentType, ProtocolVersion recordVersion,
            int headerAllocation, ReadOnlySpan<byte> plaintext)
        {
            int macSize = m_writeMac.Size;

            // TODO[cid] If we support adding padding to DTLSInnerPlaintext, this will need review
            int innerPlaintextLength = plaintext.Length + (m_encryptUseInnerPlaintext ? 1 : 0);

            byte[] ciphertext = new byte[headerAllocation + innerPlaintextLength + macSize];
            plaintext.CopyTo(ciphertext.AsSpan(headerAllocation));

            short recordType = contentType;
            if (m_encryptUseInnerPlaintext)
            {
                ciphertext[headerAllocation + plaintext.Length] = (byte)contentType;
                recordType = ContentType.tls12_cid;
            }

            byte[] mac = m_writeMac.CalculateMac(seqNo, recordType, m_encryptConnectionID,
                ciphertext.AsSpan(headerAllocation, innerPlaintextLength));
            mac.CopyTo(ciphertext.AsSpan(headerAllocation + innerPlaintextLength));

            return new TlsEncodeResult(ciphertext, 0, ciphertext.Length, recordType);
        }
#endif

        public override TlsDecodeResult DecodeCiphertext(long seqNo, short recordType, ProtocolVersion recordVersion,
            byte[] ciphertext, int offset, int len)
        {
            int macSize = m_readMac.Size;

            int innerPlaintextLength = len - macSize;

            if (innerPlaintextLength < (m_decryptUseInnerPlaintext ? 1 : 0))
                throw new TlsFatalAlert(AlertDescription.decode_error);

            byte[] expectedMac = m_readMac.CalculateMac(seqNo, recordType, m_decryptConnectionID, ciphertext, offset,
                innerPlaintextLength);

            bool badMac = !TlsUtilities.ConstantTimeAreEqual(macSize, expectedMac, 0, ciphertext,
                offset + innerPlaintextLength);
            if (badMac)
                throw new TlsFatalAlert(AlertDescription.bad_record_mac);

            short contentType = recordType;
            int plaintextLength = innerPlaintextLength;

            if (m_decryptUseInnerPlaintext)
            {
                // Strip padding and read true content type from DTLSInnerPlaintext
                for (;;)
                {
                    if (--plaintextLength < 0)
                        throw new TlsFatalAlert(AlertDescription.unexpected_message);

                    byte octet = ciphertext[offset + plaintextLength];
                    if (0 != octet)
                    {
                        contentType = (short)(octet & 0xFF);
                        break;
                    }
                }
            }

            return new TlsDecodeResult(ciphertext, offset, plaintextLength, contentType);
        }

        public override bool UsesOpaqueRecordType
        {
            get { return false; }
        }
    }
}
