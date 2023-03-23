using System;
using System.IO;

using Org.BouncyCastle.Crypto.Utilities;
using Org.BouncyCastle.Utilities;

namespace Org.BouncyCastle.Tls.Crypto.Impl
{
    /// <summary>A generic TLS 1.0-1.2 block cipher. This can be used for AES or 3DES for example.</summary>
    public class TlsBlockCipher
        : AbstractTlsCipher
    {
        protected readonly TlsCryptoParameters m_cryptoParams;
        protected readonly byte[] m_randomData;
        protected readonly bool m_encryptThenMac;
        protected readonly bool m_useExplicitIV;
        protected readonly bool m_acceptExtraPadding;
        protected readonly bool m_useExtraPadding;

        protected readonly TlsBlockCipherImpl m_decryptCipher, m_encryptCipher;
        protected readonly TlsSuiteHmac m_readMac, m_writeMac;
        protected readonly byte[] m_decryptConnectionID, m_encryptConnectionID;
        protected readonly bool m_decryptUseInnerPlaintext, m_encryptUseInnerPlaintext;

        /// <exception cref="IOException"/>
        public TlsBlockCipher(TlsCryptoParameters cryptoParams, TlsBlockCipherImpl encryptCipher,
            TlsBlockCipherImpl decryptCipher, TlsHmac clientMac, TlsHmac serverMac, int cipherKeySize)
        {
            SecurityParameters securityParameters = cryptoParams.SecurityParameters;
            ProtocolVersion negotiatedVersion = securityParameters.NegotiatedVersion;

            if (TlsImplUtilities.IsTlsV13(negotiatedVersion))
                throw new TlsFatalAlert(AlertDescription.internal_error);

            m_decryptConnectionID = securityParameters.ConnectionIDPeer;
            m_encryptConnectionID = securityParameters.ConnectionIDLocal;

            m_decryptUseInnerPlaintext = !Arrays.IsNullOrEmpty(m_decryptConnectionID);
            m_encryptUseInnerPlaintext = !Arrays.IsNullOrEmpty(m_encryptConnectionID);

            this.m_cryptoParams = cryptoParams;
            this.m_randomData = cryptoParams.NonceGenerator.GenerateNonce(256);

            this.m_encryptThenMac = securityParameters.IsEncryptThenMac;
            this.m_useExplicitIV = TlsImplUtilities.IsTlsV11(negotiatedVersion);

            this.m_acceptExtraPadding = !negotiatedVersion.IsSsl;

            /*
             * Don't use variable-length padding with truncated MACs.
             * 
             * See "Tag Size Does Matter: Attacks and Proofs for the TLS Record Protocol", Paterson,
             * Ristenpart, Shrimpton.
             *
             * TODO[DTLS] Consider supporting in DTLS (without exceeding send limit though)
             */
            this.m_useExtraPadding = securityParameters.IsExtendedPadding
                && ProtocolVersion.TLSv10.IsEqualOrEarlierVersionOf(negotiatedVersion)
                && (m_encryptThenMac || !securityParameters.IsTruncatedHmac);

            this.m_encryptCipher = encryptCipher;
            this.m_decryptCipher = decryptCipher;

            TlsBlockCipherImpl clientCipher, serverCipher;
            if (cryptoParams.IsServer)
            {
                clientCipher = decryptCipher;
                serverCipher = encryptCipher;
            }
            else
            {
                clientCipher = encryptCipher;
                serverCipher = decryptCipher;
            }

            int keyBlockSize = (2 * cipherKeySize) + clientMac.MacLength + serverMac.MacLength;

            // From TLS 1.1 onwards, block ciphers don't need IVs from the key_block
            if (!m_useExplicitIV)
            {
                keyBlockSize += clientCipher.GetBlockSize() + serverCipher.GetBlockSize();
            }

#if NETCOREAPP2_1_OR_GREATER || NETSTANDARD2_1_OR_GREATER
            Span<byte> keyBlock = keyBlockSize <= 512
                ? stackalloc byte[keyBlockSize]
                : new byte[keyBlockSize];
            TlsImplUtilities.CalculateKeyBlock(cryptoParams, keyBlock);

            clientMac.SetKey(keyBlock[..clientMac.MacLength]); keyBlock = keyBlock[clientMac.MacLength..];
            serverMac.SetKey(keyBlock[..serverMac.MacLength]); keyBlock = keyBlock[serverMac.MacLength..];

            clientCipher.SetKey(keyBlock[..cipherKeySize]); keyBlock = keyBlock[cipherKeySize..];
            serverCipher.SetKey(keyBlock[..cipherKeySize]); keyBlock = keyBlock[cipherKeySize..];

            int clientIVLength = clientCipher.GetBlockSize();
            int serverIVLength = serverCipher.GetBlockSize();

            if (m_useExplicitIV)
            {
                clientCipher.Init(clientIVLength <= 64 ? stackalloc byte[clientIVLength] : new byte[clientIVLength]);
                serverCipher.Init(serverIVLength <= 64 ? stackalloc byte[serverIVLength] : new byte[serverIVLength]);
            }
            else
            {
                clientCipher.Init(keyBlock[..clientIVLength]); keyBlock = keyBlock[clientIVLength..];
                serverCipher.Init(keyBlock[..serverIVLength]); keyBlock = keyBlock[serverIVLength..];
            }

            if (!keyBlock.IsEmpty)
                throw new TlsFatalAlert(AlertDescription.internal_error);
#else
            byte[] keyBlock = TlsImplUtilities.CalculateKeyBlock(cryptoParams, keyBlockSize);
            int pos = 0;

            clientMac.SetKey(keyBlock, pos, clientMac.MacLength);
            pos += clientMac.MacLength;
            serverMac.SetKey(keyBlock, pos, serverMac.MacLength);
            pos += serverMac.MacLength;

            clientCipher.SetKey(keyBlock, pos, cipherKeySize);
            pos += cipherKeySize;
            serverCipher.SetKey(keyBlock, pos, cipherKeySize);
            pos += cipherKeySize;

            int clientIVLength = clientCipher.GetBlockSize();
            int serverIVLength = serverCipher.GetBlockSize();

            if (m_useExplicitIV)
            {
                clientCipher.Init(new byte[clientIVLength], 0, clientIVLength);
                serverCipher.Init(new byte[serverIVLength], 0, serverIVLength);
            }
            else
            {
                clientCipher.Init(keyBlock, pos, clientIVLength);
                pos += clientIVLength;
                serverCipher.Init(keyBlock, pos, serverIVLength);
                pos += serverIVLength;
            }

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
            int blockSize = m_decryptCipher.GetBlockSize();
            int macSize = m_readMac.Size;
            int maxExtraPadding = 256;

            int innerPlaintextLimit = plaintextLimit + (m_decryptUseInnerPlaintext ? 1 : 0);

            return GetCiphertextLength(blockSize, macSize, maxExtraPadding, innerPlaintextLimit);
        }

        public override int GetCiphertextEncodeLimit(int plaintextLength, int plaintextLimit)
        {
            int blockSize = m_encryptCipher.GetBlockSize();
            int macSize = m_writeMac.Size;
            int maxExtraPadding = m_useExtraPadding ? 256 : blockSize;

            int innerPlaintextLimit = plaintextLength;
            if (m_encryptUseInnerPlaintext)
            {
                // TODO[cid] Add support for padding
                int maxPadding = 0;

                innerPlaintextLimit = 1 + System.Math.Min(plaintextLimit, plaintextLength + maxPadding);
            }

            return GetCiphertextLength(blockSize, macSize, maxExtraPadding, innerPlaintextLimit);
        }

        public override int GetPlaintextDecodeLimit(int ciphertextLimit)
        {
            int blockSize = m_decryptCipher.GetBlockSize();
            int macSize = m_readMac.Size;

            int innerPlaintextLimit = GetPlaintextLength(blockSize, macSize, ciphertextLimit);

            return innerPlaintextLimit - (m_decryptUseInnerPlaintext ? 1 : 0);
        }

        public override int GetPlaintextEncodeLimit(int ciphertextLimit)
        {
            int blockSize = m_encryptCipher.GetBlockSize();
            int macSize = m_writeMac.Size;

            int innerPlaintextLimit = GetPlaintextLength(blockSize, macSize, ciphertextLimit);

            return innerPlaintextLimit - (m_encryptUseInnerPlaintext ? 1 : 0);
        }

        public override TlsEncodeResult EncodePlaintext(long seqNo, short contentType, ProtocolVersion recordVersion,
            int headerAllocation, byte[] plaintext, int offset, int len)
        {
#if NETCOREAPP2_1_OR_GREATER || NETSTANDARD2_1_OR_GREATER
            return EncodePlaintext(seqNo, contentType, recordVersion, headerAllocation, plaintext.AsSpan(offset, len));
#else
            int blockSize = m_encryptCipher.GetBlockSize();
            int macSize = m_writeMac.Size;

            // TODO[cid] If we support adding padding to DTLSInnerPlaintext, this will need review
            int innerPlaintextLength = len + (m_encryptUseInnerPlaintext ? 1 : 0);

            int enc_input_length = innerPlaintextLength;
            if (!m_encryptThenMac)
            {
                enc_input_length += macSize;
            }

            int padding_length = blockSize - (enc_input_length % blockSize);
            if (m_useExtraPadding)
            {
                // Add a random number of extra blocks worth of padding
                int maxExtraPadBlocks = (256 - padding_length) / blockSize;
                int actualExtraPadBlocks = ChooseExtraPadBlocks(maxExtraPadBlocks);
                padding_length += actualExtraPadBlocks * blockSize;
            }

            int totalSize = innerPlaintextLength + macSize + padding_length;
            if (m_useExplicitIV)
            {
                totalSize += blockSize;
            }

            byte[] outBuf = new byte[headerAllocation + totalSize];
            int outOff = headerAllocation;

            if (m_useExplicitIV)
            {
                // Technically the explicit IV will be the encryption of this nonce
                byte[] explicitIV = m_cryptoParams.NonceGenerator.GenerateNonce(blockSize);
                Array.Copy(explicitIV, 0, outBuf, outOff, blockSize);
                outOff += blockSize;
            }

            int innerPlaintextOffset = outOff;

            Array.Copy(plaintext, offset, outBuf, outOff, len);
            outOff += len;

            short recordType = contentType;
            if (m_encryptUseInnerPlaintext)
            {
                outBuf[outOff++] = (byte)contentType;
                recordType = ContentType.tls12_cid;
            }

            if (!m_encryptThenMac)
            {
                byte[] mac = m_writeMac.CalculateMac(seqNo, recordType, m_encryptConnectionID, outBuf,
                    innerPlaintextOffset, innerPlaintextLength);
                Array.Copy(mac, 0, outBuf, outOff, mac.Length);
                outOff += mac.Length;
            }

            byte padByte = (byte)(padding_length - 1);
            for (int i = 0; i < padding_length; ++i)
            {
                outBuf[outOff++] = padByte;
            }

            m_encryptCipher.DoFinal(outBuf, headerAllocation, outOff - headerAllocation, outBuf, headerAllocation);

            if (m_encryptThenMac)
            {
                byte[] mac = m_writeMac.CalculateMac(seqNo, recordType, outBuf, headerAllocation,
                    outOff - headerAllocation);
                Array.Copy(mac, 0, outBuf, outOff, mac.Length);
                outOff += mac.Length;
            }

            if (outOff != outBuf.Length)
                throw new TlsFatalAlert(AlertDescription.internal_error);

            return new TlsEncodeResult(outBuf, 0, outBuf.Length, recordType);
#endif
        }

#if NETCOREAPP2_1_OR_GREATER || NETSTANDARD2_1_OR_GREATER
        public override TlsEncodeResult EncodePlaintext(long seqNo, short contentType, ProtocolVersion recordVersion,
            int headerAllocation, ReadOnlySpan<byte> plaintext)
        {
            int blockSize = m_encryptCipher.GetBlockSize();
            int macSize = m_writeMac.Size;

            // TODO[cid] If we support adding padding to DTLSInnerPlaintext, this will need review
            int innerPlaintextLength = plaintext.Length + (m_encryptUseInnerPlaintext ? 1 : 0);

            int enc_input_length = innerPlaintextLength;
            if (!m_encryptThenMac)
            {
                enc_input_length += macSize;
            }

            int padding_length = blockSize - (enc_input_length % blockSize);
            if (m_useExtraPadding)
            {
                // Add a random number of extra blocks worth of padding
                int maxExtraPadBlocks = (256 - padding_length) / blockSize;
                int actualExtraPadBlocks = ChooseExtraPadBlocks(maxExtraPadBlocks);
                padding_length += actualExtraPadBlocks * blockSize;
            }

            int totalSize = innerPlaintextLength + macSize + padding_length;
            if (m_useExplicitIV)
            {
                totalSize += blockSize;
            }

            byte[] outBuf = new byte[headerAllocation + totalSize];
            int outOff = headerAllocation;

            if (m_useExplicitIV)
            {
                // Technically the explicit IV will be the encryption of this nonce
                byte[] explicitIV = m_cryptoParams.NonceGenerator.GenerateNonce(blockSize);
                Array.Copy(explicitIV, 0, outBuf, outOff, blockSize);
                outOff += blockSize;
            }

            int innerPlaintextOffset = outOff;

            plaintext.CopyTo(outBuf.AsSpan(outOff));
            outOff += plaintext.Length;

            short recordType = contentType;
            if (m_encryptUseInnerPlaintext)
            {
                outBuf[outOff++] = (byte)contentType;
                recordType = ContentType.tls12_cid;
            }

            if (!m_encryptThenMac)
            {
                byte[] mac = m_writeMac.CalculateMac(seqNo, recordType, m_encryptConnectionID,
                    outBuf.AsSpan(innerPlaintextOffset, innerPlaintextLength));
                mac.CopyTo(outBuf.AsSpan(outOff));
                outOff += mac.Length;
            }

            byte padByte = (byte)(padding_length - 1);
            for (int i = 0; i < padding_length; ++i)
            {
                outBuf[outOff++] = padByte;
            }

            m_encryptCipher.DoFinal(outBuf, headerAllocation, outOff - headerAllocation, outBuf, headerAllocation);

            if (m_encryptThenMac)
            {
                byte[] mac = m_writeMac.CalculateMac(seqNo, recordType, m_encryptConnectionID,
                    outBuf.AsSpan(headerAllocation, outOff - headerAllocation));
                Array.Copy(mac, 0, outBuf, outOff, mac.Length);
                outOff += mac.Length;
            }

            if (outOff != outBuf.Length)
                throw new TlsFatalAlert(AlertDescription.internal_error);

            return new TlsEncodeResult(outBuf, 0, outBuf.Length, recordType);
        }
#endif

        public override TlsDecodeResult DecodeCiphertext(long seqNo, short recordType, ProtocolVersion recordVersion,
            byte[] ciphertext, int offset, int len)
        {
            int blockSize = m_decryptCipher.GetBlockSize();
            int macSize = m_readMac.Size;

            int minLen = blockSize;
            if (m_encryptThenMac)
            {
                minLen += macSize;
            }
            else
            {
                minLen = System.Math.Max(minLen, macSize + 1);
            }

            if (m_useExplicitIV)
            {
                minLen += blockSize;
            }

            if (len < minLen)
                throw new TlsFatalAlert(AlertDescription.decode_error);

            int blocks_length = len;
            if (m_encryptThenMac)
            {
                blocks_length -= macSize;
            }

            if (blocks_length % blockSize != 0)
                throw new TlsFatalAlert(AlertDescription.decryption_failed);

            if (m_encryptThenMac)
            {
                byte[] expectedMac = m_readMac.CalculateMac(seqNo, recordType, m_decryptConnectionID, ciphertext,
                    offset, len - macSize);

                bool checkMac = TlsUtilities.ConstantTimeAreEqual(macSize, expectedMac, 0, ciphertext,
                    offset + len - macSize);
                if (!checkMac)
                {
                    /*
                     * RFC 7366 3. The MAC SHALL be evaluated before any further processing such as
                     * decryption is performed, and if the MAC verification fails, then processing SHALL
                     * terminate immediately. For TLS, a fatal bad_record_mac MUST be generated [2]. For
                     * DTLS, the record MUST be discarded, and a fatal bad_record_mac MAY be generated
                     * [4]. This immediate response to a bad MAC eliminates any timing channels that may
                     * be available through the use of manipulated packet data.
                     */
                    throw new TlsFatalAlert(AlertDescription.bad_record_mac);
                }
            }

            m_decryptCipher.DoFinal(ciphertext, offset, blocks_length, ciphertext, offset);

            if (m_useExplicitIV)
            {
                offset += blockSize;
                blocks_length -= blockSize;
            }

            // If there's anything wrong with the padding, this will return zero
            int totalPad = CheckPaddingConstantTime(ciphertext, offset, blocks_length, blockSize,
                m_encryptThenMac ? 0 : macSize);
            bool badMac = (totalPad == 0);

            int dec_output_length = blocks_length - totalPad;

            if (!m_encryptThenMac)
            {
                dec_output_length -= macSize;

                byte[] expectedMac = m_readMac.CalculateMacConstantTime(seqNo, recordType, m_decryptConnectionID,
                    ciphertext, offset, dec_output_length, blocks_length - macSize, m_randomData);

                badMac |= !TlsUtilities.ConstantTimeAreEqual(macSize, expectedMac, 0, ciphertext,
                    offset + dec_output_length);
            }

            if (badMac)
                throw new TlsFatalAlert(AlertDescription.bad_record_mac);

            short contentType = recordType;
            if (m_decryptUseInnerPlaintext)
            {
                // Strip padding and read true content type from DTLSInnerPlaintext
                int pos = dec_output_length;
                for (;;)
                {
                    if (--pos < 0)
                        throw new TlsFatalAlert(AlertDescription.unexpected_message);

                    byte octet = ciphertext[offset + pos];
                    if (0 != octet)
                    {
                        contentType = (short)(octet & 0xFF);
                        dec_output_length = pos;
                        break;
                    }
                }
            }

            return new TlsDecodeResult(ciphertext, offset, dec_output_length, contentType);
        }

        public override bool UsesOpaqueRecordType
        {
            get { return false; }
        }

        protected virtual int CheckPaddingConstantTime(byte[] buf, int off, int len, int blockSize, int macSize)
        {
            int end = off + len;
            byte lastByte = buf[end - 1];
            int padlen = lastByte & 0xff;
            int totalPad = padlen + 1;

            int dummyIndex = 0;
            byte padDiff = 0;

            int totalPadLimit = System.Math.Min(m_acceptExtraPadding ? 256 : blockSize, len - macSize);

            if (totalPad > totalPadLimit)
            {
                totalPad = 0;
            }
            else
            {
                int padPos = end - totalPad;
                do
                {
                    padDiff |= (byte)(buf[padPos++] ^ lastByte);
                }
                while (padPos < end);

                dummyIndex = totalPad;

                if (padDiff != 0)
                {
                    totalPad = 0;
                }
            }

            // Run some extra dummy checks so the number of checks is always constant
            {
                byte[] dummyPad = m_randomData;
                while (dummyIndex < 256)
                {
                    padDiff |= (byte)(dummyPad[dummyIndex++] ^ lastByte);
                }
                // Ensure the above loop is not eliminated
                dummyPad[0] ^= padDiff;
            }

            return totalPad;
        }

        protected virtual int ChooseExtraPadBlocks(int max)
        {
            byte[] random = m_cryptoParams.NonceGenerator.GenerateNonce(4);
            int x = (int)Pack.LE_To_UInt32(random, 0);
            int n = Integers.NumberOfTrailingZeros(x);
            return System.Math.Min(n, max);
        }

        protected virtual int GetCiphertextLength(int blockSize, int macSize, int maxPadding, int plaintextLength)
        {
            int ciphertextLength = plaintextLength;

            // An explicit IV consumes 1 block
            if (m_useExplicitIV)
            {
                ciphertextLength += blockSize;
            }

            // Leave room for the MAC and (block-aligning) padding

            ciphertextLength += maxPadding;

            if (m_encryptThenMac)
            {
                ciphertextLength -= (ciphertextLength % blockSize);
                ciphertextLength += macSize;
            }
            else
            {
                ciphertextLength += macSize;
                ciphertextLength -= (ciphertextLength % blockSize);
            }

            return ciphertextLength;
        }

        protected virtual int GetPlaintextLength(int blockSize, int macSize, int ciphertextLength)
        {
            int plaintextLength = ciphertextLength;

            // Leave room for the MAC, and require block-alignment
            if (m_encryptThenMac)
            {
                plaintextLength -= macSize;
                plaintextLength -= plaintextLength % blockSize;
            }
            else
            {
                plaintextLength -= plaintextLength % blockSize;
                plaintextLength -= macSize;
            }

            // Minimum 1 byte of padding
            --plaintextLength;

            // An explicit IV consumes 1 block
            if (m_useExplicitIV)
            {
                plaintextLength -= blockSize;
            }

            return plaintextLength;
        }
    }
}
