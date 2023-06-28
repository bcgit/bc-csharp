﻿using System;
using System.IO;

using Org.BouncyCastle.Utilities;

namespace Org.BouncyCastle.Tls.Crypto.Impl
{
    /// <summary>A generic TLS 1.2 AEAD cipher.</summary>
    public class TlsAeadCipher
        : TlsCipher, TlsCipherExt
    {
        public const int AEAD_CCM = 1;
        public const int AEAD_CHACHA20_POLY1305 = 2;
        public const int AEAD_GCM = 3;

        private const int NONCE_RFC5288 = 1;
        private const int NONCE_RFC7905 = 2;
        private const long SequenceNumberPlaceholder = -1L;

        protected readonly TlsCryptoParameters m_cryptoParams;
        protected readonly int m_keySize;
        protected readonly int m_macSize;
        protected readonly int m_fixed_iv_length;
        protected readonly int m_record_iv_length;

        protected readonly TlsAeadCipherImpl m_decryptCipher, m_encryptCipher;
        protected readonly byte[] m_decryptNonce, m_encryptNonce;
        protected readonly byte[] m_decryptConnectionID, m_encryptConnectionID;
        protected readonly bool m_decryptUseInnerPlaintext, m_encryptUseInnerPlaintext;

        protected readonly bool m_isTlsV13;
        protected readonly int m_nonceMode;

        /// <exception cref="IOException"/>
        public TlsAeadCipher(TlsCryptoParameters cryptoParams, TlsAeadCipherImpl encryptCipher,
            TlsAeadCipherImpl decryptCipher, int keySize, int macSize, int aeadType)
        {
            SecurityParameters securityParameters = cryptoParams.SecurityParameters;
            ProtocolVersion negotiatedVersion = securityParameters.NegotiatedVersion;

            if (!TlsImplUtilities.IsTlsV12(negotiatedVersion))
                throw new TlsFatalAlert(AlertDescription.internal_error);

            this.m_isTlsV13 = TlsImplUtilities.IsTlsV13(negotiatedVersion);
            this.m_nonceMode = GetNonceMode(m_isTlsV13, aeadType);

            m_decryptConnectionID = securityParameters.ConnectionIDPeer;
            m_encryptConnectionID = securityParameters.ConnectionIDLocal;

            m_decryptUseInnerPlaintext = m_isTlsV13 || !Arrays.IsNullOrEmpty(m_decryptConnectionID);
            m_encryptUseInnerPlaintext = m_isTlsV13 || !Arrays.IsNullOrEmpty(m_encryptConnectionID);

            switch (m_nonceMode)
            {
            case NONCE_RFC5288:
                this.m_fixed_iv_length = 4;
                this.m_record_iv_length = 8;
                break;
            case NONCE_RFC7905:
                this.m_fixed_iv_length = 12;
                this.m_record_iv_length = 0;
                break;
            default:
                throw new TlsFatalAlert(AlertDescription.internal_error);
            }

            this.m_cryptoParams = cryptoParams;
            this.m_keySize = keySize;
            this.m_macSize = macSize;

            this.m_decryptCipher = decryptCipher;
            this.m_encryptCipher = encryptCipher;

            this.m_decryptNonce = new byte[m_fixed_iv_length];
            this.m_encryptNonce = new byte[m_fixed_iv_length];

            bool isServer = cryptoParams.IsServer;
            if (m_isTlsV13)
            {
                RekeyCipher(securityParameters, decryptCipher, m_decryptNonce, !isServer);
                RekeyCipher(securityParameters, encryptCipher, m_encryptNonce, isServer);
                return;
            }

            int keyBlockSize = (2 * keySize) + (2 * m_fixed_iv_length);

#if NETCOREAPP2_1_OR_GREATER || NETSTANDARD2_1_OR_GREATER
            Span<byte> keyBlock = keyBlockSize <= 512
                ? stackalloc byte[keyBlockSize]
                : new byte[keyBlockSize];
            TlsImplUtilities.CalculateKeyBlock(cryptoParams, keyBlock);

            if (isServer)
            {
                decryptCipher.SetKey(keyBlock[..keySize]); keyBlock = keyBlock[keySize..];
                encryptCipher.SetKey(keyBlock[..keySize]); keyBlock = keyBlock[keySize..];

                keyBlock[..m_fixed_iv_length].CopyTo(m_decryptNonce); keyBlock = keyBlock[m_fixed_iv_length..];
                keyBlock[..m_fixed_iv_length].CopyTo(m_encryptNonce); keyBlock = keyBlock[m_fixed_iv_length..];
            }
            else
            {
                encryptCipher.SetKey(keyBlock[..keySize]); keyBlock = keyBlock[keySize..];
                decryptCipher.SetKey(keyBlock[..keySize]); keyBlock = keyBlock[keySize..];

                keyBlock[..m_fixed_iv_length].CopyTo(m_encryptNonce); keyBlock = keyBlock[m_fixed_iv_length..];
                keyBlock[..m_fixed_iv_length].CopyTo(m_decryptNonce); keyBlock = keyBlock[m_fixed_iv_length..];
            }

            if (!keyBlock.IsEmpty)
                throw new TlsFatalAlert(AlertDescription.internal_error);
#else
            byte[] keyBlock = TlsImplUtilities.CalculateKeyBlock(cryptoParams, keyBlockSize);
            int pos = 0;

            if (isServer)
            {
                decryptCipher.SetKey(keyBlock, pos, keySize); pos += keySize;
                encryptCipher.SetKey(keyBlock, pos, keySize); pos += keySize;

                Array.Copy(keyBlock, pos, m_decryptNonce, 0, m_fixed_iv_length); pos += m_fixed_iv_length;
                Array.Copy(keyBlock, pos, m_encryptNonce, 0, m_fixed_iv_length); pos += m_fixed_iv_length;
            }
            else
            {
                encryptCipher.SetKey(keyBlock, pos, keySize); pos += keySize;
                decryptCipher.SetKey(keyBlock, pos, keySize); pos += keySize;

                Array.Copy(keyBlock, pos, m_encryptNonce, 0, m_fixed_iv_length); pos += m_fixed_iv_length;
                Array.Copy(keyBlock, pos, m_decryptNonce, 0, m_fixed_iv_length); pos += m_fixed_iv_length;
            }

            if (pos != keyBlockSize)
                throw new TlsFatalAlert(AlertDescription.internal_error);
#endif
        }

        public virtual int GetCiphertextDecodeLimit(int plaintextLimit)
        {
            int innerPlaintextLimit = plaintextLimit + (m_decryptUseInnerPlaintext ? 1 : 0);

            return innerPlaintextLimit + m_macSize + m_record_iv_length;
        }

        public virtual int GetCiphertextEncodeLimit(int plaintextLength, int plaintextLimit)
        {
            plaintextLimit = System.Math.Min(plaintextLength, plaintextLimit);

            int innerPlaintextLimit = plaintextLimit + (m_encryptUseInnerPlaintext ? 1 : 0);

            return innerPlaintextLimit + m_macSize + m_record_iv_length;
        }

        // TODO[api] Remove
        public virtual int GetPlaintextLimit(int ciphertextLimit)
        {
            return GetPlaintextEncodeLimit(ciphertextLimit);
        }

        public virtual int GetPlaintextDecodeLimit(int ciphertextLimit)
        {
            int innerPlaintextLimit = ciphertextLimit - m_macSize - m_record_iv_length;

            return innerPlaintextLimit - (m_decryptUseInnerPlaintext ? 1 : 0);
        }

        public virtual int GetPlaintextEncodeLimit(int ciphertextLimit)
        {
            int innerPlaintextLimit = ciphertextLimit - m_macSize - m_record_iv_length;

            return innerPlaintextLimit - (m_encryptUseInnerPlaintext ? 1 : 0);
        }

        public virtual TlsEncodeResult EncodePlaintext(long seqNo, short contentType, ProtocolVersion recordVersion,
            int headerAllocation, byte[] plaintext, int plaintextOffset, int plaintextLength)
        {
#if NETCOREAPP2_1_OR_GREATER || NETSTANDARD2_1_OR_GREATER
            return EncodePlaintext(seqNo, contentType, recordVersion, headerAllocation,
                plaintext.AsSpan(plaintextOffset, plaintextLength));
#else
            byte[] nonce = new byte[m_encryptNonce.Length + m_record_iv_length];

            switch (m_nonceMode)
            {
            case NONCE_RFC5288:
                Array.Copy(m_encryptNonce, 0, nonce, 0, m_encryptNonce.Length);
                // RFC 5288/6655: The nonce_explicit MAY be the 64-bit sequence number.
                TlsUtilities.WriteUint64(seqNo, nonce, m_encryptNonce.Length);
                break;
            case NONCE_RFC7905:
                TlsUtilities.WriteUint64(seqNo, nonce, nonce.Length - 8);
                for (int i = 0; i < m_encryptNonce.Length; ++i)
                {
                    nonce[i] ^= m_encryptNonce[i];
                }
                break;
            default:
                throw new TlsFatalAlert(AlertDescription.internal_error);
            }

            // TODO[tls13, cid] If we support adding padding to (D)TLSInnerPlaintext, this will need review
            int innerPlaintextLength = plaintextLength + (m_encryptUseInnerPlaintext ? 1 : 0);

            m_encryptCipher.Init(nonce, m_macSize, null);

            int encryptionLength = m_encryptCipher.GetOutputSize(innerPlaintextLength);
            int ciphertextLength = m_record_iv_length + encryptionLength;

            byte[] output = new byte[headerAllocation + ciphertextLength];
            int outputPos = headerAllocation;

            if (m_record_iv_length != 0)
            {
                Array.Copy(nonce, nonce.Length - m_record_iv_length, output, outputPos, m_record_iv_length);
                outputPos += m_record_iv_length;
            }

            short recordType = contentType;
            if (m_encryptUseInnerPlaintext)
            {
                recordType = m_isTlsV13 ? ContentType.application_data : ContentType.tls12_cid;
            }

            byte[] additionalData = GetAdditionalData(seqNo, recordType, recordVersion, ciphertextLength,
                innerPlaintextLength, m_encryptConnectionID);

            try
            {
                Array.Copy(plaintext, plaintextOffset, output, outputPos, plaintextLength);
                if (m_encryptUseInnerPlaintext)
                {
                    output[outputPos + plaintextLength] = (byte)contentType;
                }

                outputPos += m_encryptCipher.DoFinal(additionalData, output, outputPos, innerPlaintextLength, output,
                    outputPos);
            }
            catch (IOException)
            {
                throw;
            }
            catch (Exception e)
            {
                throw new TlsFatalAlert(AlertDescription.internal_error, e);
            }

            if (outputPos != output.Length)
            {
                // NOTE: The additional data mechanism for AEAD ciphers requires exact output size prediction.
                throw new TlsFatalAlert(AlertDescription.internal_error);
            }

            return new TlsEncodeResult(output, 0, output.Length, recordType);
#endif
        }

#if NETCOREAPP2_1_OR_GREATER || NETSTANDARD2_1_OR_GREATER
        public virtual TlsEncodeResult EncodePlaintext(long seqNo, short contentType, ProtocolVersion recordVersion,
            int headerAllocation, ReadOnlySpan<byte> plaintext)
        {
            byte[] nonce = new byte[m_encryptNonce.Length + m_record_iv_length];

            switch (m_nonceMode)
            {
            case NONCE_RFC5288:
                Array.Copy(m_encryptNonce, 0, nonce, 0, m_encryptNonce.Length);
                // RFC 5288/6655: The nonce_explicit MAY be the 64-bit sequence number.
                TlsUtilities.WriteUint64(seqNo, nonce, m_encryptNonce.Length);
                break;
            case NONCE_RFC7905:
                TlsUtilities.WriteUint64(seqNo, nonce, nonce.Length - 8);
                for (int i = 0; i < m_encryptNonce.Length; ++i)
                {
                    nonce[i] ^= m_encryptNonce[i];
                }
                break;
            default:
                throw new TlsFatalAlert(AlertDescription.internal_error);
            }

            // TODO[tls13, cid] If we support adding padding to (D)TLSInnerPlaintext, this will need review
            int innerPlaintextLength = plaintext.Length + (m_encryptUseInnerPlaintext ? 1 : 0);

            m_encryptCipher.Init(nonce, m_macSize, null);

            int encryptionLength = m_encryptCipher.GetOutputSize(innerPlaintextLength);
            int ciphertextLength = m_record_iv_length + encryptionLength;

            byte[] output = new byte[headerAllocation + ciphertextLength];
            int outputPos = headerAllocation;

            if (m_record_iv_length != 0)
            {
                Array.Copy(nonce, nonce.Length - m_record_iv_length, output, outputPos, m_record_iv_length);
                outputPos += m_record_iv_length;
            }

            short recordType = contentType;
            if (m_encryptUseInnerPlaintext)
            {
                recordType = m_isTlsV13 ? ContentType.application_data : ContentType.tls12_cid;
            }

            byte[] additionalData = GetAdditionalData(seqNo, recordType, recordVersion, ciphertextLength,
                innerPlaintextLength, m_encryptConnectionID);

            try
            {
                plaintext.CopyTo(output.AsSpan(outputPos));
                if (m_encryptUseInnerPlaintext)
                {
                    output[outputPos + plaintext.Length] = (byte)contentType;
                }

                outputPos += m_encryptCipher.DoFinal(additionalData, output, outputPos, innerPlaintextLength, output,
                    outputPos);
            }
            catch (IOException)
            {
                throw;
            }
            catch (Exception e)
            {
                throw new TlsFatalAlert(AlertDescription.internal_error, e);
            }

            if (outputPos != output.Length)
            {
                // NOTE: The additional data mechanism for AEAD ciphers requires exact output size prediction.
                throw new TlsFatalAlert(AlertDescription.internal_error);
            }

            return new TlsEncodeResult(output, 0, output.Length, recordType);
        }
#endif

        public virtual TlsDecodeResult DecodeCiphertext(long seqNo, short recordType, ProtocolVersion recordVersion,
            byte[] ciphertext, int ciphertextOffset, int ciphertextLength)
        {
            if (GetPlaintextDecodeLimit(ciphertextLength) < 0)
                throw new TlsFatalAlert(AlertDescription.decode_error);

            byte[] nonce = new byte[m_decryptNonce.Length + m_record_iv_length];

            switch (m_nonceMode)
            {
            case NONCE_RFC5288:
                Array.Copy(m_decryptNonce, 0, nonce, 0, m_decryptNonce.Length);
                Array.Copy(ciphertext, ciphertextOffset, nonce, nonce.Length - m_record_iv_length,
                    m_record_iv_length);
                break;
            case NONCE_RFC7905:
                TlsUtilities.WriteUint64(seqNo, nonce, nonce.Length - 8);
                for (int i = 0; i < m_decryptNonce.Length; ++i)
                {
                    nonce[i] ^= m_decryptNonce[i];
                }
                break;
            default:
                throw new TlsFatalAlert(AlertDescription.internal_error);
            }

            m_decryptCipher.Init(nonce, m_macSize, null);

            int encryptionOffset = ciphertextOffset + m_record_iv_length;
            int encryptionLength = ciphertextLength - m_record_iv_length;
            int innerPlaintextLength = m_decryptCipher.GetOutputSize(encryptionLength);

            byte[] additionalData = GetAdditionalData(seqNo, recordType, recordVersion, ciphertextLength,
                innerPlaintextLength, m_decryptConnectionID);

            int outputPos;
            try
            {
                outputPos = m_decryptCipher.DoFinal(additionalData, ciphertext, encryptionOffset, encryptionLength,
                    ciphertext, encryptionOffset);
            }
            catch (IOException)
            {
                throw;
            }
            catch (Exception e)
            {
                throw new TlsFatalAlert(AlertDescription.bad_record_mac, e);
            }

            if (outputPos != innerPlaintextLength)
            {
                // NOTE: The additional data mechanism for AEAD ciphers requires exact output size prediction.
                throw new TlsFatalAlert(AlertDescription.internal_error);
            }

            short contentType = recordType;
            int plaintextLength = innerPlaintextLength;

            if (m_decryptUseInnerPlaintext)
            {
                // Strip padding and read true content type from TLSInnerPlaintext
                for (;;)
                {
                    if (--plaintextLength < 0)
                        throw new TlsFatalAlert(AlertDescription.unexpected_message);

                    byte octet = ciphertext[encryptionOffset + plaintextLength];
                    if (0 != octet)
                    {
                        contentType = (short)(octet & 0xFF);
                        break;
                    }
                }
            }

            return new TlsDecodeResult(ciphertext, encryptionOffset, plaintextLength, contentType);
        }

        public virtual void RekeyDecoder()
        {
            RekeyCipher(m_cryptoParams.SecurityParameters, m_decryptCipher, m_decryptNonce, !m_cryptoParams.IsServer);
        }

        public virtual void RekeyEncoder()
        {
            RekeyCipher(m_cryptoParams.SecurityParameters, m_encryptCipher, m_encryptNonce, m_cryptoParams.IsServer);
        }

        public virtual bool UsesOpaqueRecordType
        {
            get { return m_isTlsV13; }
        }

        protected virtual byte[] GetAdditionalData(long seqNo, short recordType, ProtocolVersion recordVersion,
            int ciphertextLength, int plaintextLength)
        {
            if (m_isTlsV13)
            {
                /*
                 * TLSCiphertext.opaque_type || TLSCiphertext.legacy_record_version || TLSCiphertext.length
                 */
                byte[] additional_data = new byte[5];
                TlsUtilities.WriteUint8(recordType, additional_data, 0);
                TlsUtilities.WriteVersion(recordVersion, additional_data, 1);
                TlsUtilities.WriteUint16(ciphertextLength, additional_data, 3);
                return additional_data;
            }
            else
            {
                /*
                 * seq_num + TLSCompressed.type + TLSCompressed.version + TLSCompressed.length
                 */
                byte[] additional_data = new byte[13];
                TlsUtilities.WriteUint64(seqNo, additional_data, 0);
                TlsUtilities.WriteUint8(recordType, additional_data, 8);
                TlsUtilities.WriteVersion(recordVersion, additional_data, 9);
                TlsUtilities.WriteUint16(plaintextLength, additional_data, 11);
                return additional_data;
            }
        }

        protected virtual byte[] GetAdditionalData(long seqNo, short recordType, ProtocolVersion recordVersion,
            int ciphertextLength, int plaintextLength, byte[] connectionID)
        {
            if (Arrays.IsNullOrEmpty(connectionID))
                return GetAdditionalData(seqNo, recordType, recordVersion, ciphertextLength, plaintextLength);

            /*
             * seq_num_placeholder + tls12_cid + cid_length + tls12_cid + DTLSCiphertext.version + epoch
             *     + sequence_number + cid + length_of_DTLSInnerPlaintext
             */
            int cidLength = connectionID.Length;
            byte[] additional_data = new byte[23 + cidLength];
            TlsUtilities.WriteUint64(SequenceNumberPlaceholder, additional_data, 0);
            TlsUtilities.WriteUint8(ContentType.tls12_cid, additional_data, 8);
            TlsUtilities.WriteUint8(cidLength, additional_data, 9);
            TlsUtilities.WriteUint8(ContentType.tls12_cid, additional_data, 10);
            TlsUtilities.WriteVersion(recordVersion, additional_data, 11);
            TlsUtilities.WriteUint64(seqNo, additional_data, 13);
            Array.Copy(connectionID, 0, additional_data, 21, cidLength);
            TlsUtilities.WriteUint16(plaintextLength, additional_data, 21 + cidLength);
            return additional_data;
        }

        protected virtual void RekeyCipher(SecurityParameters securityParameters, TlsAeadCipherImpl cipher,
            byte[] nonce, bool serverSecret)
        {
            if (!m_isTlsV13)
                throw new TlsFatalAlert(AlertDescription.internal_error);

            TlsSecret secret = serverSecret
                ?   securityParameters.TrafficSecretServer
                :   securityParameters.TrafficSecretClient;

            // TODO[tls13] For early data, have to disable server->client
            if (null == secret)
                throw new TlsFatalAlert(AlertDescription.internal_error);

            Setup13Cipher(cipher, nonce, secret, securityParameters.PrfCryptoHashAlgorithm);
        }

        protected virtual void Setup13Cipher(TlsAeadCipherImpl cipher, byte[] nonce, TlsSecret secret,
            int cryptoHashAlgorithm)
        {
            byte[] key = TlsCryptoUtilities.HkdfExpandLabel(secret, cryptoHashAlgorithm, "key",
                TlsUtilities.EmptyBytes, m_keySize).Extract();
            byte[] iv = TlsCryptoUtilities.HkdfExpandLabel(secret, cryptoHashAlgorithm, "iv", TlsUtilities.EmptyBytes,
                m_fixed_iv_length).Extract();

            cipher.SetKey(key, 0, m_keySize);
            Array.Copy(iv, 0, nonce, 0, m_fixed_iv_length);
        }

        private static int GetNonceMode(bool isTLSv13, int aeadType)
        {
            switch (aeadType)
            {
            case AEAD_CCM:
            case AEAD_GCM:
                return isTLSv13 ? NONCE_RFC7905 : NONCE_RFC5288;

            case AEAD_CHACHA20_POLY1305:
                return NONCE_RFC7905;

            default:
                throw new TlsFatalAlert(AlertDescription.internal_error);
            }
        }
    }
}
