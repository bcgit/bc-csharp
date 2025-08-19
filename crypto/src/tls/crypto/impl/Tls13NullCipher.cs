using System;
using System.IO;

using Org.BouncyCastle.Utilities;

namespace Org.BouncyCastle.Tls.Crypto.Impl
{
    /// <summary>A generic TLS 1.3 "integrity-only" cipher.</summary>
    public sealed class Tls13NullCipher
        : TlsCipher, TlsCipherExt
    {
        // TODO[dtls13] Handle connection IDs

        private readonly TlsCryptoParameters m_cryptoParams;

        private readonly TlsHmac m_readHmac, m_writeHmac;
        private readonly byte[] m_readNonce, m_writeNonce;

        /// <exception cref="IOException"/>
        public Tls13NullCipher(TlsCryptoParameters cryptoParams, TlsHmac readHmac, TlsHmac writeHmac)
        {
            if (!TlsImplUtilities.IsTlsV13(cryptoParams))
                throw new TlsFatalAlert(AlertDescription.internal_error);

            m_cryptoParams = cryptoParams;
            m_readHmac = readHmac;
            m_writeHmac = writeHmac;

            m_readNonce = new byte[m_readHmac.MacLength];
            m_writeNonce = new byte[m_writeHmac.MacLength];

            RekeyDecoder();
            RekeyEncoder();
        }

        public int GetCiphertextDecodeLimit(int plaintextLimit) => plaintextLimit + 1 + m_readHmac.MacLength;

        public int GetCiphertextEncodeLimit(int plaintextLength, int plaintextLimit) =>
            System.Math.Min(plaintextLength, plaintextLimit) + 1 + m_writeHmac.MacLength;

        // TODO[api] Remove
        public int GetPlaintextLimit(int ciphertextLimit) => GetPlaintextEncodeLimit(ciphertextLimit);

        public int GetPlaintextDecodeLimit(int ciphertextLimit) => ciphertextLimit - m_readHmac.MacLength - 1;

        public int GetPlaintextEncodeLimit(int ciphertextLimit) => ciphertextLimit - m_writeHmac.MacLength - 1;

        public TlsEncodeResult EncodePlaintext(long seqNo, short contentType, ProtocolVersion recordVersion,
            int headerAllocation, byte[] plaintext, int plaintextOffset, int plaintextLength)
        {
#if NETCOREAPP2_1_OR_GREATER || NETSTANDARD2_1_OR_GREATER
            return EncodePlaintext(seqNo, contentType, recordVersion, headerAllocation,
                plaintext.AsSpan(plaintextOffset, plaintextLength));
#else
            int macLength = m_writeHmac.MacLength;

            // TODO Possibly redundant if we reset after any failures (i.e. DTLS)
            m_writeHmac.Reset();

            byte[] nonce = CreateRecordNonce(m_writeNonce, seqNo);
            m_writeHmac.Update(nonce, 0, nonce.Length);

            // TODO[tls13, cid] If we support adding padding to (D)TLSInnerPlaintext, this will need review
            int innerPlaintextLength = plaintextLength + 1;
            int ciphertextLength = innerPlaintextLength + macLength;
            byte[] output = new byte[headerAllocation + ciphertextLength];
            int outputPos = headerAllocation;

            short recordType = ContentType.application_data;

            byte[] additionalData = GetAdditionalData(seqNo, recordType, recordVersion, ciphertextLength);

            try
            {
                Array.Copy(plaintext, plaintextOffset, output, outputPos, plaintextLength);
                output[outputPos + plaintextLength] = (byte)contentType;

                m_writeHmac.Update(additionalData, 0, additionalData.Length);
                m_writeHmac.Update(output, outputPos, innerPlaintextLength);
                m_writeHmac.CalculateMac(output, outputPos + innerPlaintextLength);
                outputPos += innerPlaintextLength + macLength;
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
                throw new TlsFatalAlert(AlertDescription.internal_error);

            return new TlsEncodeResult(output, 0, output.Length, recordType);
#endif
        }

#if NETCOREAPP2_1_OR_GREATER || NETSTANDARD2_1_OR_GREATER
        public TlsEncodeResult EncodePlaintext(long seqNo, short contentType, ProtocolVersion recordVersion,
            int headerAllocation, ReadOnlySpan<byte> plaintext)
        {
            int macLength = m_writeHmac.MacLength;

            // TODO Possibly redundant if we reset after any failures (i.e. DTLS)
            m_writeHmac.Reset();

            byte[] nonce = CreateRecordNonce(m_writeNonce, seqNo);
            m_writeHmac.Update(nonce);

            // TODO[tls13, cid] If we support adding padding to (D)TLSInnerPlaintext, this will need review
            int innerPlaintextLength = plaintext.Length + 1;
            int ciphertextLength = innerPlaintextLength + macLength;
            byte[] output = new byte[headerAllocation + ciphertextLength];

            short recordType = ContentType.application_data;

            byte[] additionalData = GetAdditionalData(seqNo, recordType, recordVersion, ciphertextLength);

            try
            {
                plaintext.CopyTo(output.AsSpan(headerAllocation));
                output[headerAllocation + plaintext.Length] = (byte)contentType;

                m_writeHmac.Update(additionalData);
                m_writeHmac.Update(output.AsSpan(headerAllocation, innerPlaintextLength));
                m_writeHmac.CalculateMac(output, headerAllocation + innerPlaintextLength);
            }
            catch (IOException)
            {
                throw;
            }
            catch (Exception e)
            {
                throw new TlsFatalAlert(AlertDescription.internal_error, e);
            }

            return new TlsEncodeResult(output, 0, output.Length, recordType);
        }
#endif

        public TlsDecodeResult DecodeCiphertext(long seqNo, short recordType, ProtocolVersion recordVersion,
            byte[] ciphertext, int ciphertextOffset, int ciphertextLength)
        {
            int macLength = m_readHmac.MacLength;

            int innerPlaintextLength = ciphertextLength - macLength;
            if (innerPlaintextLength < 1)
                throw new TlsFatalAlert(AlertDescription.decode_error);

            // TODO Possibly redundant if we reset after any failures (i.e. DTLS)
            m_readHmac.Reset();

            byte[] nonce = CreateRecordNonce(m_readNonce, seqNo);
            m_readHmac.Update(nonce, 0, nonce.Length);

            byte[] additionalData = GetAdditionalData(seqNo, recordType, recordVersion, ciphertextLength);

            try
            {
                m_readHmac.Update(additionalData, 0, additionalData.Length);
                m_readHmac.Update(ciphertext, ciphertextOffset, innerPlaintextLength);
                byte[] calculated = m_readHmac.CalculateMac();
                if (!Arrays.FixedTimeEquals(macLength, calculated, 0, ciphertext, ciphertextOffset + innerPlaintextLength))
                    throw new TlsFatalAlert(AlertDescription.bad_record_mac);
            }
            catch (IOException)
            {
                throw;
            }
            catch (Exception e)
            {
                throw new TlsFatalAlert(AlertDescription.bad_record_mac, e);
            }

            short contentType = recordType;
            int plaintextLength = innerPlaintextLength;

            // Strip padding and read true content type from TLSInnerPlaintext
            for (;;)
            {
                if (--plaintextLength < 0)
                    throw new TlsFatalAlert(AlertDescription.unexpected_message);

                byte octet = ciphertext[ciphertextOffset + plaintextLength];
                if (0 != octet)
                {
                    contentType = (short)(octet & 0xFF);
                    break;
                }
            }

            return new TlsDecodeResult(ciphertext, ciphertextOffset, plaintextLength, contentType);
        }

        public void RekeyDecoder() =>
            RekeyHmac(m_cryptoParams.SecurityParameters, m_readHmac, m_readNonce, !m_cryptoParams.IsServer);

        public void RekeyEncoder() =>
            RekeyHmac(m_cryptoParams.SecurityParameters, m_writeHmac, m_writeNonce, m_cryptoParams.IsServer);

        public bool UsesOpaqueRecordType => true;

        private void RekeyHmac(SecurityParameters securityParameters, TlsHmac hmac, byte[] nonce,
            bool serverSecret)
        {
            TlsSecret secret = serverSecret
                ? securityParameters.TrafficSecretServer
                : securityParameters.TrafficSecretClient;

            // TODO[tls13] For early data, have to disable server->client
            if (null == secret)
                throw new TlsFatalAlert(AlertDescription.internal_error);

            SetupHmac(hmac, nonce, secret, securityParameters.PrfCryptoHashAlgorithm);
        }

        private void SetupHmac(TlsHmac hmac, byte[] nonce, TlsSecret secret, int cryptoHashAlgorithm)
        {
            int length = hmac.MacLength;
            byte[] key = HkdfExpandLabel(secret, cryptoHashAlgorithm, "key", length).Extract();
            hmac.SetKey(key, 0, length);

#if NETCOREAPP2_1_OR_GREATER || NETSTANDARD2_1_OR_GREATER
            HkdfExpandLabel(secret, cryptoHashAlgorithm, "iv", length).ExtractTo(nonce);
#else
            byte[] iv = HkdfExpandLabel(secret, cryptoHashAlgorithm, "iv", length).Extract();
            Array.Copy(iv, 0, nonce, 0, length);
#endif
        }

        private static byte[] CreateRecordNonce(byte[] fixedNonce, long seqNo)
        {
            int nonceLength = fixedNonce.Length;
            byte[] nonce = new byte[nonceLength];
            TlsUtilities.WriteUint64(seqNo, nonce, nonceLength - 8);
            Bytes.XorTo(nonceLength, fixedNonce, nonce);
            return nonce;
        }

        private static byte[] GetAdditionalData(long seqNo, short recordType, ProtocolVersion recordVersion,
            int ciphertextLength)
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

        private static TlsSecret HkdfExpandLabel(TlsSecret secret, int cryptoHashAlgorithm, string label, int length) =>
            TlsCryptoUtilities.HkdfExpandLabel(secret, cryptoHashAlgorithm, label, TlsUtilities.EmptyBytes, length);
    }
}
