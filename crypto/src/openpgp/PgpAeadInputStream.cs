using System;
using System.IO;

using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Crypto.Modes;
using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.Crypto.Utilities;
using Org.BouncyCastle.Utilities;
using Org.BouncyCastle.Utilities.IO;

namespace Org.BouncyCastle.Bcpg.OpenPgp
{
    /// <summary>
    /// Decrypting stream for the chunked AEAD encoding of a v2 SEIPD packet (RFC 9580 5.13.2).
    /// </summary>
    /// <remarks>
    /// One chunk at a time is decrypted and authenticated before any of its plaintext is released. The last chunk is
    /// only released after the final authentication tag, which covers the total length of the plaintext, has been
    /// verified. Any failure is reported with a <see cref="PgpDataValidationException"/>, and the stream stays failed.
    /// </remarks>
    internal sealed class PgpAeadInputStream
        : BaseInputStream
    {
        private readonly Stream m_input;
        private readonly SymmetricKeyAlgorithmTag m_symmetricAlgorithm;
        private readonly AeadAlgorithmTag m_aeadAlgorithm;
        private readonly byte[] m_keyBytes;
        private readonly byte[] m_iv;
        private readonly byte[] m_aad;
        private readonly int m_chunkLength;

        private readonly byte[] m_nonce;
        private readonly byte[] m_ciphertext;   // up to a chunk with its tag, and the next 16 octets
        private readonly byte[] m_plaintext;

        private int m_ciphertextLength;
        private int m_plaintextPos, m_plaintextEnd;
        private long m_chunkIndex;
        private long m_totalPlaintext;
        private bool m_finished;
        private bool m_failed;

        /// <param name="input">The stream of the chunked data, i.e. the body of the SEIPD packet after the salt.</param>
        /// <param name="messageKey">The message key (the stream keeps a copy and wipes it when disposed).</param>
        /// <param name="iv">The initialization vector, a nonce whose last 8 octets are not used.</param>
        /// <param name="aad">The associated data (header) of the SEIPD packet.</param>
        internal PgpAeadInputStream(Stream input, SymmetricKeyAlgorithmTag symmetricAlgorithm,
            AeadAlgorithmTag aeadAlgorithm, byte[] messageKey, byte[] iv, byte[] aad, int chunkSizeOctet)
        {
            m_input = input;
            m_symmetricAlgorithm = symmetricAlgorithm;
            m_aeadAlgorithm = aeadAlgorithm;
            m_keyBytes = Arrays.Clone(messageKey);
            m_iv = Arrays.Clone(iv);
            m_aad = Arrays.Clone(aad);
            m_chunkLength = PgpAead.GetChunkLength(chunkSizeOctet);

            m_nonce = new byte[m_iv.Length];
            m_ciphertext = new byte[m_chunkLength + 2 * PgpAead.TagLength];
            m_plaintext = new byte[m_chunkLength];
        }

        /// <summary>Whether the whole message has been read and its final authentication tag verified.</summary>
        internal bool IsVerified => m_finished && !m_failed;

        public override int ReadByte()
        {
            if (!EnsurePlaintext())
                return -1;

            return m_plaintext[m_plaintextPos++];
        }

        public override int Read(byte[] buffer, int offset, int count)
        {
            Streams.ValidateBufferArguments(buffer, offset, count);

            if (count < 1)
                return 0;

            if (!EnsurePlaintext())
                return 0;

            int length = System.Math.Min(count, m_plaintextEnd - m_plaintextPos);
            Array.Copy(m_plaintext, m_plaintextPos, buffer, offset, length);
            m_plaintextPos += length;
            return length;
        }

#if NETCOREAPP2_1_OR_GREATER || NETSTANDARD2_1_OR_GREATER
        public override int Read(Span<byte> buffer)
        {
            if (buffer.IsEmpty)
                return 0;

            if (!EnsurePlaintext())
                return 0;

            int length = System.Math.Min(buffer.Length, m_plaintextEnd - m_plaintextPos);
            m_plaintext.AsSpan(m_plaintextPos, length).CopyTo(buffer);
            m_plaintextPos += length;
            return length;
        }
#endif

        /// <summary>Make sure that there is unread plaintext, unless the end of the data has been reached.</summary>
        private bool EnsurePlaintext()
        {
            if (m_failed)
                throw new PgpDataValidationException("AEAD data failed validation");

            while (m_plaintextPos >= m_plaintextEnd)
            {
                if (m_finished)
                    return false;

                try
                {
                    ProcessNextChunk();
                }
                catch (PgpDataValidationException)
                {
                    Fail();
                    throw;
                }
                catch (EndOfStreamException e)
                {
                    // a packet that ends early; callers that read packets treat this exception as a clean end
                    Fail();
                    throw new PgpDataValidationException("AEAD data is truncated", e);
                }
                catch (Exception e)
                {
                    Fail();
                    if (e is IOException)
                        throw;
                    throw new PgpDataValidationException("AEAD data failed validation", e);
                }
            }

            return true;
        }

        private void Fail()
        {
            m_failed = true;
            m_plaintextPos = m_plaintextEnd = 0;
            Arrays.ZeroMemory(m_plaintext);
            Arrays.ZeroMemory(m_ciphertext);
            m_ciphertextLength = 0;
        }

        private void ProcessNextChunk()
        {
            int capacity = m_ciphertext.Length;

            m_ciphertextLength += Streams.ReadFully(m_input, m_ciphertext, m_ciphertextLength,
                capacity - m_ciphertextLength);

            if (m_ciphertextLength == capacity)
            {
                // A full chunk, with the 16 octets that follow it: either the final tag or the next chunk's start
                DecryptChunk(m_chunkLength + PgpAead.TagLength);

                Array.Copy(m_ciphertext, m_chunkLength + PgpAead.TagLength, m_ciphertext, 0, PgpAead.TagLength);
                m_ciphertextLength = PgpAead.TagLength;
                return;
            }

            // The end of the data: [last chunk with tag] final tag
            int remaining = m_ciphertextLength;
            if (remaining < PgpAead.TagLength)
                throw new PgpDataValidationException("AEAD data is truncated: no final authentication tag");

            if (remaining == PgpAead.TagLength)
            {
                m_plaintextPos = m_plaintextEnd = 0;
            }
            else if (remaining < 2 * PgpAead.TagLength)
            {
                throw new PgpDataValidationException("AEAD data is malformed: incomplete last chunk");
            }
            else
            {
                DecryptChunk(remaining - PgpAead.TagLength);
            }

            VerifyFinalTag(remaining - PgpAead.TagLength);

            m_finished = true;
            Arrays.ZeroMemory(m_ciphertext);
            m_ciphertextLength = 0;
        }

        private void DecryptChunk(int length)
        {
            CreateNonce(m_chunkIndex);

            IAeadCipher cipher = PgpAead.CreateCipher(m_symmetricAlgorithm, m_aeadAlgorithm);
            cipher.Init(false, new AeadParameters(new KeyParameter(m_keyBytes), PgpAead.TagLength * 8, m_nonce, m_aad));

            int output = cipher.ProcessBytes(m_ciphertext, 0, length, m_plaintext, 0);
            output += cipher.DoFinal(m_plaintext, output);

            ++m_chunkIndex;
            m_totalPlaintext += output;
            m_plaintextPos = 0;
            m_plaintextEnd = output;
        }

        private void VerifyFinalTag(int tagOffset)
        {
            CreateNonce(m_chunkIndex);

            byte[] aad = new byte[m_aad.Length + 8];
            Array.Copy(m_aad, aad, m_aad.Length);
            Pack.UInt64_To_BE((ulong)m_totalPlaintext, aad, m_aad.Length);

            IAeadCipher cipher = PgpAead.CreateCipher(m_symmetricAlgorithm, m_aeadAlgorithm);
            cipher.Init(false, new AeadParameters(new KeyParameter(m_keyBytes), PgpAead.TagLength * 8, m_nonce, aad));

            byte[] unused = new byte[cipher.GetOutputSize(PgpAead.TagLength)];
            int output = cipher.ProcessBytes(m_ciphertext, tagOffset, PgpAead.TagLength, unused, 0);
            cipher.DoFinal(unused, output);
        }

        private void CreateNonce(long chunkIndex) => PgpAead.CreateNonce(m_iv, chunkIndex, m_nonce);

        protected override void Dispose(bool disposing)
        {
            if (disposing)
            {
                Arrays.ZeroMemory(m_keyBytes);
                Arrays.ZeroMemory(m_plaintext);
                Arrays.ZeroMemory(m_ciphertext);
                m_input.Dispose();
            }
            base.Dispose(disposing);
        }
    }
}
