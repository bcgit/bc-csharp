using System;
using System.IO;

using Org.BouncyCastle.Crypto.Modes;
using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.Crypto.Utilities;
using Org.BouncyCastle.Utilities;
using Org.BouncyCastle.Utilities.IO;

namespace Org.BouncyCastle.Bcpg.OpenPgp
{
    /// <summary>
    /// Encrypting stream for the chunked AEAD encoding of a v2 SEIPD packet (RFC 9580 5.13.2).
    /// </summary>
    /// <remarks>
    /// Plaintext is buffered until a chunk is full, then written as the encrypted chunk with its tag.
    /// <see cref="Finish"/> writes the last, partial chunk (if there is any plaintext left) and the final tag, which
    /// covers the total length of the plaintext. An empty chunk is never written.
    /// </remarks>
    internal sealed class PgpAeadOutputStream
        : BaseOutputStream
    {
        private readonly Stream m_output;
        private readonly SymmetricKeyAlgorithmTag m_symmetricAlgorithm;
        private readonly AeadAlgorithmTag m_aeadAlgorithm;
        private readonly byte[] m_keyBytes;
        private readonly byte[] m_iv;
        private readonly byte[] m_aad;
        private readonly int m_chunkLength;

        private readonly byte[] m_nonce;
        private readonly byte[] m_plaintext;

        private int m_plaintextLength;
        private long m_chunkIndex;
        private long m_totalPlaintext;
        private bool m_finished;

        /// <param name="output">The stream to write the encrypted chunks to.</param>
        /// <param name="messageKey">The message key (the stream keeps a copy and wipes it when finished).</param>
        /// <param name="iv">The initialization vector, a nonce whose last 8 octets are not used.</param>
        /// <param name="aad">The associated data (header) of the SEIPD packet.</param>
        internal PgpAeadOutputStream(Stream output, SymmetricKeyAlgorithmTag symmetricAlgorithm,
            AeadAlgorithmTag aeadAlgorithm, byte[] messageKey, byte[] iv, byte[] aad, int chunkSizeOctet)
        {
            m_output = output;
            m_symmetricAlgorithm = symmetricAlgorithm;
            m_aeadAlgorithm = aeadAlgorithm;
            m_keyBytes = Arrays.Clone(messageKey);
            m_iv = Arrays.Clone(iv);
            m_aad = Arrays.Clone(aad);
            m_chunkLength = PgpAead.GetChunkLength(chunkSizeOctet);

            m_nonce = new byte[m_iv.Length];
            m_plaintext = new byte[m_chunkLength];
        }

        public override void WriteByte(byte value)
        {
            if (m_finished)
                throw new InvalidOperationException("stream already finished");

            m_plaintext[m_plaintextLength++] = value;
            if (m_plaintextLength == m_chunkLength)
            {
                EncryptChunk();
            }
        }

        public override void Write(byte[] buffer, int offset, int count)
        {
            Streams.ValidateBufferArguments(buffer, offset, count);

            if (m_finished)
                throw new InvalidOperationException("stream already finished");

            while (count > 0)
            {
                int length = System.Math.Min(count, m_chunkLength - m_plaintextLength);
                Array.Copy(buffer, offset, m_plaintext, m_plaintextLength, length);
                m_plaintextLength += length;
                offset += length;
                count -= length;

                if (m_plaintextLength == m_chunkLength)
                {
                    EncryptChunk();
                }
            }
        }

#if NETCOREAPP2_1_OR_GREATER || NETSTANDARD2_1_OR_GREATER
        public override void Write(ReadOnlySpan<byte> buffer)
        {
            if (m_finished)
                throw new InvalidOperationException("stream already finished");

            while (!buffer.IsEmpty)
            {
                int length = System.Math.Min(buffer.Length, m_chunkLength - m_plaintextLength);
                buffer[..length].CopyTo(m_plaintext.AsSpan(m_plaintextLength));
                m_plaintextLength += length;
                buffer = buffer[length..];

                if (m_plaintextLength == m_chunkLength)
                {
                    EncryptChunk();
                }
            }
        }
#endif

        /// <summary>Write the last chunk and the final authentication tag, and wipe the key material.</summary>
        internal void Finish()
        {
            if (m_finished)
                return;

            m_finished = true;

            try
            {
                if (m_plaintextLength > 0)
                {
                    EncryptChunk();
                }

                WriteFinalTag();
            }
            finally
            {
                Arrays.ZeroMemory(m_keyBytes);
                Arrays.ZeroMemory(m_plaintext);
            }
        }

        private void EncryptChunk()
        {
            PgpAead.CreateNonce(m_iv, m_chunkIndex, m_nonce);

            IAeadCipher cipher = PgpAead.CreateCipher(m_symmetricAlgorithm, m_aeadAlgorithm);
            cipher.Init(true, new AeadParameters(new KeyParameter(m_keyBytes), PgpAead.TagLength * 8, m_nonce, m_aad));

            byte[] output = new byte[cipher.GetOutputSize(m_plaintextLength)];
            int length = cipher.ProcessBytes(m_plaintext, 0, m_plaintextLength, output, 0);
            length += cipher.DoFinal(output, length);

            m_output.Write(output, 0, length);

            ++m_chunkIndex;
            m_totalPlaintext += m_plaintextLength;
            m_plaintextLength = 0;
        }

        private void WriteFinalTag()
        {
            PgpAead.CreateNonce(m_iv, m_chunkIndex, m_nonce);

            byte[] aad = new byte[m_aad.Length + 8];
            Array.Copy(m_aad, aad, m_aad.Length);
            Pack.UInt64_To_BE((ulong)m_totalPlaintext, aad, m_aad.Length);

            IAeadCipher cipher = PgpAead.CreateCipher(m_symmetricAlgorithm, m_aeadAlgorithm);
            cipher.Init(true, new AeadParameters(new KeyParameter(m_keyBytes), PgpAead.TagLength * 8, m_nonce, aad));

            byte[] tag = new byte[cipher.GetOutputSize(0)];
            int length = cipher.DoFinal(tag, 0);

            m_output.Write(tag, 0, length);
        }
    }
}
