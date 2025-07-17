using System;
using System.Diagnostics;
using System.IO;

using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Crypto.IO;
using Org.BouncyCastle.Security;
using Org.BouncyCastle.Utilities;
using Org.BouncyCastle.Utilities.IO;

namespace Org.BouncyCastle.Bcpg.OpenPgp
{
    public abstract class PgpEncryptedData
    {
        internal class TruncatedStream
            : BaseInputStream
        {
            private const int LookAheadSize = 22;
            private const int LookAheadBufSize = 512;
            private const int LookAheadBufLimit = LookAheadBufSize - LookAheadSize;

            private readonly byte[] m_lookAhead = new byte[LookAheadBufSize];
            private readonly Stream m_inStr;
            private int m_bufStart, m_bufEnd;

            internal TruncatedStream(Stream inStr)
            {
                int numRead = Streams.ReadFully(inStr, m_lookAhead);
                if (numRead < LookAheadSize)
                    throw new EndOfStreamException();

                m_inStr = inStr;
                m_bufStart = 0;
                m_bufEnd = numRead - LookAheadSize;
            }

            private int FillBuffer()
            {
                if (m_bufEnd < LookAheadBufLimit)
                    return 0;

                Debug.Assert(m_bufStart == LookAheadBufLimit);
                Debug.Assert(m_bufEnd == LookAheadBufLimit);

                Array.Copy(m_lookAhead, LookAheadBufLimit, m_lookAhead, 0, LookAheadSize);
                m_bufEnd = Streams.ReadFully(m_inStr, m_lookAhead, LookAheadSize, LookAheadBufLimit);
                m_bufStart = 0;
                return m_bufEnd;
            }

            public override int Read(byte[] buffer, int offset, int count)
            {
                Streams.ValidateBufferArguments(buffer, offset, count);

#if NETCOREAPP2_1_OR_GREATER || NETSTANDARD2_1_OR_GREATER
                return Read(buffer.AsSpan(offset, count));
#else
                int avail = m_bufEnd - m_bufStart;

                int pos = offset;
                while (count > avail)
                {
                    Array.Copy(m_lookAhead, m_bufStart, buffer, pos, avail);

                    m_bufStart += avail;
                    pos += avail;
                    count -= avail;

                    if ((avail = FillBuffer()) < 1)
                        return pos - offset;
                }

                Array.Copy(m_lookAhead, m_bufStart, buffer, pos, count);
                m_bufStart += count;

                return pos + count - offset;
#endif
            }

#if NETCOREAPP2_1_OR_GREATER || NETSTANDARD2_1_OR_GREATER
            public override int Read(Span<byte> buffer)
            {
                int avail = m_bufEnd - m_bufStart;

                int pos = 0, count = buffer.Length;
                while (count > avail)
                {
                    m_lookAhead.AsSpan(m_bufStart, avail).CopyTo(buffer[pos..]);

                    m_bufStart += avail;
                    pos += avail;
                    count -= avail;

                    if ((avail = FillBuffer()) < 1)
                        return pos;
                }

                m_lookAhead.AsSpan(m_bufStart, count).CopyTo(buffer[pos..]);
                m_bufStart += count;

                return pos + count;
            }
#endif

            public override int ReadByte()
            {
                if (m_bufStart >= m_bufEnd && FillBuffer() < 1)
                    return -1;

                return m_lookAhead[m_bufStart++];
            }

            internal bool CheckMdc(IDigest digest)
            {
                byte[] hash = DigestUtilities.DoFinal(digest, m_lookAhead, m_bufStart, 2);

                return Arrays.FixedTimeEquals(hash.Length, hash, 0, m_lookAhead, m_bufStart + 2);
            }
        }

        private readonly InputStreamPacket m_encData;

        private Stream m_decStream;

        internal PgpEncryptedData(InputStreamPacket encData)
        {
            m_encData = encData;
        }

        /// <summary>Return the raw input stream for the data stream.</summary>
        public virtual Stream GetInputStream() => m_encData.GetInputStream();

        /// <summary>Return true if the message is integrity protected.</summary>
        /// <returns>True, if there is a modification detection code namespace associated
        /// with this stream.</returns>
        public bool IsIntegrityProtected() => m_encData is SymmetricEncIntegrityPacket;

        /// <summary>Note: This can only be called after the message has been read.</summary>
        /// <returns>True, if the message verifies, false otherwise</returns>
        public bool Verify()
        {
            if (!IsIntegrityProtected())
                throw new PgpException("data not integrity protected.");

            DigestStream digestStream = (DigestStream)m_decStream;

            if (digestStream.ReadByte() >= 0)
            {
                Streams.Drain(digestStream);
            }

            var truncStream = (TruncatedStream)digestStream.Stream;

            return truncStream.CheckMdc(digestStream.ReadDigest);
        }

        internal IBufferedCipher CreateBufferedCipher(string cipherName)
        {
            string mode = IsIntegrityProtected() ? "CFB" : "OpenPGPCFB";
            string algorithm = $"{cipherName}/{mode}/NoPadding";
            return CipherUtilities.GetCipher(algorithm);
        }

        internal Stream InitDecStream(Stream decStream)
        {
            if (IsIntegrityProtected())
            {
                var truncStream = new TruncatedStream(decStream);
                var readDigest = PgpUtilities.CreateDigest(HashAlgorithmTag.Sha1);
                decStream = new DigestStream(truncStream, readDigest, writeDigest: null);
            }

            m_decStream = decStream;
            return decStream;
        }

        internal static void QuickCheck(byte[] prefix)
        {
            int pLen = prefix.Length;
            Debug.Assert(pLen >= 4);

            byte p1 = prefix[pLen - 4];
            byte p2 = prefix[pLen - 3];
            byte v1 = prefix[pLen - 2];
            byte v2 = prefix[pLen - 1];

            bool repeatCheckPassed = v1 == p1 && v2 == p2;

            /*
             * NB: Some PGP versions produce 0 for the extra bytes rather than repeating the two previous bytes.
             */
            bool zerosCheckPassed = v1 == 0 && v2 == 0;

            if (!repeatCheckPassed && !zerosCheckPassed)
                throw new PgpDataValidationException("quick check failed.");
        }
    }
}
