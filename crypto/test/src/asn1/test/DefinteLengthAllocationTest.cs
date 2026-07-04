using System;
using System.IO;

using NUnit.Framework;

using Org.BouncyCastle.Utilities.IO;

namespace Org.BouncyCastle.Asn1.Tests
{
    /// <summary>
    /// Regression coverage for the definite-length materialization allocation guard in
    /// <see cref="DefiniteLengthInputStream.ToArray"/>.
    /// </summary>
    /// <remarks>
    /// When <see cref="Asn1InputStream"/> wraps a raw (non-array, non-file) stream, the per-object limit falls back to
    /// <c>Arrays.MaxLength</c> (<see cref="Asn1InputStream.FindLimit(Stream)"/>), so allocating the full declared
    /// length up front let a short crafted header - an OCTET STRING declaring a near-heap length with no body - drive
    /// an <see cref="OutOfMemoryException"/> before any data was read. The buffer is now grown as bytes actually
    /// arrive: a short input allocates only a bounded working buffer, a well-formed object still materializes
    /// correctly, and a truncated object still fails with the established "DEF length ... object truncated by ..."
    /// <see cref="EndOfStreamException"/>.
    /// </remarks>
    [TestFixture]
    public class DefiniteLengthAllocationTest
    {
        /// <summary>
        /// A large declared length must not be requested (and therefore allocated) in a single up-front read.
        /// </summary>
        /// <remarks>
        /// The eager <c>new byte[length]</c> asked the stream for the whole declared length at once, whereas the guard
        /// reads into a bounded, incrementally grown buffer.
        /// </remarks>
        [Test]
        public void DeclaredLengthNotAllocatedUpFront()
        {
            int declaredLength = 1 << 20;   // 1 MiB - comfortably past the bounded working buffer

            // OCTET STRING (tag 0x04), long-form length 0x100000, followed by a full body.
            byte[] input = new byte[5 + declaredLength];
            input[0] = (byte)0x04;
            input[1] = (byte)0x83;          // long form, 3 length octets
            input[2] = (byte)0x10;
            input[3] = (byte)0x00;
            input[4] = (byte)0x00;

            RecordingStream inStr = new RecordingStream(input);
            Asn1OctetString octets = (Asn1OctetString)new Asn1InputStream(inStr).ReadObject();

            Assert.AreEqual(declaredLength, octets.GetOctetsLength(),
                "octet string did not materialize to the declared length");
            int result = inStr.m_firstBulkReadLength;
            Assert.True(result >= 0 && result < declaredLength,
                $"first bulk read requested the full declared length ({result})");
        }

        /// <summary>
        /// A definite-length object whose stream ends early still fails with the exact truncation message the eager
        /// read produced (the message text is asserted elsewhere in the suite).
        /// </summary>
        [Test]
        public void TruncatedObjectReportsExpectedMessage()
        {
            int declaredLength = 1 << 20;
            int bodySupplied = 10;

            byte[] input = new byte[5 + bodySupplied];
            input[0] = (byte)0x04;
            input[1] = (byte)0x83;
            input[2] = (byte)0x10;
            input[3] = (byte)0x00;
            input[4] = (byte)0x00;

            try
            {
                new Asn1InputStream(new RecordingStream(input)).ReadObject();
                Assert.Fail("no exception on truncated definite-length object");
            }
            catch (EndOfStreamException e)
            {
                string expected = $"DEF length {declaredLength} object truncated by {declaredLength - bodySupplied}";
                Assert.AreEqual(expected, e.Message, $"unexpected truncation message: {e.Message}");
            }
            catch (Exception e)
            {
                Assert.Fail("unexpected exception: " + e);
            }
        }

        /// <summary>
        /// A generic BaseInputStream (so <see cref="Asn1InputStream.FindLimit(Stream)"/> takes the
        /// <c>Arrays.MaxLength</c> fallback) that records the size of the first bulk read request.
        /// </summary>
        private sealed class RecordingStream
            : BaseInputStream
        {
            private readonly byte[] m_data;
            private int m_pos = 0;
            internal int m_firstBulkReadLength = -1;

            internal RecordingStream(byte[] data)
            {
                m_data = data;
            }

            public override int Read(byte[] buf, int off, int len)
            {
                if (m_firstBulkReadLength < 0)
                {
                    m_firstBulkReadLength = len;
                }

                if (m_pos >= m_data.Length)
                    return 0;

                int n = System.Math.Min(len, m_data.Length - m_pos);
                Array.Copy(m_data, m_pos, buf, off, n);
                m_pos += n;
                return n;
            }

            // NOTE: .NET Core 3.1 has Span<T>, but is tested against our .NET Standard 2.0 assembly.
//#if NETCOREAPP2_1_OR_GREATER || NETSTANDARD2_1_OR_GREATER
#if NET6_0_OR_GREATER || NETSTANDARD2_1_OR_GREATER
            public override int Read(Span<byte> buffer)
            {
                if (m_firstBulkReadLength < 0)
                {
                    m_firstBulkReadLength = buffer.Length;
                }

                if (m_pos >= m_data.Length)
                    return 0;

                int n = System.Math.Min(buffer.Length, m_data.Length - m_pos);
                m_data.AsSpan(m_pos, n).CopyTo(buffer);
                m_pos += n;
                return n;
            }
#endif

            public override int ReadByte() => m_pos < m_data.Length ? m_data[m_pos++] : -1;
        }
    }
}
