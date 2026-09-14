using System;
using System.IO;

using NUnit.Framework;

namespace Org.BouncyCastle.Utilities.Bzip2.Tests
{
    /// <summary>
    /// Round-trip tests for <see cref="CBZip2OutputStream"/> / <see cref="CBZip2InputStream"/>, and checks that the
    /// span and array read overloads agree, both on the bytes they produce and on how they treat an
    /// <see cref="IOException"/> raised part way through a read.
    /// </summary>
    [TestFixture]
    public class Bzip2StreamTest
    {
        private const int FixedSeed = 0x0B21;

        /// <summary>100 KiB blocks, so a few hundred KB of input spans several blocks.</summary>
        private const int BlockSize100k = 1;

        /// <summary>Serves bytes from an array, then fails instead of reporting end of data.</summary>
        private sealed class ThrowAfterStream
            : Stream
        {
            private readonly byte[] m_data;
            private readonly int m_limit;
            private int m_pos;

            internal ThrowAfterStream(byte[] data, int limit)
            {
                m_data = data;
                m_limit = limit;
            }

            public override bool CanRead => true;
            public override bool CanSeek => false;
            public override bool CanWrite => false;
            public override long Length => throw new NotSupportedException();
            public override long Position
            {
                get => throw new NotSupportedException();
                set => throw new NotSupportedException();
            }

            public override void Flush()
            {
            }

            public override int Read(byte[] buffer, int offset, int count)
            {
                if (m_pos >= m_limit)
                    throw new IOException("simulated read failure");

                int n = System.Math.Min(count, m_limit - m_pos);
                if (n < 1)
                    return 0;

                Array.Copy(m_data, m_pos, buffer, offset, n);
                m_pos += n;
                return n;
            }

            public override long Seek(long offset, SeekOrigin origin) => throw new NotSupportedException();
            public override void SetLength(long value) => throw new NotSupportedException();
            public override void Write(byte[] buffer, int offset, int count) => throw new NotSupportedException();
        }

        /// <summary>Compressible data: long runs of a small alphabet.</summary>
        private static byte[] CreateData(int length, int seed)
        {
            byte[] data = new byte[length];
            var rng = new Random(seed);
            int pos = 0;
            while (pos < length)
            {
                int runLength = System.Math.Min(rng.Next(1, 40), length - pos);
                byte value = (byte)rng.Next(0, 12);
                for (int i = 0; i < runLength; ++i)
                {
                    data[pos++] = value;
                }
            }
            return data;
        }

        private static byte[] Compress(byte[] data)
        {
            var output = new MemoryStream();
            using (var bzOut = new CBZip2OutputStreamLeaveOpen(output, BlockSize100k))
            {
                bzOut.Write(data, 0, data.Length);
            }
            return output.ToArray();
        }

        private static readonly int[] Sizes = { 0, 1, 2, 1000, 99999, 100000, 100001, 250000 };

        [Test]
        public void ArrayReadRoundTrips()
        {
            foreach (int size in Sizes)
            {
                byte[] data = CreateData(size, FixedSeed + size);
                byte[] compressed = Compress(data);

                var output = new MemoryStream();
                using (var bzIn = new CBZip2InputStream(new MemoryStream(compressed, false)))
                {
                    byte[] scratch = new byte[8192];
                    int numRead;
                    while ((numRead = bzIn.Read(scratch, 0, scratch.Length)) > 0)
                    {
                        output.Write(scratch, 0, numRead);
                    }
                }

                Assert.That(output.ToArray(), Is.EqualTo(data), $"round trip failed at size {size}");
            }
        }

        // NOTE: .NET Core 3.1 has Span<T>, but is tested against our .NET Standard 2.0 assembly, which compiles
        // neither the Read(Span) override below nor the one on BaseInputStream.
//#if NETCOREAPP2_1_OR_GREATER || NETSTANDARD2_1_OR_GREATER
#if NET6_0_OR_GREATER || NETSTANDARD2_1_OR_GREATER
        [Test]
        public void SpanReadMatchesArrayRead([Values(1, 17, 4096, 100000)] int request)
        {
            foreach (int size in Sizes)
            {
                byte[] data = CreateData(size, FixedSeed + size);
                byte[] compressed = Compress(data);

                var output = new MemoryStream();
                using (var bzIn = new CBZip2InputStream(new MemoryStream(compressed, false)))
                {
                    byte[] scratch = new byte[request];
                    int numRead;
                    while ((numRead = bzIn.Read(scratch.AsSpan())) > 0)
                    {
                        Assert.That(numRead, Is.LessThanOrEqualTo(request), "read more than requested");
                        output.Write(scratch, 0, numRead);
                    }
                }

                Assert.That(output.ToArray(), Is.EqualTo(data), $"round trip failed at size {size}");
            }
        }

        /// <summary>
        /// A read that has already delivered bytes when the underlying stream fails must not swallow the failure and
        /// report a short read. The array overload deliberately propagates (unlike the base class implementation),
        /// and the span overload must agree with it.
        /// </summary>
        [Test]
        public void SpanReadPropagatesIOExceptionLikeArrayRead()
        {
            byte[] data = CreateData(250000, FixedSeed);
            byte[] compressed = Compress(data);

            // Withhold the final compressed byte, so the first blocks decode but a later one cannot.
            int limit = compressed.Length - 1;
            byte[] scratch = new byte[data.Length];

            using (var bzIn = new CBZip2InputStream(new ThrowAfterStream(compressed, limit)))
            {
                Assert.That(bzIn.Read(scratch, 0, 1000), Is.EqualTo(1000), "first array read should succeed");
                Assert.Throws<IOException>(() => bzIn.Read(scratch, 0, scratch.Length));
            }

            using (var bzIn = new CBZip2InputStream(new ThrowAfterStream(compressed, limit)))
            {
                Assert.That(bzIn.Read(scratch.AsSpan(0, 1000)), Is.EqualTo(1000), "first span read should succeed");
                Assert.Throws<IOException>(() => bzIn.Read(scratch.AsSpan()));
            }
        }
#endif
    }
}
