// NOTE: .NET Core 3.1 has Span<T>, but is tested against our .NET Standard 2.0 assembly.
//#if NETCOREAPP2_1_OR_GREATER || NETSTANDARD2_1_OR_GREATER
#if NET6_0_OR_GREATER || NETSTANDARD2_1_OR_GREATER
using System;
using System.Collections.Generic;
using System.IO;

using NUnit.Framework;

namespace Org.BouncyCastle.Utilities.IO.Tests
{
    /// <summary>
    /// Tests for <see cref="Streams.ReadSpanViaArray(Stream, Span{byte}, byte[])"/> and
    /// <see cref="Streams.WriteSpanViaArray(Stream, ReadOnlySpan{byte}, byte[])"/>, the helpers that implement the
    /// span overloads of a stream in terms of its array overloads.
    /// </summary>
    [TestFixture]
    public class SpanViaArrayTest
    {
        /// <summary>
        /// Serves bytes from an array, capping each <c>Read</c> by a script of per-call limits. Calls beyond the
        /// script are served in full. Counts the calls so tests can assert how many blocks were taken.
        /// </summary>
        private sealed class ScriptedInputStream
            : Stream
        {
            private readonly byte[] m_data;
            private readonly int[] m_script;
            private int m_pos;
            private int m_calls;

            internal ScriptedInputStream(byte[] data, params int[] script)
            {
                m_data = data;
                m_script = script;
            }

            internal int Calls => m_calls;

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
                int index = m_calls++;

                int n = System.Math.Min(count, m_data.Length - m_pos);
                if (index < m_script.Length)
                {
                    n = System.Math.Min(n, m_script[index]);
                }
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

        /// <summary>Records the size of each <c>Write</c> call alongside the bytes received.</summary>
        private sealed class RecordingOutputStream
            : Stream
        {
            private readonly MemoryStream m_received = new MemoryStream();
            private readonly List<int> m_writeSizes = new List<int>();

            internal byte[] Received => m_received.ToArray();
            internal IList<int> WriteSizes => m_writeSizes;

            public override bool CanRead => false;
            public override bool CanSeek => false;
            public override bool CanWrite => true;
            public override long Length => throw new NotSupportedException();
            public override long Position
            {
                get => throw new NotSupportedException();
                set => throw new NotSupportedException();
            }

            public override void Flush()
            {
            }

            public override int Read(byte[] buffer, int offset, int count) => throw new NotSupportedException();
            public override long Seek(long offset, SeekOrigin origin) => throw new NotSupportedException();
            public override void SetLength(long value) => throw new NotSupportedException();

            public override void Write(byte[] buffer, int offset, int count)
            {
                m_writeSizes.Add(count);
                m_received.Write(buffer, offset, count);
            }
        }

        private static byte[] CreateData(int length)
        {
            byte[] data = new byte[length];
            for (int i = 0; i < length; ++i)
            {
                data[i] = (byte)(i * 7 + (i >> 8));
            }
            return data;
        }

        [Test]
        public void ReadFillsSpanWhileBlocksAreSatisfiedInFull()
        {
            byte[] data = CreateData(1000);
            var source = new ScriptedInputStream(data);
            byte[] destination = new byte[1000];

            int numRead = Streams.ReadSpanViaArray(source, destination.AsSpan(), new byte[100]);

            Assert.That(numRead, Is.EqualTo(1000));
            Assert.That(destination, Is.EqualTo(data));
            Assert.That(source.Calls, Is.EqualTo(10), "should take exactly one call per full block");
        }

        [Test]
        public void ReadStopsAtFirstShortBlock()
        {
            byte[] data = CreateData(1000);
            // Two full 100-byte blocks, then a short one; the helper must not ask again after the short read.
            var source = new ScriptedInputStream(data, 100, 100, 30);
            byte[] destination = new byte[1000];

            int numRead = Streams.ReadSpanViaArray(source, destination.AsSpan(), new byte[100]);

            Assert.That(numRead, Is.EqualTo(230));
            Assert.That(source.Calls, Is.EqualTo(3));
            Assert.That(destination.AsSpan(0, 230).SequenceEqual(data.AsSpan(0, 230)), Is.True);
            Assert.That(destination.AsSpan(230).SequenceEqual(new byte[770]), Is.True, "tail must be untouched");
        }

        [Test]
        public void ReadIsCappedByTheSpanNotTheTransferBuffer()
        {
            byte[] data = CreateData(1000);
            var source = new ScriptedInputStream(data);
            byte[] destination = new byte[10];

            int numRead = Streams.ReadSpanViaArray(source, destination.AsSpan(), new byte[4096]);

            Assert.That(numRead, Is.EqualTo(10));
            Assert.That(source.Calls, Is.EqualTo(1));
            Assert.That(destination.AsSpan().SequenceEqual(data.AsSpan(0, 10)), Is.True);
        }

        [Test]
        public void ReadAtEndOfDataReturnsZero()
        {
            var source = new ScriptedInputStream(Array.Empty<byte>());

            Assert.That(Streams.ReadSpanViaArray(source, new byte[100].AsSpan(), new byte[16]), Is.EqualTo(0));
            Assert.That(source.Calls, Is.EqualTo(1));
        }

        [Test]
        public void ReadOfEmptySpanTouchesNothing()
        {
            var source = new ScriptedInputStream(CreateData(100));

            Assert.That(Streams.ReadSpanViaArray(source, Span<byte>.Empty, new byte[16]), Is.EqualTo(0));
            Assert.That(source.Calls, Is.EqualTo(0), "an empty span must not reach the stream");
        }

        [Test]
        public void ReadWithAllocatedTransferBufferFillsSpan()
        {
            byte[] data = CreateData(20000);
            var source = new ScriptedInputStream(data);
            byte[] destination = new byte[20000];

            // The allocating overload caps the block size, not the result.
            int numRead = Streams.ReadSpanViaArray(source, destination.AsSpan());

            Assert.That(numRead, Is.EqualTo(20000));
            Assert.That(destination, Is.EqualTo(data));
        }

        [Test]
        public void WriteSendsEverythingInBlocks()
        {
            byte[] data = CreateData(1000);
            var destination = new RecordingOutputStream();

            Streams.WriteSpanViaArray(destination, data.AsSpan(), new byte[300]);

            Assert.That(destination.Received, Is.EqualTo(data));
            Assert.That(destination.WriteSizes, Is.EqualTo(new[] { 300, 300, 300, 100 }));
        }

        [Test]
        public void WriteOfEmptySpanTouchesNothing()
        {
            var destination = new RecordingOutputStream();

            Streams.WriteSpanViaArray(destination, ReadOnlySpan<byte>.Empty, new byte[16]);
            Streams.WriteSpanViaArray(destination, ReadOnlySpan<byte>.Empty);

            Assert.That(destination.WriteSizes, Is.Empty);
        }

        /// <summary>
        /// An empty transfer buffer consumes nothing each pass, so the write loop would never terminate. Both
        /// helpers must reject it rather than spin.
        /// </summary>
        [Test]
        public void EmptyTransferBufferIsRejected()
        {
            var source = new ScriptedInputStream(CreateData(100));
            var destination = new RecordingOutputStream();
            byte[] data = CreateData(10);
            byte[] scratch = new byte[10];
            byte[] empty = Array.Empty<byte>();

            Assert.Throws<ArgumentException>(() => Streams.ReadSpanViaArray(source, scratch.AsSpan(), empty));
            Assert.Throws<ArgumentException>(() => Streams.WriteSpanViaArray(destination, data.AsSpan(), empty));

            Assert.That(source.Calls, Is.EqualTo(0));
            Assert.That(destination.WriteSizes, Is.Empty);
        }

        [Test]
        public void WriteWithAllocatedTransferBufferSendsEverything()
        {
            byte[] data = CreateData(20000);
            var destination = new RecordingOutputStream();

            Streams.WriteSpanViaArray(destination, data.AsSpan());

            Assert.That(destination.Received, Is.EqualTo(data));
        }
    }
}
#endif
