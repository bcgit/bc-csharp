using System;
using System.IO;
#if NETSTANDARD1_0_OR_GREATER || NETCOREAPP1_0_OR_GREATER
using System.Runtime.CompilerServices;
#endif
#if NETCOREAPP2_1_OR_GREATER || NETSTANDARD2_1_OR_GREATER
using System.Runtime.InteropServices;
#endif
#if NETCOREAPP1_0_OR_GREATER || NET45_OR_GREATER || NETSTANDARD1_0_OR_GREATER
using System.Threading;
using System.Threading.Tasks;
#endif

namespace Org.BouncyCastle.Utilities.IO
{
    /// <summary>
    /// Minimal adapter over a source of bytes (e.g. a <see cref="Stream"/> or a <see cref="BinaryReader"/>) for
    /// generic reading helpers. Implement on a struct so that the helpers can be JIT-specialized per source.
    /// </summary>
    internal interface IReadSource
    {
        /// <summary>
        /// Read up to <paramref name="count"/> bytes into <paramref name="buffer"/> at <paramref name="offset"/>,
        /// returning the number of bytes read, or zero at end of data. Same contract as
        /// <see cref="Stream.Read(byte[], int, int)"/>.
        /// </summary>
        int Read(byte[] buffer, int offset, int count);
    }

    public static class Streams
    {
        private static readonly int MaxStackAlloc = Platform.Is64BitProcess ? 4096 : 1024;

        public static int DefaultBufferSize => MaxStackAlloc;

        public static void CopyTo(Stream source, Stream destination) => CopyTo(source, destination, DefaultBufferSize);

        public static void CopyTo(Stream source, Stream destination, int bufferSize)
        {
            int bytesRead;
#if NETCOREAPP2_1_OR_GREATER || NETSTANDARD2_1_OR_GREATER
            Span<byte> buffer = bufferSize <= MaxStackAlloc
                ? stackalloc byte[bufferSize]
                : new byte[bufferSize];
            while ((bytesRead = source.Read(buffer)) != 0)
            {
                destination.Write(buffer[..bytesRead]);
            }
#else
            byte[] buffer = new byte[bufferSize];
            while ((bytesRead = source.Read(buffer, 0, buffer.Length)) != 0)
            {
                destination.Write(buffer, 0, bytesRead);
            }
#endif
        }

#if NETCOREAPP1_0_OR_GREATER || NET45_OR_GREATER || NETSTANDARD1_0_OR_GREATER
        public static Task CopyToAsync(Stream source, Stream destination) =>
            CopyToAsync(source, destination, DefaultBufferSize);

        public static Task CopyToAsync(Stream source, Stream destination, int bufferSize) =>
            CopyToAsync(source, destination, bufferSize, CancellationToken.None);

        public static Task CopyToAsync(Stream source, Stream destination, CancellationToken cancellationToken) =>
            CopyToAsync(source, destination, DefaultBufferSize, cancellationToken);

        public static async Task CopyToAsync(Stream source, Stream destination, int bufferSize,
            CancellationToken cancellationToken)
        {
            int bytesRead;
            byte[] buffer = new byte[bufferSize];
#if NETCOREAPP2_1_OR_GREATER || NETSTANDARD2_1_OR_GREATER
            while ((bytesRead = await ReadAsync(source, new Memory<byte>(buffer), cancellationToken)
                .ConfigureAwait(false)) != 0)
            {
                await WriteAsync(destination, new ReadOnlyMemory<byte>(buffer, 0, bytesRead), cancellationToken)
                    .ConfigureAwait(false);
            }
#else
            while ((bytesRead = await source.ReadAsync(buffer, 0, buffer.Length, cancellationToken)
                .ConfigureAwait(false)) != 0)
            {
                await destination.WriteAsync(buffer, 0, bytesRead, cancellationToken).ConfigureAwait(false);
            }
#endif
        }
#endif

        public static void Drain(Stream inStr) => Drain(inStr, DefaultBufferSize);

        public static void Drain(Stream inStr, int bufferSize) => CopyTo(inStr, Stream.Null, bufferSize);

        /// <summary>Write the full contents of inStr to the destination stream outStr.</summary>
        /// <param name="inStr">Source stream.</param>
        /// <param name="outStr">Destination stream.</param>
        /// <exception cref="IOException">In case of IO failure.</exception>
        public static void PipeAll(Stream inStr, Stream outStr) => PipeAll(inStr, outStr, DefaultBufferSize);

        /// <summary>Write the full contents of inStr to the destination stream outStr.</summary>
        /// <param name="inStr">Source stream.</param>
        /// <param name="outStr">Destination stream.</param>
        /// <param name="bufferSize">The size of temporary buffer to use.</param>
        /// <exception cref="IOException">In case of IO failure.</exception>
        public static void PipeAll(Stream inStr, Stream outStr, int bufferSize) => CopyTo(inStr, outStr, bufferSize);

        /// <summary>
        /// Pipe all bytes from <c>inStr</c> to <c>outStr</c>, throwing <c>StreamFlowException</c> if greater
        /// than <c>limit</c> bytes in <c>inStr</c>.
        /// </summary>
        /// <param name="inStr">
        /// A <see cref="Stream"/>
        /// </param>
        /// <param name="limit">
        /// A <see cref="System.Int64"/>
        /// </param>
        /// <param name="outStr">
        /// A <see cref="Stream"/>
        /// </param>
        /// <returns>The number of bytes actually transferred, if not greater than <c>limit</c></returns>
        /// <exception cref="IOException"></exception>
        public static long PipeAllLimited(Stream inStr, long limit, Stream outStr) =>
            PipeAllLimited(inStr, limit, outStr, DefaultBufferSize);

        public static long PipeAllLimited(Stream inStr, long limit, Stream outStr, int bufferSize)
        {
            using (var limited = new LimitedInputStream(limit, inStr, leaveOpen: true))
            {
                CopyTo(limited, outStr, bufferSize);
                return limit - limited.CurrentLimit;
            }
        }

        public static byte[] ReadAll(Stream inStr) => ReadAll(inStr, DefaultBufferSize);

        public static byte[] ReadAll(Stream inStr, int bufferSize)
        {
            MemoryStream buf = new MemoryStream();
            using (buf)
            {
                CopyTo(inStr, buf, bufferSize);
            }
            return buf.ToArray();
        }

        [Obsolete("Will be removed")]
        public static byte[] ReadAll(MemoryStream inStr) => inStr.ToArray();

        public static byte[] ReadAllLimited(Stream inStr, int limit) => ReadAllLimited(inStr, limit, DefaultBufferSize);

        public static byte[] ReadAllLimited(Stream inStr, int limit, int bufferSize)
        {
            MemoryStream buf = new MemoryStream();
            using (buf)
            {
                PipeAllLimited(inStr, limit, buf, bufferSize);
            }
            return buf.ToArray();
        }

#if NETCOREAPP2_1_OR_GREATER || NETSTANDARD2_1_OR_GREATER
        public static ValueTask<int> ReadAsync(Stream source, Memory<byte> buffer,
            CancellationToken cancellationToken = default)
        {
            if (MemoryMarshal.TryGetArray(buffer, out ArraySegment<byte> array))
            {
                return new ValueTask<int>(
                    source.ReadAsync(array.Array!, array.Offset, array.Count, cancellationToken));
            }

            byte[] sharedBuffer = new byte[buffer.Length];
            var readTask = source.ReadAsync(sharedBuffer, 0, buffer.Length, cancellationToken);
            return ReadAsyncCompletion(readTask, sharedBuffer, buffer);
        }

        internal static async ValueTask<int> ReadAsyncCompletion(Task<int> readTask, byte[] localBuffer,
            Memory<byte> localDestination)
        {
            try
            {
                int result = await readTask.ConfigureAwait(false);
                new ReadOnlySpan<byte>(localBuffer, 0, result).CopyTo(localDestination.Span);
                return result;
            }
            finally
            {
                Array.Clear(localBuffer, 0, localBuffer.Length);
            }
        }
#endif

        public static int ReadFully(Stream inStr, byte[] buf) => ReadFully(inStr, buf, 0, buf.Length);

        public static int ReadFully(Stream inStr, byte[] buf, int off, int len)
        {
            int totalRead = 0;
            while (totalRead < len)
            {
                int numRead = inStr.Read(buf, off + totalRead, len - totalRead);
                if (numRead < 1)
                    break;
                totalRead += numRead;
            }
            return totalRead;
        }

#if NETCOREAPP2_1_OR_GREATER || NETSTANDARD2_1_OR_GREATER
        public static int ReadFully(Stream inStr, Span<byte> buffer)
        {
            int totalRead = 0;
            while (totalRead < buffer.Length)
            {
                int numRead = inStr.Read(buffer[totalRead..]);
                if (numRead < 1)
                    break;
                totalRead += numRead;
            }
            return totalRead;
        }
#endif

        /// <summary>Best-effort query of the data remaining before the end of a seekable stream.</summary>
        /// <remarks>
        /// Fails (rather than clamping) unless the stream reports a non-negative length and position. A position
        /// beyond the end is a legal seek target and reports zero available.
        /// The result is only meaningful when nothing sits between the caller and the stream: a buffering reader
        /// (e.g. <see cref="BinaryReader"/> makes no promise about read-ahead) can leave the stream position past
        /// the caller's logical position, and such callers should rely on <see cref="TryGetLength"/> instead.
        /// </remarks>
        public static bool TryGetAvailable(Stream stream, out long available)
        {
            try
            {
                if (stream.CanSeek)
                {
                    long length = stream.Length, position = stream.Position;
                    if (length >= 0L && position >= 0L)
                    {
                        available = System.Math.Max(0L, length - position);
                        return true;
                    }
                }
            }
            catch (Exception)
            {
                // Ignore; this method is best-effort only
            }

            available = default;
            return false;
        }

        /// <summary>Best-effort query of the total length of a seekable stream.</summary>
        /// <remarks>Fails (rather than clamping) unless the stream reports a non-negative length.</remarks>
        public static bool TryGetLength(Stream stream, out long length)
        {
            try
            {
                if (stream.CanSeek)
                {
                    length = stream.Length;
                    if (length >= 0L)
                        return true;
                }
            }
            catch (Exception)
            {
                // Ignore; this method is best-effort only
            }

            length = default;
            return false;
        }

        /// <summary>
        /// Read exactly <paramref name="exactLength"/> bytes from <paramref name="stream"/>, allocated incrementally.
        /// </summary>
        /// <remarks>
        /// The resulting <paramref name="bytes"/> array (if any) is grown incrementally as data arrives rather than
        /// allocated at the full length up front. A caller passing an untrusted (possibly hostile) length therefore
        /// cannot drive an extremely large allocation from a short input.
        /// </remarks>
        internal static bool TryReadExactIncremental(Stream stream, int exactLength, out byte[] bytes) =>
            TryReadExactIncremental(new StreamReadSource(stream), exactLength, out bytes);

        /// <summary>
        /// Read exactly <paramref name="exactLength"/> bytes from <paramref name="source"/>, allocated incrementally.
        /// </summary>
        /// <remarks>
        /// <typeparamref name="TSource"/> is constrained to a struct so that the JIT specializes this method per
        /// adapter and the <see cref="IReadSource.Read"/> calls are direct rather than interface dispatch.
        /// </remarks>
        internal static bool TryReadExactIncremental<TSource>(TSource source, int exactLength, out byte[] bytes)
            where TSource : struct, IReadSource
        {
            if (exactLength < 0)
                throw new ArgumentOutOfRangeException("cannot be negative", nameof(exactLength));
            if (exactLength > Arrays.MaxLength)
                throw new ArgumentOutOfRangeException("exceeds maximum length for an array", nameof(exactLength));

            int initialAlloc = exactLength;
            while (initialAlloc > DefaultBufferSize)
            {
                initialAlloc = (int)(((uint)initialAlloc + 3U) >> 2);
            }

            byte[] buf = new byte[initialAlloc];
            int totalRead = 0;
            while (totalRead < exactLength)
            {
                if (totalRead == buf.Length)
                {
                    int expandedAlloc = (int)System.Math.Min(exactLength, 4L * buf.Length);
                    buf = Arrays.CopyOf(buf, expandedAlloc);
                }

                int numRead = source.Read(buf, totalRead, buf.Length - totalRead);
                if (numRead < 1)
                {
                    bytes = default;
                    return false;
                }

                totalRead += numRead;
            }

            bytes = buf;
            return true;
        }

#if NETSTANDARD1_0_OR_GREATER || NETCOREAPP1_0_OR_GREATER
        [MethodImpl(MethodImplOptions.AggressiveInlining)]
#endif
        public static void ValidateBufferArguments(byte[] buffer, int offset, int count)
        {
            if (buffer == null)
                throw new ArgumentNullException(nameof(buffer));
            if (offset < 0)
                throw new ArgumentOutOfRangeException(nameof(offset));
            if ((uint)count > buffer.Length - offset)
                throw new ArgumentOutOfRangeException(nameof(count));
        }

#if NETCOREAPP1_0_OR_GREATER || NET45_OR_GREATER || NETSTANDARD1_0_OR_GREATER
        internal static async Task WriteAsyncCompletion(Task writeTask, byte[] localBuffer)
        {
            try
            {
                await writeTask.ConfigureAwait(false);
            }
            finally
            {
                Array.Clear(localBuffer, 0, localBuffer.Length);
            }
        }

        internal static Task WriteAsyncDirect(Stream destination, byte[] buffer, int offset, int count,
            CancellationToken cancellationToken)
        {
            if (cancellationToken.IsCancellationRequested)
                return Task.FromCanceled(cancellationToken);

            destination.Write(buffer, offset, count);
            return Task.CompletedTask;
        }
#endif

#if NETCOREAPP2_1_OR_GREATER || NETSTANDARD2_1_OR_GREATER
        public static ValueTask WriteAsync(Stream destination, ReadOnlyMemory<byte> buffer,
            CancellationToken cancellationToken = default)
        {
            if (MemoryMarshal.TryGetArray(buffer, out ArraySegment<byte> array))
            {
                return new ValueTask(
                    destination.WriteAsync(array.Array!, array.Offset, array.Count, cancellationToken));
            }

            byte[] sharedBuffer = buffer.ToArray();
            var writeTask = destination.WriteAsync(sharedBuffer, 0, buffer.Length, cancellationToken);
            return new ValueTask(WriteAsyncCompletion(writeTask, sharedBuffer));
        }

        internal static async ValueTask WriteAsyncCompletion(ValueTask writeTask, byte[] localBuffer)
        {
            try
            {
                await writeTask.ConfigureAwait(false);
            }
            finally
            {
                Array.Clear(localBuffer, 0, localBuffer.Length);
            }
        }

        internal static ValueTask WriteAsyncDirect(Stream destination, ReadOnlyMemory<byte> buffer,
            CancellationToken cancellationToken = default)
        {
            if (cancellationToken.IsCancellationRequested)
                return ValueTask.FromCanceled(cancellationToken);

            destination.Write(buffer.Span);
            return ValueTask.CompletedTask;
        }
#endif

        /// <exception cref="IOException"></exception>
        public static int WriteBufTo(MemoryStream buf, byte[] output, int offset)
        {
#if NETCOREAPP2_0_OR_GREATER || NETSTANDARD2_1_OR_GREATER
            if (buf.TryGetBuffer(out var buffer))
            {
                buffer.CopyTo(output, offset);
                return buffer.Count;
            }
#endif

            int size = Convert.ToInt32(buf.Length);
            using (var segment = new MemoryStream(output, offset, size))
            {
                buf.WriteTo(segment);
            }
            return size;
        }

        private readonly struct StreamReadSource
            : IReadSource
        {
            private readonly Stream m_stream;

            internal StreamReadSource(Stream stream)
            {
                m_stream = stream ?? throw new ArgumentNullException(nameof(stream));
            }

            public int Read(byte[] buffer, int offset, int count) => m_stream.Read(buffer, offset, count);
        }
    }
}
