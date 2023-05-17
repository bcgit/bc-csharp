using System;
using System.IO;
#if NETCOREAPP2_1_OR_GREATER || NETSTANDARD2_1_OR_GREATER
using System.Runtime.InteropServices;
#endif
#if NETCOREAPP1_0_OR_GREATER || NET45_OR_GREATER || NETSTANDARD1_0_OR_GREATER
using System.Threading;
using System.Threading.Tasks;
#endif

namespace Org.BouncyCastle.Utilities.IO
{
    public static class Streams
	{
        private static readonly int MaxStackAlloc = Platform.Is64BitProcess ? 4096 : 1024;

		public static int DefaultBufferSize => MaxStackAlloc;

        public static void CopyTo(Stream source, Stream destination)
        {
			CopyTo(source, destination, DefaultBufferSize);
        }

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
        public static Task CopyToAsync(Stream source, Stream destination)
        {
            return CopyToAsync(source, destination, DefaultBufferSize);
        }

        public static Task CopyToAsync(Stream source, Stream destination, int bufferSize)
        {
            return CopyToAsync(source, destination, bufferSize, CancellationToken.None);
        }

        public static Task CopyToAsync(Stream source, Stream destination, CancellationToken cancellationToken)
        {
            return CopyToAsync(source, destination, DefaultBufferSize, cancellationToken);
        }

        public static async Task CopyToAsync(Stream source, Stream destination, int bufferSize,
			CancellationToken cancellationToken)
        {
            int bytesRead;
            byte[] buffer = new byte[bufferSize];
#if NETCOREAPP2_1_OR_GREATER || NETSTANDARD2_1_OR_GREATER
            while ((bytesRead = await ReadAsync(source, new Memory<byte>(buffer), cancellationToken).ConfigureAwait(false)) != 0)
			{
				await WriteAsync(destination, new ReadOnlyMemory<byte>(buffer, 0, bytesRead), cancellationToken).ConfigureAwait(false);
			}
#else
			while ((bytesRead = await source.ReadAsync(buffer, 0, buffer.Length, cancellationToken).ConfigureAwait(false)) != 0)
			{
				await destination.WriteAsync(buffer, 0, bytesRead, cancellationToken).ConfigureAwait(false);
			}
#endif
		}
#endif

        public static void Drain(Stream inStr)
		{
			CopyTo(inStr, Stream.Null, DefaultBufferSize);
		}

        /// <summary>Write the full contents of inStr to the destination stream outStr.</summary>
        /// <param name="inStr">Source stream.</param>
        /// <param name="outStr">Destination stream.</param>
        /// <exception cref="IOException">In case of IO failure.</exception>
        public static void PipeAll(Stream inStr, Stream outStr)
		{
            PipeAll(inStr, outStr, DefaultBufferSize);
        }

        /// <summary>Write the full contents of inStr to the destination stream outStr.</summary>
        /// <param name="inStr">Source stream.</param>
        /// <param name="outStr">Destination stream.</param>
        /// <param name="bufferSize">The size of temporary buffer to use.</param>
        /// <exception cref="IOException">In case of IO failure.</exception>
        public static void PipeAll(Stream inStr, Stream outStr, int bufferSize)
        {
            CopyTo(inStr, outStr, bufferSize);
		}

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
		public static long PipeAllLimited(Stream inStr, long limit, Stream outStr)
		{
			return PipeAllLimited(inStr, limit, outStr, DefaultBufferSize);
		}

        public static long PipeAllLimited(Stream inStr, long limit, Stream outStr, int bufferSize)
        {
            var limited = new LimitedInputStream(inStr, limit);
            CopyTo(limited, outStr, bufferSize);
            return limit - limited.CurrentLimit;
        }

        public static byte[] ReadAll(Stream inStr)
		{
			MemoryStream buf = new MemoryStream();
			PipeAll(inStr, buf);
			return buf.ToArray();
		}

        public static byte[] ReadAll(MemoryStream inStr)
        {
			return inStr.ToArray();
        }

        public static byte[] ReadAllLimited(Stream inStr, int limit)
		{
			MemoryStream buf = new MemoryStream();
			PipeAllLimited(inStr, limit, buf);
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

		public static int ReadFully(Stream inStr, byte[] buf)
		{
			return ReadFully(inStr, buf, 0, buf.Length);
		}

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

        public static void ValidateBufferArguments(byte[] buffer, int offset, int count)
        {
			if (buffer == null)
				throw new ArgumentNullException("buffer");
			int available = buffer.Length - offset;
			if ((offset | available) < 0)
				throw new ArgumentOutOfRangeException("offset");
			int remaining = available - count;
			if ((count | remaining) < 0)
				throw new ArgumentOutOfRangeException("count");
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
            buf.WriteTo(new MemoryStream(output, offset, size));
            return size;
        }
    }
}
