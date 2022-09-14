using System;
using System.IO;

namespace Org.BouncyCastle.Utilities.IO
{
	public sealed class Streams
	{
		private const int BufferSize = 4096;

		private Streams()
		{
		}

		public static void Drain(Stream inStr)
		{
			byte[] bs = new byte[BufferSize];
			while (inStr.Read(bs, 0, bs.Length) > 0)
			{
			}
		}

        /// <summary>Write the full contents of inStr to the destination stream outStr.</summary>
        /// <param name="inStr">Source stream.</param>
        /// <param name="outStr">Destination stream.</param>
        /// <exception cref="IOException">In case of IO failure.</exception>
        public static void PipeAll(Stream inStr, Stream outStr)
		{
            PipeAll(inStr, outStr, BufferSize);
        }

        /// <summary>Write the full contents of inStr to the destination stream outStr.</summary>
        /// <param name="inStr">Source stream.</param>
        /// <param name="outStr">Destination stream.</param>
        /// <param name="bufferSize">The size of temporary buffer to use.</param>
        /// <exception cref="IOException">In case of IO failure.</exception>
        public static void PipeAll(Stream inStr, Stream outStr, int bufferSize)
        {
            byte[] bs = new byte[bufferSize];
            int numRead;
			while ((numRead = inStr.Read(bs, 0, bs.Length)) > 0)
			{
				outStr.Write(bs, 0, numRead);
			}
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
			byte[] bs = new byte[BufferSize];
			long total = 0;
			int numRead;
			while ((numRead = inStr.Read(bs, 0, bs.Length)) > 0)
			{
                if ((limit - total) < numRead)
					throw new StreamOverflowException("Data Overflow");
                total += numRead;
                outStr.Write(bs, 0, numRead);
			}
			return total;
		}

		public static byte[] ReadAll(Stream inStr)
		{
			MemoryStream buf = new MemoryStream();
			PipeAll(inStr, buf);
			return buf.ToArray();
		}

		public static byte[] ReadAllLimited(Stream inStr, int limit)
		{
			MemoryStream buf = new MemoryStream();
			PipeAllLimited(inStr, limit, buf);
			return buf.ToArray();
		}

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

        /// <exception cref="IOException"></exception>
        public static int WriteBufTo(MemoryStream buf, byte[] output, int offset)
        {
			int size = Convert.ToInt32(buf.Length);
            buf.WriteTo(new MemoryStream(output, offset, size));
            return size;
        }
    }
}
