using System;
using System.IO;
using System.Threading;
using System.Threading.Tasks;

namespace Org.BouncyCastle.Utilities.IO
{
	public class PushbackStream
		: FilterStream
	{
		private int m_buf = -1;

		public PushbackStream(Stream s)
			: base(s)
		{
		}

#if NETCOREAPP2_0_OR_GREATER || NETSTANDARD2_1_OR_GREATER
        public override void CopyTo(Stream destination, int bufferSize)
        {
			if (m_buf != -1)
			{
				destination.WriteByte((byte)m_buf);
                m_buf = -1;
            }

			Streams.CopyTo(s, destination, bufferSize);
        }
#endif

        public override async Task CopyToAsync(Stream destination, int bufferSize, CancellationToken cancellationToken)
        {
            if (m_buf != -1)
            {
				byte[] buffer = new byte[1]{ (byte)m_buf };
                await destination.WriteAsync(buffer, 0, 1, cancellationToken).ConfigureAwait(false);
                m_buf = -1;
            }

            await Streams.CopyToAsync(s, destination, bufferSize, cancellationToken);
        }

        public override int Read(byte[] buffer, int offset, int count)
		{
			Streams.ValidateBufferArguments(buffer, offset, count);

			if (m_buf != -1)
			{
				if (count < 1)
					return 0;

				buffer[offset] = (byte)m_buf;
				m_buf = -1;
				return 1;
			}

			return s.Read(buffer, offset, count);
		}

#if NETCOREAPP2_1_OR_GREATER || NETSTANDARD2_1_OR_GREATER
        public override int Read(Span<byte> buffer)
        {
			if (m_buf != -1)
			{
                if (buffer.IsEmpty)
                    return 0;

                buffer[0] = (byte)m_buf;
                m_buf = -1;
                return 1;
            }

            return s.Read(buffer);
        }

        public override ValueTask<int> ReadAsync(Memory<byte> buffer, CancellationToken cancellationToken = default)
        {
            if (m_buf != -1)
            {
                if (buffer.IsEmpty)
                    return new ValueTask<int>(0);

                buffer.Span[0] = (byte)m_buf;
                m_buf = -1;
                return new ValueTask<int>(1);
            }

            return Streams.ReadAsync(s, buffer, cancellationToken);
        }
#endif

        public override int ReadByte()
		{
			if (m_buf != -1)
			{
				int tmp = m_buf;
				m_buf = -1;
				return tmp;
			}

			return s.ReadByte();
		}

		public virtual void Unread(int b)
		{
			if (m_buf != -1)
				throw new InvalidOperationException("Can only push back one byte");

			m_buf = b & 0xFF;
		}
	}
}
