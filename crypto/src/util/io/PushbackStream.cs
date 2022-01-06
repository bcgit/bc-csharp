using System;
using System.IO;

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

		public override int ReadByte()
		{
			if (m_buf != -1)
			{
				int tmp = m_buf;
				m_buf = -1;
				return tmp;
			}

			return base.ReadByte();
		}

		public override int Read(byte[] buffer, int offset, int count)
		{
            if (count < 1)
                return 0;

			if (m_buf != -1)
			{
				buffer[offset] = (byte)m_buf;
				m_buf = -1;
				return 1;
			}

			return base.Read(buffer, offset, count);
		}

		public virtual void Unread(int b)
		{
			if (m_buf != -1)
				throw new InvalidOperationException("Can only push back one byte");

			m_buf = b & 0xFF;
		}
	}
}
