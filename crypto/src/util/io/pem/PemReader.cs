using System;
using System.Collections.Generic;
using System.IO;
using System.Text;

using Org.BouncyCastle.Utilities.Encoders;

namespace Org.BouncyCastle.Utilities.IO.Pem
{
	public class PemReader
		: IDisposable
	{
        private const int LineLength = 64;

        private readonly TextReader m_reader;
		private readonly MemoryStream m_buffer;
		private readonly StreamWriter m_textBuffer;
		private readonly Stack<int> m_pushback = new Stack<int>();

		public PemReader(TextReader reader)
		{
			m_reader = reader ?? throw new ArgumentNullException(nameof(reader));
            m_buffer = new MemoryStream();
            m_textBuffer = new StreamWriter(m_buffer);
		}

        #region IDisposable

        public void Dispose()
        {
            Dispose(true);
            GC.SuppressFinalize(this);
        }

        protected virtual void Dispose(bool disposing)
        {
            if (disposing)
            {
                m_reader.Dispose();
            }
        }

        #endregion

        public TextReader Reader 
		{
			get { return m_reader; }
		}


		/// <returns>
		/// A <see cref="PemObject"/>
		/// </returns>
		/// <exception cref="IOException"></exception>	
		public PemObject ReadPemObject()
        {
			//
			// Look for BEGIN
			//

			for (;;)
			{
				// Seek a leading dash, ignore anything up to that point.
				if (!SeekDash())
					return null; 

				// consume dash [-----]BEGIN ...
				if (!ConsumeDash())
					throw new IOException("no data after consuming leading dashes");

				SkipWhiteSpace();

				if (Expect("BEGIN"))
					break;
			}

			SkipWhiteSpace();

			//
			// Consume type, accepting whitespace
			//

			if (!BufferUntilStopChar('-', false))
				throw new IOException("ran out of data before consuming type");

			string type = BufferedString().Trim();

			// Consume dashes after type.

			if (!ConsumeDash())
				throw new IOException("ran out of data consuming header");

			SkipWhiteSpace();

			//
			// Read ahead looking for headers.
			// Look for a colon for up to 64 characters, as an indication there might be a header.
			//

			var headers = new List<PemHeader>();

			while (SeekColon(LineLength))
            {
				if (!BufferUntilStopChar(':', false))
					throw new IOException("ran out of data reading header key value");

				string key = BufferedString().Trim();

				int c = Read();
				if (c != ':')
					throw new IOException("expected colon");

				//
				// We are going to look for well formed headers, if they do not end with a "LF" we cannot
				// discern where they end.
				//

				if (!BufferUntilStopChar('\n', false)) // Now read to the end of the line.
					throw new IOException("ran out of data before consuming header value");

				SkipWhiteSpace();

				string value = BufferedString().Trim();
				headers.Add(new PemHeader(key, value));
			}

			//
			// Consume payload, ignoring all white space until we encounter a '-'
			//

			SkipWhiteSpace();

			if (!BufferUntilStopChar('-', true))
				throw new IOException("ran out of data before consuming payload");

			string payload = BufferedString();

			// Seek the start of the end.
			if (!SeekDash())
				throw new IOException("did not find leading '-'");

			if (!ConsumeDash())
				throw new IOException("no data after consuming trailing dashes");

			if (!Expect("END " + type))
				throw new IOException("END " + type + " was not found.");

			if (!SeekDash())
				throw new IOException("did not find ending '-'");

			// consume trailing dashes.
			ConsumeDash();

			return new PemObject(type, headers, Base64.Decode(payload));
		}

		private string BufferedString()
        {
			m_textBuffer.Flush();

#if NETCOREAPP2_1_OR_GREATER || NETSTANDARD2_1_OR_GREATER
            if (!m_buffer.TryGetBuffer(out var data))
                throw new InvalidOperationException();

            string value = Encoding.UTF8.GetString(data);
#else
            string value = Strings.FromUtf8ByteArray(m_buffer.ToArray());
#endif

            m_buffer.Position = 0;
			m_buffer.SetLength(0);

			return value;
        }

		private bool SeekDash()
        {
			int c;
			while ((c = Read()) >= 0)
            {
				if (c == '-')
					break;
            }

			PushBack(c);

			return c >= 0;
        }

		/// <summary>
		/// Seek ':" up to the limit.
		/// </summary>
		/// <param name="upTo"></param>
		/// <returns></returns>
		private bool SeekColon(int upTo)
		{
			int c = 0;
			bool colonFound = false;
			var read = new List<int>();

			for (; upTo >= 0 && c >= 0; upTo--)
            {
				c = Read();
				read.Add(c);
				if (c == ':')
                {
					colonFound = true;
					break;
                }
            }

			int readPos = read.Count;
			while (--readPos >= 0)
			{
				PushBack(read[readPos]);
			}

			return colonFound;
		}

		/// <summary>
		/// Consume the dashes
		/// </summary>
		/// <returns></returns>
		private bool ConsumeDash()
        {
			int c;
			while ((c = Read()) >= 0)
			{
				if (c != '-')
					break;
			}

			PushBack(c);

			return c >= 0;
		}

		/// <summary>
		/// Skip white space leave char in stream.
		/// </summary>
		private void SkipWhiteSpace()
        {
			int c;
			while ((c = Read()) >= 0)
			{
				if (c > ' ')
					break;
			}

			PushBack(c);
		}

		/// <summary>
		/// Read forward consuming the expected string.
		/// </summary>
		/// <param name="value">expected string</param>
		/// <returns>false if not consumed</returns>
		private bool Expect(string value)
        {
			for (int t = 0; t < value.Length; t++)
            {
				if (Read() != value[t])
					return false;
            }

			return true;
        }

		/// <summary>
		/// Consume until dash.
		/// </summary>
		/// <returns>true if stream end not met</returns>
		private bool BufferUntilStopChar(char stopChar, bool skipWhiteSpace)
        {
			int c;
			while ((c = Read()) >= 0)
			{	
				if (skipWhiteSpace && c <= ' ')
					continue;

				if (c == stopChar)
				{
                    PushBack(c);
                    break;
                }

				m_textBuffer.Write((char)c);
				m_textBuffer.Flush();
			}

			return c >= 0;
		}

		private void PushBack(int value)
        {
			m_pushback.Push(value);
        }

		private int Read()
        {
			if (m_pushback.Count > 0)
				return m_pushback.Pop();

			return m_reader.Read();
        }
	}
}
