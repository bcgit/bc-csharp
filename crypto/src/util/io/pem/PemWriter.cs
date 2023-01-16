using System;
using System.IO;

using Org.BouncyCastle.Utilities.Encoders;

namespace Org.BouncyCastle.Utilities.IO.Pem
{
	/**
	* A generic PEM writer, based on RFC 1421
	*/
	public class PemWriter
		: IDisposable
	{
		private const int LineLength = 64;

		private readonly TextWriter m_writer;
		private readonly int m_nlLength;
		private readonly char[] m_buf = new char[LineLength];

		/**
		 * Base constructor.
		 *
		 * @param out output stream to use.
		 */
		public PemWriter(TextWriter writer)
		{
			m_writer = writer ?? throw new ArgumentNullException(nameof(writer));
            m_nlLength = Environment.NewLine.Length;
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
                m_writer.Dispose();
            }
        }

        #endregion

        public TextWriter Writer
		{
			get { return m_writer; }
		}

		/**
		 * Return the number of bytes or characters required to contain the
		 * passed in object if it is PEM encoded.
		 *
		 * @param obj pem object to be output
		 * @return an estimate of the number of bytes
		 */
		public int GetOutputSize(PemObject obj)
		{
			// BEGIN and END boundaries.
			int size = (2 * (obj.Type.Length + 10 + m_nlLength)) + 6 + 4;

			if (obj.Headers.Count > 0)
			{
				foreach (PemHeader header in obj.Headers)
				{
					size += header.Name.Length + ": ".Length + header.Value.Length + m_nlLength;
				}

				size += m_nlLength;
			}

			// base64 encoding
			int dataLen = ((obj.Content.Length + 2) / 3) * 4;

			size += dataLen + (((dataLen + LineLength - 1) / LineLength) * m_nlLength);

			return size;
		}

		public void WriteObject(PemObjectGenerator objGen)
		{
			PemObject obj = objGen.Generate();

			WritePreEncapsulationBoundary(obj.Type);

			if (obj.Headers.Count > 0)
			{
				foreach (PemHeader header in obj.Headers)
				{
					m_writer.Write(header.Name);
					m_writer.Write(": ");
					m_writer.WriteLine(header.Value);
				}

				m_writer.WriteLine();
			}

			WriteEncoded(obj.Content);
			WritePostEncapsulationBoundary(obj.Type);
		}

		private void WriteEncoded(byte[] bytes)
		{
			bytes = Base64.Encode(bytes);

			for (int i = 0; i < bytes.Length; i += m_buf.Length)
			{
				int index = 0;
				while (index != m_buf.Length)
				{
					if ((i + index) >= bytes.Length)
						break;

					m_buf[index] = (char)bytes[i + index];
					index++;
				}
				m_writer.WriteLine(m_buf, 0, index);
			}
		}

		private void WritePreEncapsulationBoundary(string type)
		{
			m_writer.WriteLine("-----BEGIN " + type + "-----");
		}

		private void WritePostEncapsulationBoundary(string type)
		{
			m_writer.WriteLine("-----END " + type + "-----");
		}
    }
}
