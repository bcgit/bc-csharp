using System;
using System.IO;

using Org.BouncyCastle.Security;

namespace Org.BouncyCastle.Utilities.Test
{
	public class FixedSecureRandom
		: SecureRandom
	{
		private byte[]       _data;
		private int          _index;

		protected FixedSecureRandom(
			byte[] data)
		{
			_data = data;
		}

		public static FixedSecureRandom From(
			params byte[][] values)
		{
			MemoryStream bOut = new MemoryStream();

			for (int i = 0; i != values.Length; i++)
			{
				try
				{
					byte[] v = values[i];
					bOut.Write(v, 0, v.Length);
				}
				catch (IOException)
				{
					throw new ArgumentException("can't save value array.");
				}
			}

			return new FixedSecureRandom(bOut.ToArray());
		}

        public override byte[] GenerateSeed(int numBytes)
        {
            return SecureRandom.GetNextBytes(this, numBytes);
        }

        public override void NextBytes(
			byte[] buf)
		{
			Array.Copy(_data, _index, buf, 0, buf.Length);

			_index += buf.Length;
		}

		public override void NextBytes(
			byte[]	buf,
			int		off,
			int		len)
		{
			Array.Copy(_data, _index, buf, off, len);

			_index += len;
		}

		public bool IsExhausted
		{
			get { return _index == _data.Length; }
		}
	}
}
