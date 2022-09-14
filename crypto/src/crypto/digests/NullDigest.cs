using System;
using System.IO;

using Org.BouncyCastle.Utilities.IO;

namespace Org.BouncyCastle.Crypto.Digests
{
	public class NullDigest : IDigest
	{
		private readonly MemoryStream bOut = new MemoryStream();

		public string AlgorithmName
		{
			get { return "NULL"; }
		}

		public int GetByteLength()
		{
			// TODO Is this okay?
			return 0;
		}

		public int GetDigestSize()
		{
			return Convert.ToInt32(bOut.Length);
		}

		public void Update(byte b)
		{
			bOut.WriteByte(b);
		}

		public void BlockUpdate(byte[] inBytes, int inOff, int len)
		{
			bOut.Write(inBytes, inOff, len);
		}

        public int DoFinal(byte[] outBytes, int outOff)
		{
            try
            {
                return Streams.WriteBufTo(bOut, outBytes, outOff);
            }
            finally
            {
                Reset();
            }
        }

        public void Reset()
		{
			bOut.SetLength(0);
		}
	}
}
