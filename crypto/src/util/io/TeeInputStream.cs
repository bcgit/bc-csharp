using System;
using System.Diagnostics;
using System.IO;

namespace Org.BouncyCastle.Utilities.IO
{
	public class TeeInputStream
		: BaseInputStream
	{
		private readonly Stream input, tee;

		public TeeInputStream(Stream input, Stream tee)
		{
			Debug.Assert(input.CanRead);
			Debug.Assert(tee.CanWrite);

			this.input = input;
			this.tee = tee;
		}

#if PORTABLE
        protected override void Dispose(bool disposing)
        {
            if (disposing)
            {
                Platform.Dispose(input);
                Platform.Dispose(tee);
            }
            base.Dispose(disposing);
        }
#else
        public override void Close()
		{
            Platform.Dispose(input);
            Platform.Dispose(tee);
            base.Close();
		}
#endif

        public override int Read(byte[] buffer, int offset, int count)
		{
			int i = input.Read(buffer, offset, count);

			if (i > 0)
			{
				tee.Write(buffer, offset, i);
			}

			return i;
		}

		public override int ReadByte()
		{
			int i = input.ReadByte();

			if (i >= 0)
			{
				tee.WriteByte((byte)i);
			}

			return i;
		}
	}
}
