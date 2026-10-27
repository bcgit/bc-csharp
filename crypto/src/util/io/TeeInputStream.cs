using System;
using System.Diagnostics;
using System.IO;

namespace Org.BouncyCastle.Utilities.IO
{
    /// <summary>An input stream that copies everything read from it to a second stream.</summary>
    public class TeeInputStream
        : BaseInputStream
    {
        private readonly Stream input, tee;

        /// <summary>Create a new <see cref="TeeInputStream"/>.</summary>
        /// <param name="input">The input data.</param>
        /// <param name="tee">The tee.</param>
        public TeeInputStream(Stream input, Stream tee)
        {
            Debug.Assert(input.CanRead);
            Debug.Assert(tee.CanWrite);

            this.input = input;
            this.tee = tee;
        }

        /// <inheritdoc/>
        protected override void Dispose(bool disposing)
        {
            if (disposing)
            {
                input.Dispose();
                tee.Dispose();
            }
            base.Dispose(disposing);
        }

        /// <inheritdoc/>
        public override int Read(byte[] buffer, int offset, int count)
        {
            int i = input.Read(buffer, offset, count);

            if (i > 0)
            {
                tee.Write(buffer, offset, i);
            }

            return i;
        }

#if NETCOREAPP2_1_OR_GREATER || NETSTANDARD2_1_OR_GREATER
        /// <inheritdoc/>
        public override int Read(Span<byte> buffer)
        {
            int i = input.Read(buffer);

            if (i > 0)
            {
                tee.Write(buffer[..i]);
            }

            return i;
        }
#endif

        /// <inheritdoc/>
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
