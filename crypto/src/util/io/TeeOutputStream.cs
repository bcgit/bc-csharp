using System;
using System.Diagnostics;
using System.IO;

namespace Org.BouncyCastle.Utilities.IO
{
    public class TeeOutputStream
        : BaseOutputStream
    {
        private readonly Stream output, tee;

        /// <summary>Create a new <see cref="TeeOutputStream"/>.</summary>
        /// <param name="output">The buffer to write the output to.</param>
        /// <param name="tee">The tee.</param>
        public TeeOutputStream(Stream output, Stream tee)
        {
            Debug.Assert(output.CanWrite);
            Debug.Assert(tee.CanWrite);

            this.output = output;
            this.tee = tee;
        }

        /// <inheritdoc/>
        protected override void Dispose(bool disposing)
        {
            if (disposing)
            {
                output.Dispose();
                tee.Dispose();
            }
            base.Dispose(disposing);
        }

        /// <inheritdoc/>
        public override void Write(byte[] buffer, int offset, int count)
        {
            output.Write(buffer, offset, count);
            tee.Write(buffer, offset, count);
        }

#if NETCOREAPP2_1_OR_GREATER || NETSTANDARD2_1_OR_GREATER
        /// <inheritdoc/>
        public override void Write(ReadOnlySpan<byte> buffer)
        {
            output.Write(buffer);
            tee.Write(buffer);
        }
#endif

        /// <inheritdoc/>
        public override void WriteByte(byte value)
        {
            output.WriteByte(value);
            tee.WriteByte(value);
        }
    }
}
