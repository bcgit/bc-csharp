/*
Copyright (c) 2001 Lapo Luchini.

Redistribution and use in source and binary forms, with or without
modification, are permitted provided that the following conditions are met:

  1. Redistributions of source code must retain the above copyright notice,
     this list of conditions and the following disclaimer.

  2. Redistributions in binary form must reproduce the above copyright
     notice, this list of conditions and the following disclaimer in
     the documentation and/or other materials provided with the distribution.

  3. The names of the authors may not be used to endorse or promote products
     derived from this software without specific prior written permission.

THIS SOFTWARE IS PROVIDED ``AS IS'' AND ANY EXPRESSED OR IMPLIED WARRANTIES,
INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND
FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE AUTHORS
OR ANY CONTRIBUTORS TO THIS SOFTWARE BE LIABLE FOR ANY DIRECT, INDIRECT,
INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT
LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA,
OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF
LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING
NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE,
EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 */
/*
 * This program is based on zlib-1.1.3, so all credit should go authors
 * Jean-loup Gailly(jloup@gzip.org) and Mark Adler(madler@alumni.caltech.edu)
 * and contributors of zlib.
 */
/* This file is a port of jzlib v1.0.7, com.jcraft.jzlib.ZOutputStream.java
 */

using System;
using System.Diagnostics;
using System.IO;

using Org.BouncyCastle.Utilities.IO;

namespace Org.BouncyCastle.Utilities.Zlib
{
    /// <summary>
    /// An output stream that compresses (or decompresses) the data written to it and writes the result to an underlying
    /// stream.
    /// </summary>
    public class ZOutputStream
        : BaseOutputStream
    {
        private static ZStream GetDefaultZStream(bool nowrap)
        {
            ZStream z = new ZStream();
            z.inflateInit(nowrap);
            return z;
        }

        private const int BufferSize = 4096;

        /// <summary>The zlib stream state.</summary>
        protected ZStream z;
        /// <summary>The flush level.</summary>
        protected int flushLevel = JZlib.Z_NO_FLUSH;
        /// <summary>The buffer for data to be written to the underlying stream.</summary>
        // TODO Allow custom buf
        protected byte[] buf = new byte[BufferSize];
        /// <summary>The buf 1.</summary>
        protected byte[] buf1 = new byte[1];
        /// <summary>true if the stream compresses data, false if it decompresses.</summary>
        protected bool compress;

        /// <summary>The underlying stream.</summary>
        protected Stream output;
        /// <summary>true once the stream has been closed.</summary>
        protected bool closed;

#if NETCOREAPP2_1_OR_GREATER || NETSTANDARD2_1_OR_GREATER
        // Transfer buffer for Write(ReadOnlySpan), allocated on first use. Only ever read by our own deflater (never
        // handed to the caller-supplied output stream), so reusing it is safe.
        private byte[] spanBuf;
#endif

        /// <summary>Create a new <see cref="ZOutputStream"/>.</summary>
        /// <param name="output">The buffer to write the output to.</param>
        public ZOutputStream(Stream output)
            : this(output, false)
        {
        }

        /// <summary>Create a new <see cref="ZOutputStream"/>.</summary>
        /// <param name="output">The buffer to write the output to.</param>
        /// <param name="nowrap">true if nowrap, false otherwise.</param>
        public ZOutputStream(Stream output, bool nowrap)
            : this(output, GetDefaultZStream(nowrap))
        {
        }

        /// <summary>Create a new <see cref="ZOutputStream"/>.</summary>
        /// <param name="output">The buffer to write the output to.</param>
        /// <param name="z">The result.</param>
        public ZOutputStream(Stream output, ZStream z)
            : base()
        {
            Debug.Assert(output.CanWrite);

            if (z == null)
            {
                z = new ZStream();
            }

            if (z.istate == null && z.dstate == null)
            {
                z.inflateInit();
            }

            this.output = output;
            this.compress = (z.istate == null);
            this.z = z;
        }

        /// <summary>Create a new <see cref="ZOutputStream"/>.</summary>
        /// <param name="output">The buffer to write the output to.</param>
        /// <param name="level">The level.</param>
        public ZOutputStream(Stream output, int level)
            : this(output, level, false)
        {
        }

        /// <summary>Create a new <see cref="ZOutputStream"/>.</summary>
        /// <param name="output">The buffer to write the output to.</param>
        /// <param name="level">The level.</param>
        /// <param name="nowrap">true if nowrap, false otherwise.</param>
        public ZOutputStream(Stream output, int level, bool nowrap)
            : base()
        {
            Debug.Assert(output.CanWrite);

            this.output = output;
            this.compress = true;
            this.z = new ZStream();
            this.z.deflateInit(level, nowrap);
        }

        /// <summary>Dispose of this stream without disposing of the underlying stream.</summary>
        /// <param name="disposing">true when called from <c>Dispose</c>, false when called from a finalizer.</param>
        protected void Detach(bool disposing)
        {
            if (disposing)
            {
                ImplDisposing(disposeOutput: false);
            }
            base.Dispose(disposing);
        }

        /// <inheritdoc/>
        protected override void Dispose(bool disposing)
        {
            if (disposing)
            {
                ImplDisposing(disposeOutput: true);
            }
            base.Dispose(disposing);
        }

        private void ImplDisposing(bool disposeOutput)
        {
            if (!closed)
            {
                try
                {
                    try
                    {
                        Finish();
                    }
                    catch (IOException)
                    {
                        // Ignore
                    }
                }
                finally
                {
                    this.closed = true;
                    End();
                    if (disposeOutput)
                    {
                        output.Dispose();
                    }
                    output = null;
                }
            }
        }

        /// <summary>Release the resources used by the zlib state.</summary>
        public virtual void End()
        {
            if (z == null)
                return;
            if (compress)
                z.deflateEnd();
            else
                z.inflateEnd();
            z.free();
            z = null;
        }

        /// <summary>
        /// Finish the compressed (or decompressed) data, flushing all pending output to the underlying stream.
        /// </summary>
        public virtual void Finish()
        {
            do
            {
                z.next_out = buf;
                z.next_out_index = 0;
                z.avail_out = buf.Length;

                int err = compress
                    ? z.deflate(JZlib.Z_FINISH)
                    : z.inflate(JZlib.Z_FINISH);

                if (err != JZlib.Z_STREAM_END && err != JZlib.Z_OK)
                    // TODO
                    //throw new ZStreamException((compress?"de":"in")+"flating: "+z.msg);
                    throw new IOException((compress ? "de" : "in") + "flating: " + z.msg);

                int count = buf.Length - z.avail_out;
                if (count > 0)
                {
                    output.Write(buf, 0, count);
                }
            }
            while (z.avail_in > 0 || z.avail_out == 0);

            Flush();
        }

        /// <inheritdoc/>
        public override void Flush()
        {
            output.Flush();
        }

        /// <summary>Gets or sets the flush mode.</summary>
        public virtual int FlushMode
        {
            get { return flushLevel; }
            set { this.flushLevel = value; }
        }

        /// <summary>Gets the total in.</summary>
        public virtual long TotalIn
        {
            get { return z.total_in; }
        }

        /// <summary>Gets the total out.</summary>
        public virtual long TotalOut
        {
            get { return z.total_out; }
        }

        /// <inheritdoc/>
        public override void Write(byte[] buffer, int offset, int count)
        {
            Streams.ValidateBufferArguments(buffer, offset, count);

            if (count == 0)
                return;

            z.next_in = buffer;
            z.next_in_index = offset;
            z.avail_in = count;

            do
            {
                z.next_out = buf;
                z.next_out_index = 0;
                z.avail_out = buf.Length;

                int err = compress
                    ? z.deflate(flushLevel)
                    : z.inflate(flushLevel);

                if (err != JZlib.Z_OK)
                    // TODO
                    //throw new ZStreamException((compress ? "de" : "in") + "flating: " + z.msg);
                    throw new IOException((compress ? "de" : "in") + "flating: " + z.msg);

                output.Write(buf, 0, buf.Length - z.avail_out);
            }
            while (z.avail_in > 0 || z.avail_out == 0);
        }

#if NETCOREAPP2_1_OR_GREATER || NETSTANDARD2_1_OR_GREATER
        /*
         * The base implementation would call WriteByte per byte, and each of those runs a full deflate/inflate call
         * for a single byte of input. Go through our own array overload instead, one block at a time.
         */
        public override void Write(ReadOnlySpan<byte> buffer)
        {
            if (buffer.IsEmpty)
                return;

            if (spanBuf == null)
            {
                spanBuf = new byte[BufferSize];
            }

            Streams.WriteSpanViaArray(this, buffer, spanBuf);
        }
#endif

        /// <inheritdoc/>
        public override void WriteByte(byte value)
        {
            buf1[0] = value;
            Write(buf1, 0, 1);
        }
    }

    /// <summary>A <see cref="ZOutputStream"/> that leaves the underlying stream open when it is disposed.</summary>
    public class ZOutputStreamLeaveOpen
        : ZOutputStream
    {
        /// <summary>Create a new <see cref="ZOutputStreamLeaveOpen"/>.</summary>
        /// <param name="output">The buffer to write the output to.</param>
        public ZOutputStreamLeaveOpen(Stream output)
            : base(output)
        {
        }

        /// <summary>Create a new <see cref="ZOutputStreamLeaveOpen"/>.</summary>
        /// <param name="output">The buffer to write the output to.</param>
        /// <param name="nowrap">true if nowrap, false otherwise.</param>
        public ZOutputStreamLeaveOpen(Stream output, bool nowrap)
            : base(output, nowrap)
        {
        }

        /// <summary>Create a new <see cref="ZOutputStreamLeaveOpen"/>.</summary>
        /// <param name="output">The buffer to write the output to.</param>
        /// <param name="z">The result.</param>
        public ZOutputStreamLeaveOpen(Stream output, ZStream z)
            : base(output, z)
        {
        }

        /// <summary>Create a new <see cref="ZOutputStreamLeaveOpen"/>.</summary>
        /// <param name="output">The buffer to write the output to.</param>
        /// <param name="level">The level.</param>
        public ZOutputStreamLeaveOpen(Stream output, int level)
            : base(output, level)
        {
        }

        /// <summary>Create a new <see cref="ZOutputStreamLeaveOpen"/>.</summary>
        /// <param name="output">The buffer to write the output to.</param>
        /// <param name="level">The level.</param>
        /// <param name="nowrap">true if nowrap, false otherwise.</param>
        public ZOutputStreamLeaveOpen(Stream output, int level, bool nowrap)
            : base(output, level, nowrap)
        {
        }

        /// <inheritdoc/>
        protected override void Dispose(bool disposing)
        {
            Detach(disposing);
        }
    }
}
