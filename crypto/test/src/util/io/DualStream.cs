using System;
using System.Collections.Generic;
using System.Text;
using System.IO;

namespace crypto.test.src.util.io
{
    class DualStream : Stream
    {
        private Stream _input;
        private Stream _output;

        public DualStream(Stream input, Stream output)
        {
            _input = input;
            _output = output;
        }

        public override bool CanRead
        {
            get { return _input.CanRead; }
        }

        public override bool CanSeek
        {
            get { return false; }
        }

        public override bool CanWrite
        {
            get { return _output.CanWrite; }
        }

        public override void Flush()
        {
            _output.Flush();
        }

        public override long Length
        {
            get { throw new NotSupportedException(); }
        }

        public override long Position
        {
            get
            {
                throw new NotSupportedException();
            }
            set
            {
                throw new NotSupportedException();
            }
        }

        public override int Read(byte[] buffer, int offset, int count)
        {
            return _input.Read(buffer, offset, count);
        }

        public override long Seek(long offset, SeekOrigin origin)
        {
            throw new NotSupportedException();
        }

        public override void SetLength(long value)
        {
            throw new NotSupportedException();
        }

        public override void Write(byte[] buffer, int offset, int count)
        {
            _output.Write(buffer, offset, count);
        }
    }
}
