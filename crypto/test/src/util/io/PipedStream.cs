using System;
using System.Collections.Generic;
using System.Text;
using System.IO;
using System.Threading;

namespace crypto.test.src.util.io
{
    class PipedStream : Stream 
    {
        private byte[] _buffer = new byte[0x100000];
        private int _readerPosition = 0;
        private int _writerPosition = 0;
        private object _bufferLock = new object();
        private EventWaitHandle _readerWaitHandle = new AutoResetEvent(false);
        private EventWaitHandle _writerWaitHandle = new AutoResetEvent(false);
        private bool _disposing = false;

        public override bool CanRead
        {
            get { return true; }
        }

        public override bool CanSeek
        {
            get { return false; }
        }

        public override bool CanWrite
        {
            get { return true; }
        }

        public override void Flush()
        {
            
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
            var bytesRead = 0;
            do
            {
                lock (_bufferLock)
                {
                    if (_readerPosition < _writerPosition)
                    {
                        bytesRead = _writerPosition - _readerPosition;
                        if (bytesRead > count)
                            bytesRead = count;

                        Buffer.BlockCopy(this._buffer, _readerPosition, buffer, offset, bytesRead);

                        _readerPosition += bytesRead;

                        if (_readerPosition == _writerPosition)
                        {
                            _readerPosition = _writerPosition = 0;
                            _writerWaitHandle.Set();
                        }

                        return bytesRead;
                    }

                    if (_disposing)
                    {
                        return bytesRead;
                    }
                }

                _readerWaitHandle.WaitOne(); 

            } while (bytesRead == 0);

            return bytesRead;

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
            do
            {
                lock (_bufferLock)
                {
                    if (_disposing)
                        throw new ObjectDisposedException("PipeStream"); 

                    var bytesToWrite = _buffer.Length - _writerPosition;

                    if (bytesToWrite > count)
                        bytesToWrite = count;

                    if (bytesToWrite > 0)
                    {
                        Buffer.BlockCopy(buffer, offset, _buffer, _writerPosition, bytesToWrite);
                        _writerPosition += bytesToWrite;
                        count -= bytesToWrite;
                        offset += bytesToWrite;

                        _readerWaitHandle.Set();

                        if (count == 0)
                            return;
                    }
                }

                // wait for reader to read all buffered data before writing more bytes 
                _writerWaitHandle.WaitOne();
            } while (count > 0);
        }

        public override void Close()
        {
            lock (_buffer)
            {
                _disposing = true;

                _readerWaitHandle.Set();
                _writerWaitHandle.Set();
                _readerWaitHandle = _writerWaitHandle = new ManualResetEvent(true);
            }
        }
    }
}
