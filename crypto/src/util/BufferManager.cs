using System;
using System.Threading;
using System.Collections.Generic;
using System.Text;

namespace Org.BouncyCastle.Utilities
{
    internal class BufferManager
    {
        private volatile int[] _flags = new int[8];
        private volatile byte[][] _buffers = new byte[8][];
        private readonly int _bufferSize;

        public BufferManager(int bufferSize)
        {
            _bufferSize = bufferSize;
        }

        public byte[] TakeBuffer()
        {
            for (int i = 0; i < _flags.Length; i++)
            {
                if (Interlocked.CompareExchange(ref _flags[i], 1, 0) == 0)
                {
                    if (_buffers[i] == null)
                        _buffers[i] = new byte[_bufferSize];
                    
                    return _buffers[i];                    
                }
            }

            return new byte[_bufferSize];
        }

        public void ReturnBuffer(byte[] buffer)
        {
            for (int i = 0; i < _buffers.Length; i++)
            {
                if (_buffers[i] == buffer)
                    Interlocked.Decrement(ref _flags[i]);
            }
        }
    }
}
