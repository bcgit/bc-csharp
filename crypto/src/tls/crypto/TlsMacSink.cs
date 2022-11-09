﻿using System;

using Org.BouncyCastle.Utilities.IO;

namespace Org.BouncyCastle.Tls.Crypto
{
    public class TlsMacSink
        : BaseOutputStream
    {
        private readonly TlsMac m_mac;

        public TlsMacSink(TlsMac mac)
        {
            this.m_mac = mac;
        }

        public virtual TlsMac Mac
        {
            get { return m_mac; }
        }

        public override void Write(byte[] buffer, int offset, int count)
        {
            Streams.ValidateBufferArguments(buffer, offset, count);

            if (count > 0)
            {
                m_mac.Update(buffer, offset, count);
            }
        }

#if NETCOREAPP2_1_OR_GREATER || NETSTANDARD2_1_OR_GREATER
        public override void Write(ReadOnlySpan<byte> buffer)
        {
            if (!buffer.IsEmpty)
            {
                m_mac.Update(buffer);
            }
        }
#endif

        public override void WriteByte(byte value)
        {
            m_mac.Update(new byte[]{ value }, 0, 1);
        }
    }
}
