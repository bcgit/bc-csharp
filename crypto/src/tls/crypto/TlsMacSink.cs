using System;

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

        public override void WriteByte(byte b)
        {
            m_mac.Update(new byte[]{ b }, 0, 1);
        }

        public override void Write(byte[] buf, int off, int len)
        {
            if (len > 0)
            {
                m_mac.Update(buf, off, len);
            }
        }
    }
}
