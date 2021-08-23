using System;

using Org.BouncyCastle.Utilities.IO;

namespace Org.BouncyCastle.Tls.Crypto
{
    public class TlsHashSink
        : BaseOutputStream
    {
        private readonly TlsHash m_hash;

        public TlsHashSink(TlsHash hash)
        {
            this.m_hash = hash;
        }

        public virtual TlsHash Hash
        {
            get { return m_hash; }
        }

        public override void WriteByte(byte b)
        {
            m_hash.Update(new byte[] { b }, 0, 1);
        }

        public override void Write(byte[] buf, int off, int len)
        {
            if (len > 0)
            {
                m_hash.Update(buf, off, len);
            }
        }
    }
}
