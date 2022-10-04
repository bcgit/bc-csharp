using System;
using System.IO;

using Org.BouncyCastle.Utilities;

namespace Org.BouncyCastle.Tls.Crypto.Impl
{
    /// <summary>Base class for a TlsSecret implementation which captures common code and fields.</summary>
    public abstract class AbstractTlsSecret
        : TlsSecret
    {
        protected static byte[] CopyData(AbstractTlsSecret other)
        {
            return other.CopyData();
        }

        protected byte[] m_data;

        /// <summary>Base constructor.</summary>
        /// <param name="data">the byte[] making up the secret value.</param>
        protected AbstractTlsSecret(byte[] data)
        {
            m_data = data;
        }

        protected virtual void CheckAlive()
        {
            if (m_data == null)
                throw new InvalidOperationException("Secret has already been extracted or destroyed");
        }

        protected abstract AbstractTlsCrypto Crypto { get; }

        public virtual byte[] CalculateHmac(int cryptoHashAlgorithm, byte[] buf, int off, int len)
        {
            lock (this)
            {
                CheckAlive();

                TlsHmac hmac = Crypto.CreateHmacForHash(cryptoHashAlgorithm);
                hmac.SetKey(m_data, 0, m_data.Length);
                hmac.Update(buf, off, len);
                return hmac.CalculateMac();
            }
        }

        public abstract TlsSecret DeriveUsingPrf(int prfAlgorithm, string label, byte[] seed, int length);

#if NETCOREAPP2_1_OR_GREATER || NETSTANDARD2_1_OR_GREATER
        public abstract TlsSecret DeriveUsingPrf(int prfAlgorithm, ReadOnlySpan<char> label, ReadOnlySpan<byte> seed,
            int length);
#endif

        public virtual void Destroy()
        {
            lock (this)
            {
                if (m_data != null)
                {
                    // TODO Is there a way to ensure the data is really overwritten?
                    Array.Clear(m_data, 0, m_data.Length);
                    m_data = null;
                }
            }
        }

        /// <exception cref="IOException"/>
        public virtual byte[] Encrypt(TlsEncryptor encryptor)
        {
            lock (this)
            {
                CheckAlive();

                return encryptor.Encrypt(m_data, 0, m_data.Length);
            }
        }

        public virtual byte[] Extract()
        {
            lock (this)
            {
                CheckAlive();

                byte[] result = m_data;
                m_data = null;
                return result;
            }
        }

#if NETCOREAPP2_1_OR_GREATER || NETSTANDARD2_1_OR_GREATER
        public virtual void ExtractTo(Span<byte> output)
        {
            lock (this)
            {
                CheckAlive();

                m_data.CopyTo(output);
                m_data = null;
            }
        }
#endif

        public abstract TlsSecret HkdfExpand(int cryptoHashAlgorithm, byte[] info, int length);

#if NETCOREAPP2_1_OR_GREATER || NETSTANDARD2_1_OR_GREATER
        public abstract TlsSecret HkdfExpand(int cryptoHashAlgorithm, ReadOnlySpan<byte> info, int length);
#endif

        public abstract TlsSecret HkdfExtract(int cryptoHashAlgorithm, TlsSecret ikm);

        public virtual bool IsAlive()
        {
            lock (this)
            {
                return null != m_data;
            }
        }

        public virtual int Length
        {
            get
            {
                lock (this)
                {
                    CheckAlive();

                    return m_data.Length;
                }
            }
        }

        internal virtual byte[] CopyData()
        {
            lock (this)
            {
                return Arrays.Clone(m_data);
            }
        }
    }
}
