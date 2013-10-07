using System.IO;
using System;

namespace Org.BouncyCastle.Crypto.Tls
{
    /**
     * Buffers input until the hash algorithm is determined.
     */
    class DeferredHash : TlsHandshakeHash
    {
        protected TlsContext context;

        private DigestInputBuffer buf = new DigestInputBuffer();
        private IDigest hash = null;

        public DeferredHash()
        {
            this.buf = new DigestInputBuffer();
            this.hash = null;
        }

        private DeferredHash(IDigest hash)
        {
            this.buf = null;
            this.hash = hash;
        }

        public void Init(TlsContext context)
        {
            this.context = context;
        }

        public TlsHandshakeHash Commit()
        {
            int prfAlgorithm = context.SecurityParameters.PrfAlgorithm;

            IDigest prfHash = TlsUtilities.CreatePRFHash(prfAlgorithm);

            buf.UpdateDigest(prfHash);

            if (prfHash is TlsHandshakeHash)
            {
                TlsHandshakeHash tlsPRFHash = (TlsHandshakeHash)prfHash;
                tlsPRFHash.Init(context);
                return tlsPRFHash.Commit();
            }

            this.hash = prfHash;
            this.buf = null;

            return this;
        }

        public TlsHandshakeHash Fork()
        {
            CheckHash();
            int prfAlgorithm = context.SecurityParameters.PrfAlgorithm;
            return new DeferredHash(TlsUtilities.ClonePRFHash(prfAlgorithm, hash));
        }

        public string AlgorithmName
        {
            get
            {
                CheckHash();
                return hash.AlgorithmName;
            }
        }

        public int GetDigestSize()
        {
            CheckHash();
            return hash.GetDigestSize();
        }

        public int GetByteLength()
        {
            CheckHash();
            return hash.GetByteLength();
        }

        public void Update(byte input)
        {
            if (hash == null)
            {
                buf.WriteByte(input);
            }
            else
            {
                hash.Update(input);
            }
        }

        public void BlockUpdate(byte[] input, int inOff, int len)
        {
            if (hash == null)
            {
                buf.Write(input, inOff, len);
            }
            else
            {
                hash.BlockUpdate(input, inOff, len);
            }
        }

        public int DoFinal(byte[] output, int outOff)
        {
            CheckHash();
            return hash.DoFinal(output, outOff);
        }

        public void Reset()
        {
            if (hash == null)
            {
                buf.SetLength(0);
            }
            else
            {
                hash.Reset();
            }
        }

        protected void CheckHash()
        {
            if (hash == null)
            {
                throw new ArgumentException("No hash algorithm has been set");
            }
        }

        class DigestInputBuffer : MemoryStream
        {
            public void UpdateDigest(IDigest d)
            {
                d.BlockUpdate(GetBuffer(), 0, (int)this.Length);
            }
        }
    }
}