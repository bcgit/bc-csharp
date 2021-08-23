using System;
using System.Collections;
using System.IO;

using Org.BouncyCastle.Tls.Crypto;
using Org.BouncyCastle.Utilities;

namespace Org.BouncyCastle.Tls
{
    /// <summary>Buffers input until the hash algorithm is determined.</summary>
    internal sealed class DeferredHash
        : TlsHandshakeHash
    {
        private const int BufferingHashLimit = 4;

        private readonly TlsContext m_context;

        private DigestInputBuffer m_buf;
        private readonly IDictionary m_hashes;
        private bool m_forceBuffering;
        private bool m_sealed;

        internal DeferredHash(TlsContext context)
        {
            this.m_context = context;
            this.m_buf = new DigestInputBuffer();
            this.m_hashes = Platform.CreateHashtable();
            this.m_forceBuffering = false;
            this.m_sealed = false;
        }

        private DeferredHash(TlsContext context, IDictionary hashes)
        {
            this.m_context = context;
            this.m_buf = null;
            this.m_hashes = hashes;
            this.m_forceBuffering = false;
            this.m_sealed = true;
        }

        /// <exception cref="IOException"/>
        public void CopyBufferTo(Stream output)
        {
            if (m_buf == null)
            {
                // If you see this, you need to call forceBuffering() before SealHashAlgorithms()
                throw new InvalidOperationException("Not buffering");
            }

            m_buf.CopyTo(output);
        }

        public void ForceBuffering()
        {
            if (m_sealed)
                throw new InvalidOperationException("Too late to force buffering");

            this.m_forceBuffering = true;
        }

        public void NotifyPrfDetermined()
        {
            SecurityParameters securityParameters = m_context.SecurityParameters;

            switch (securityParameters.PrfAlgorithm)
            {
            case PrfAlgorithm.ssl_prf_legacy:
            case PrfAlgorithm.tls_prf_legacy:
            {
                CheckTrackingHash(CryptoHashAlgorithm.md5);
                CheckTrackingHash(CryptoHashAlgorithm.sha1);
                break;
            }
            default:
            {
                CheckTrackingHash(securityParameters.PrfCryptoHashAlgorithm);
                break;
            }
            }
        }

        public void TrackHashAlgorithm(int cryptoHashAlgorithm)
        {
            if (m_sealed)
                throw new InvalidOperationException("Too late to track more hash algorithms");

            CheckTrackingHash(cryptoHashAlgorithm);
        }

        public void SealHashAlgorithms()
        {
            if (m_sealed)
                throw new InvalidOperationException("Already sealed");

            this.m_sealed = true;
            CheckStopBuffering();
        }

        public TlsHandshakeHash StopTracking()
        {
            SecurityParameters securityParameters = m_context.SecurityParameters;

            IDictionary newHashes = Platform.CreateHashtable();
            switch (securityParameters.PrfAlgorithm)
            {
            case PrfAlgorithm.ssl_prf_legacy:
            case PrfAlgorithm.tls_prf_legacy:
            {
                CloneHash(newHashes, HashAlgorithm.md5);
                CloneHash(newHashes, HashAlgorithm.sha1);
                break;
            }
            default:
            {
                CloneHash(newHashes, securityParameters.PrfCryptoHashAlgorithm);
                break;
            }
            }
            return new DeferredHash(m_context, newHashes);
        }

        public TlsHash ForkPrfHash()
        {
            CheckStopBuffering();

            SecurityParameters securityParameters = m_context.SecurityParameters;

            TlsHash prfHash;
            switch (securityParameters.PrfAlgorithm)
            {
            case PrfAlgorithm.ssl_prf_legacy:
            case PrfAlgorithm.tls_prf_legacy:
            {
                prfHash = new CombinedHash(m_context, CloneHash(HashAlgorithm.md5), CloneHash(HashAlgorithm.sha1));
                break;
            }
            default:
            {
                prfHash = CloneHash(securityParameters.PrfCryptoHashAlgorithm);
                break;
            }
            }

            if (m_buf != null)
            {
                m_buf.UpdateDigest(prfHash);
            }

            return prfHash;
        }

        public byte[] GetFinalHash(int cryptoHashAlgorithm)
        {
            TlsHash d = (TlsHash)m_hashes[cryptoHashAlgorithm];
            if (d == null)
                throw new InvalidOperationException("CryptoHashAlgorithm." + cryptoHashAlgorithm
                    + " is not being tracked");

            CheckStopBuffering();

            d = d.CloneHash();
            if (m_buf != null)
            {
                m_buf.UpdateDigest(d);
            }

            return d.CalculateHash();
        }

        public void Update(byte[] input, int inOff, int len)
        {
            if (m_buf != null)
            {
                m_buf.Write(input, inOff, len);
                return;
            }

            foreach (TlsHash hash in m_hashes.Values)
            {
                hash.Update(input, inOff, len);
            }
        }

        public byte[] CalculateHash()
        {
            throw new InvalidOperationException("Use 'ForkPrfHash' to get a definite hash");
        }

        public TlsHash CloneHash()
        {
            throw new InvalidOperationException("attempt to clone a DeferredHash");
        }

        public void Reset()
        {
            if (m_buf != null)
            {
                m_buf.SetLength(0);
                return;
            }

            foreach (TlsHash hash in m_hashes.Values)
            {
                hash.Reset();
            }
        }

        private void CheckStopBuffering()
        {
            if (!m_forceBuffering && m_sealed && m_buf != null && m_hashes.Count <= BufferingHashLimit)
            {
                foreach (TlsHash hash in m_hashes.Values)
                {
                    m_buf.UpdateDigest(hash);
                }

                this.m_buf = null;
            }
        }

        private void CheckTrackingHash(int cryptoHashAlgorithm)
        {
            if (!m_hashes.Contains(cryptoHashAlgorithm))
            {
                TlsHash hash = m_context.Crypto.CreateHash(cryptoHashAlgorithm);
                m_hashes[cryptoHashAlgorithm] = hash;
            }
        }

        private TlsHash CloneHash(int cryptoHashAlgorithm)
        {
            return ((TlsHash)m_hashes[cryptoHashAlgorithm]).CloneHash();
        }

        private void CloneHash(IDictionary newHashes, int cryptoHashAlgorithm)
        {
            TlsHash hash = CloneHash(cryptoHashAlgorithm);
            if (m_buf != null)
            {
                m_buf.UpdateDigest(hash);
            }
            newHashes[cryptoHashAlgorithm] = hash;
        }
    }
}
