using System;

using Org.BouncyCastle.Crypto.Digests;

namespace Org.BouncyCastle.Crypto.Tls
{
    /// <remarks>A combined hash, which implements md5(m) || sha1(m).</remarks>
    internal class CombinedHash : TlsHandshakeHash
    {
        protected TlsContext context;
        private readonly MD5Digest md5;
        private readonly Sha1Digest sha1;

        internal CombinedHash()
        {
            this.md5 = new MD5Digest();
            this.sha1 = new Sha1Digest();
        }

        internal CombinedHash(CombinedHash t)
        {
            this.context = t.context;
            
            this.md5 = new MD5Digest(t.md5);
            this.sha1 = new Sha1Digest(t.sha1);
        }

        public void Init(TlsContext context)
        {
            this.context = context;
        }

        public TlsHandshakeHash Commit()
        {
            return this;
        }

        public TlsHandshakeHash Fork()
        {
            return new CombinedHash(this);
        }

        /// <seealso cref="IDigest.AlgorithmName"/>
        public string AlgorithmName
        {
            get
            {
                return md5.AlgorithmName + " and " + sha1.AlgorithmName + " for TLS 1.0";
            }
        }

        /// <seealso cref="IDigest.GetByteLength"/>
        public int GetByteLength()
        {
            return System.Math.Max(md5.GetByteLength(), sha1.GetByteLength());
        }

        /// <seealso cref="IDigest.GetDigestSize"/>
        public int GetDigestSize()
        {
            return md5.GetDigestSize() + sha1.GetDigestSize();
        }

        /// <seealso cref="IDigest.Update"/>
        public void Update(
            byte input)
        {
            md5.Update(input);
            sha1.Update(input);
        }

        /// <seealso cref="IDigest.BlockUpdate"/>
        public void BlockUpdate(
            byte[] input,
            int inOff,
            int len)
        {
            md5.BlockUpdate(input, inOff, len);
            sha1.BlockUpdate(input, inOff, len);
        }

        /// <seealso cref="IDigest.DoFinal"/>
        public int DoFinal(
            byte[] output,
            int outOff)
        {
            if (context != null && TlsUtilities.IsSSL(context))
            {
                Ssl3Complete(md5, Ssl3Mac.IPAD, Ssl3Mac.OPAD, 48);
                Ssl3Complete(sha1, Ssl3Mac.IPAD, Ssl3Mac.OPAD, 40);
            }

            int i1 = md5.DoFinal(output, outOff);
            int i2 = sha1.DoFinal(output, outOff + i1);
            return i1 + i2;
        }

        /// <seealso cref="IDigest.Reset"/>
        public void Reset()
        {
            md5.Reset();
            sha1.Reset();
        }

        protected void Ssl3Complete(IDigest d, byte[] ipad, byte[] opad, int padLength)
        {
            byte[] master_secret = context.SecurityParameters.masterSecret;

            d.BlockUpdate(master_secret, 0, master_secret.Length);
            d.BlockUpdate(ipad, 0, padLength);

            byte[] tmp = new byte[d.GetDigestSize()];
            d.DoFinal(tmp, 0);

            d.BlockUpdate(master_secret, 0, master_secret.Length);
            d.BlockUpdate(opad, 0, padLength);
            d.BlockUpdate(tmp, 0, tmp.Length);
        }
    }
}
