using System;

using Org.BouncyCastle.Utilities;

namespace Org.BouncyCastle.Crypto.Tls
{
    public class SecurityParameters
    {
        internal int prfAlgorithm = -1;
        internal byte[] masterSecret = null;
        internal byte[] clientRandom = null;
        internal byte[] serverRandom = null;

        internal virtual void Clear()
        {
            if (this.masterSecret != null)
            {
                Arrays.Fill(this.masterSecret, (byte)0);
                this.masterSecret = null;
            }
        }

        /**
         * @return {@link PRFAlgorithm}
         */
        public virtual int PrfAlgorithm
        {
            get { return prfAlgorithm; }
        }

        public virtual byte[] MasterSecret
        {
            get { return masterSecret; }
        }

        public virtual byte[] ClientRandom
        {
            get { return clientRandom; }
        }

        public virtual byte[] ServerRandom
        {
            get { return serverRandom; }
        }
    }
}
