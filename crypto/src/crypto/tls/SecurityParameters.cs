using System;
using Org.BouncyCastle.Utilities;

namespace Org.BouncyCastle.Crypto.Tls
{
	public class SecurityParameters
	{
        internal int entity = -1;
        internal CipherSuite cipherSuite = Org.BouncyCastle.Crypto.Tls.CipherSuite.UNASSINGED;
        internal CompressionMethod compressionAlgorithm = 0;
        internal int prfAlgorithm = -1;
        internal int verifyDataLength = -1;
        internal byte[] masterSecret = null;
        internal byte[] clientRandom = null;
        internal byte[] serverRandom = null;

        // TODO Keep these internal, since it's maybe not the ideal place for them
        internal short maxFragmentLength = -1;
        internal bool truncatedHMac = false;

        internal void CopySessionParametersFrom(SecurityParameters other)
        {
            this.entity = other.entity;
            this.cipherSuite = other.cipherSuite;
            this.compressionAlgorithm = other.compressionAlgorithm;
            this.prfAlgorithm = other.prfAlgorithm;
            this.verifyDataLength = other.verifyDataLength;
            this.masterSecret = Arrays.Clone(other.masterSecret);
        }

        public void Clear()
        {
            if (this.masterSecret != null)
            {
                Arrays.Fill(this.masterSecret, (byte)0);
                this.masterSecret = null;
            }
        }

        /**
         * @return {@link ConnectionEnd}
         */
        public int Entity
        {
            get
            {
                return entity;
            }
        }

        /**
         * @return {@link CipherSuite}
         */
        public CipherSuite CipherSuite
        {
            get
            {
                return cipherSuite;
            }
        }

        /**
         * @return {@link CompressionMethod}
         */
        public CompressionMethod CompressionAlgorithm
        {
            get
            {
                return compressionAlgorithm;
            }
        }

        /**
         * @return {@link PRFAlgorithm}
         */
        public int PrfAlgorithm
        {
            get
            {
                return prfAlgorithm;
            }
        }

        public int VerifyDataLength
        {
            get
            {
                return verifyDataLength;
            }
        }

        public byte[] MasterSecret
        {
            get
            {
                return masterSecret;
            }
        }

        public byte[] ClientRandom
        {
            get
            {
                return clientRandom;
            }
        }

        public byte[] ServerRandom
        {
            get
            {
                return serverRandom;
            }
        }
    }
}
