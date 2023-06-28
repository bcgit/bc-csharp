using System;

using Org.BouncyCastle.Utilities;

namespace Org.BouncyCastle.Crypto.Parameters
{
    /// <summary>Blake3 Parameters.</summary>
    public sealed class Blake3Parameters
        : ICipherParameters
    {
        private const int KeyLen = 32;

        private byte[] m_theKey;
        private byte[] m_theContext;

        /// <summary>Create a key parameter.</summary>
        /// <param name="pContext">the context</param>
        /// <returns>the parameter</returns>
        public static Blake3Parameters Context(byte[] pContext)
        {
            if (pContext == null)
                throw new ArgumentNullException(nameof(pContext));

            Blake3Parameters myParams = new Blake3Parameters();
            myParams.m_theContext = Arrays.Clone(pContext);
            return myParams;
        }

        /// <summary>Create a key parameter.</summary>
        /// <param name="pKey">the key</param>
        /// <returns>the parameter</returns>
        public static Blake3Parameters Key(byte[] pKey)
        {
            if (pKey == null)
                throw new ArgumentNullException(nameof(pKey));
            if (pKey.Length != KeyLen)
                throw new ArgumentException("Invalid key length", nameof(pKey));

            Blake3Parameters myParams = new Blake3Parameters();
            myParams.m_theKey = Arrays.Clone(pKey);
            return myParams;
        }

        /// <summary>Obtain the key.</summary>
        /// <returns>the key</returns>
        public byte[] GetKey() => Arrays.Clone(m_theKey);

        /// <summary>Clear the key bytes.</summary>
        public void ClearKey()
        {
            Arrays.Fill(m_theKey, 0);
        }

        /// <summary>Obtain the salt.</summary>
        /// <returns>the salt</returns>
        public byte[] GetContext() => Arrays.Clone(m_theContext);
    }
}
