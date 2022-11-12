using System;

using Org.BouncyCastle.Crypto;

namespace Org.BouncyCastle.Pqc.Crypto.Falcon
{
    public sealed class FalconParameters 
        : ICipherParameters
    {
        public static readonly FalconParameters falcon_512 = new FalconParameters("falcon512", 9, 40);
        public static readonly FalconParameters falcon_1024 = new FalconParameters("falcon1024", 10, 40);

        private readonly string name;
        private readonly uint logn;
        private readonly uint nonce_length;

        private FalconParameters(string name, uint logn, uint nonce_length)
        {
            this.name = name;
            this.logn = logn;
            this.nonce_length = nonce_length;
        }

        public int LogN => Convert.ToInt32(logn);

        public int NonceLength => Convert.ToInt32(nonce_length);

        public string Name => name;
    }
}
