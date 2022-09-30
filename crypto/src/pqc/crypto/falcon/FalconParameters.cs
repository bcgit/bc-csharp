using Org.BouncyCastle.Crypto;

namespace Org.BouncyCastle.Pqc.Crypto.Falcon
{
    public sealed class FalconParameters 
        : ICipherParameters
    {
        public static FalconParameters falcon_512 = new FalconParameters("falcon512", 9, 40);
        public static FalconParameters falcon_1024 = new FalconParameters("falcon1024", 10, 40);

        private string name;
        private uint logn;
        private uint nonce_length;

        private FalconParameters(string name, uint logn, uint nonce_length)
        {
            this.name = name;
            this.logn = logn;
            this.nonce_length = nonce_length;
        }

        public uint LogN => logn;

        public uint NonceLength => nonce_length;

        public string Name => name;
    }
}
