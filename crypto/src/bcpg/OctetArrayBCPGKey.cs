using Org.BouncyCastle.Utilities;
using System;

namespace Org.BouncyCastle.Bcpg
{
    /**
     * Public/Secret BcpgKey which is encoded as an array of octets rather than an MPI
     * 
     */
    public abstract class OctetArrayBcpgKey
        : BcpgObject, IBcpgKey
    {
        private readonly byte[] key;

        protected OctetArrayBcpgKey(int length, BcpgInputStream bcpgIn)
        {
            key = new byte[length];
            bcpgIn.ReadFully(key);
        }

        protected OctetArrayBcpgKey(int length, byte[] key)
        {
            if (key.Length != length)
            {
                throw new ArgumentException("unexpected key encoding length: expected " + length + " bytes, got " + key.Length);
            }

            this.key = Arrays.Clone(key);
        }

        /// <inheritdoc/>
        public string Format
        {
            get { return "PGP"; }
        }

        /// <inheritdoc/>
        public override void Encode(BcpgOutputStream bcpgOut)
        {
            bcpgOut.Write(key);
        }

        public byte[] GetKey()
        {
            return Arrays.Clone(key);
        }
    }
}