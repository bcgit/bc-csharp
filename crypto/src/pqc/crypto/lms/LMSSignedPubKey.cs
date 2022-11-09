using System;

using Org.BouncyCastle.Utilities;

namespace Org.BouncyCastle.Pqc.Crypto.Lms
{
    public class LmsSignedPubKey
        : IEncodable
    {
        private LmsSignature signature;
        private LmsPublicKeyParameters publicKey;

        public LmsSignedPubKey(LmsSignature signature, LmsPublicKeyParameters publicKey)
        {
            this.signature = signature;
            this.publicKey = publicKey;
        }


        public LmsSignature GetSignature()
        {
            return signature;
        }

        public LmsPublicKeyParameters GetPublicKey()
        {
            return publicKey;
        }

        public override  bool Equals(Object o)
        {
            if (this == o)
            {
                return true;
            }
            if (o == null || GetType() != o.GetType())
            {
                return false;
            }

            LmsSignedPubKey that = (LmsSignedPubKey)o;

            if (signature != null ? !signature.Equals(that.signature) : that.signature != null)
            {
                return false;
            }
            return publicKey != null ? publicKey.Equals(that.publicKey) : that.publicKey == null;
        }
        
        public override int GetHashCode()
        {
            int result = signature != null ? signature.GetHashCode() : 0;
            result = 31 * result + (publicKey != null ? publicKey.GetHashCode() : 0);
            return result;
        }

        public byte[] GetEncoded()
        {
            return Composer.Compose()
                .Bytes(signature.GetEncoded())
                .Bytes(publicKey.GetEncoded())
                .Build();
        }
    }
}