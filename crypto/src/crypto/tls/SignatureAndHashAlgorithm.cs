using System;
using System.IO;

namespace Org.BouncyCastle.Crypto.Tls
{

    /**
     * RFC 5246 7.4.1.4.1
     */
    public class SignatureAndHashAlgorithm
    {
        protected short hash;
        protected short signature;

        /**
         * @param hash      {@link HashAlgorithm}
         * @param signature {@link SignatureAlgorithm}
         */
        public SignatureAndHashAlgorithm(short hash, short signature)
        {
            if (!TlsUtilities.IsValidUint8(hash))
            {
                throw new ArgumentException("'hash' should be a uint8");
            }
            if (!TlsUtilities.IsValidUint8(signature))
            {
                throw new ArgumentException("'signature' should be a uint8");
            }
            if (signature == SignatureAlgorithm.anonymous)
            {
                throw new ArgumentException("'signature' MUST NOT be \"anonymous\"");
            }

            this.hash = hash;
            this.signature = signature;
        }

        /**
         * @return {@link HashAlgorithm}
         */
        public short Hash
        {
            get
            {
                return hash;
            }
        }

        /**
         * @return {@link SignatureAlgorithm}
         */
        public short Signature
        {
            get
            {
                return signature;
            }
        }

        public override bool Equals(Object obj)
        {
            if (!(obj is SignatureAndHashAlgorithm))
            {
                return false;
            }
            SignatureAndHashAlgorithm other = (SignatureAndHashAlgorithm)obj;
            return Hash == Hash && other.Signature == Signature;
        }

        public override int GetHashCode()
        {
            return (int)(((uint)Hash << 16) | (ushort)Signature);
        }

        /**
         * Encode this {@link SignatureAndHashAlgorithm} to an {@link Stream}.
         *
         * @param output the {@link Stream} to encode to.
         * @throws IOException
         */
        public void Encode(Stream output)
        {
            TlsUtilities.WriteUint8(hash, output);
            TlsUtilities.WriteUint8(signature, output);
        }

        /**
         * Parse a {@link SignatureAndHashAlgorithm} from an {@link InputStream}.
         *
         * @param input the {@link InputStream} to parse from.
         * @return a {@link SignatureAndHashAlgorithm} object.
         * @throws IOException
         */
        public static SignatureAndHashAlgorithm Parse(Stream input)
        {
            short hash = TlsUtilities.ReadUint8(input);
            short signature = TlsUtilities.ReadUint8(input);
            return new SignatureAndHashAlgorithm(hash, signature);
        }
    }
}