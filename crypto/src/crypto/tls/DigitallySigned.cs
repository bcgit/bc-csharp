using System;
using System.IO;

namespace Org.BouncyCastle.Crypto.Tls
{


    public class DigitallySigned
    {
        protected SignatureAndHashAlgorithm algorithm;
        protected byte[] signature;

        public DigitallySigned(SignatureAndHashAlgorithm algorithm, byte[] signature)
        {
            if (signature == null)
            {
                throw new ArgumentException("'signature' cannot be null");
            }

            this.algorithm = algorithm;
            this.signature = signature;
        }

        /**
         * @return a {@link SignatureAndHashAlgorithm} (or null before TLS 1.2).
         */
        public SignatureAndHashAlgorithm Algorithm
        {
            get
            {
                return algorithm;
            }
        }

        public byte[] Signature
        {
            get
            {
                return signature;
            }
        }

        /**
         * Encode this {@link DigitallySigned} to an {@link Stream}.
         * 
         * @param output
         *            the {@link Stream} to encode to.
         * @throws IOException
         */
        public void Encode(Stream output)
        {
            if (algorithm != null)
            {
                algorithm.Encode(output);
            }
            TlsUtilities.WriteOpaque16(signature, output);
        }

        /**
         * Parse a {@link DigitallySigned} from an {@link InputStream}.
         * 
         * @param context
         *            the {@link TlsContext} of the current connection.
         * @param input
         *            the {@link InputStream} to parse from.
         * @return a {@link DigitallySigned} object.
         * @throws IOException
         */
        public static DigitallySigned Parse(TlsContext context, Stream input)
        {
            SignatureAndHashAlgorithm algorithm = null;
            if (TlsUtilities.IsTLSv12(context))
            {
                algorithm = SignatureAndHashAlgorithm.Parse(input);
            }
            byte[] signature = TlsUtilities.ReadOpaque16(input);
            return new DigitallySigned(algorithm, signature);
        }
    }
}

