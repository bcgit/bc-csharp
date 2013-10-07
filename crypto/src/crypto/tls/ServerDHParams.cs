using System;
using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.Math;
using System.IO;

namespace Org.BouncyCastle.Crypto.Tls
{
    public class ServerDHParams
    {
        protected DHPublicKeyParameters publicKey;

        public ServerDHParams(DHPublicKeyParameters publicKey)
        {
            if (publicKey == null)
            {
                throw new ArgumentException("'publicKey' cannot be null");
            }

            this.publicKey = publicKey;
        }

        public DHPublicKeyParameters PublicKey
        {
            get
            {
                return publicKey;
            }
        }

        /**
         * Encode this {@link ServerDHParams} to an {@link Stream}.
         * 
         * @param output
         *            the {@link Stream} to encode to.
         * @throws IOException
         */
        public void Encode(Stream output)
        {
            DHParameters dhParameters = publicKey.Parameters;
            BigInteger Ys = publicKey.Y;

            TlsDHUtilities.WriteDHParameter(dhParameters.P, output);
            TlsDHUtilities.WriteDHParameter(dhParameters.G, output);
            TlsDHUtilities.WriteDHParameter(Ys, output);
        }

        /**
         * Parse a {@link ServerDHParams} from an {@link InputStream}.
         * 
         * @param input
         *            the {@link InputStream} to parse from.
         * @return a {@link ServerDHParams} object.
         * @throws IOException
         */
        public static ServerDHParams Parse(Stream input)
        {
            BigInteger p = TlsDHUtilities.ReadDHParameter(input);
            BigInteger g = TlsDHUtilities.ReadDHParameter(input);
            BigInteger Ys = TlsDHUtilities.ReadDHParameter(input);

            return new ServerDHParams(new DHPublicKeyParameters(Ys, new DHParameters(p, g)));
        }
    }
}