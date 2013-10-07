using System.IO;
using System;
namespace Org.BouncyCastle.Crypto.Tls
{
    public class HeartbeatExtension
    {
        private short mode;

        public HeartbeatExtension(short mode)
        {
            if (!HeartbeatMode.IsValid(mode))
            {
                throw new ArgumentException("'mode' is not a valid HeartbeatMode value");
            }

            this.mode = mode;
        }

        public short Mode
        {
            get
            {
                return mode;
            }
        }

        /**
         * Encode this {@link HeartbeatExtension} to an {@link Stream}.
         * 
         * @param output
         *            the {@link Stream} to encode to.
         * @throws IOException
         */
        public void encode(Stream output)
        {
            TlsUtilities.WriteUint8(mode, output);
        }

        /**
         * Parse a {@link HeartbeatExtension} from an {@link InputStream}.
         * 
         * @param input
         *            the {@link InputStream} to parse from.
         * @return a {@link HeartbeatExtension} object.
         * @throws IOException
         */
        public static HeartbeatExtension parse(Stream input)
        {
            short mode = TlsUtilities.ReadUint8(input);

            if (!HeartbeatMode.IsValid(mode))
            {
                throw new TlsFatalAlert(AlertDescription.illegal_parameter);
            }

            return new HeartbeatExtension(mode);
        }
    }

}