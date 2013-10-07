using Org.BouncyCastle.Utilities;
using System;
using System.IO;

namespace Org.BouncyCastle.Crypto.Tls
{


    /**
     * RFC 6066 5.
     */
    public class URLAndHash
    {
        protected string url;
        protected byte[] sha1Hash;

        public URLAndHash(string url, byte[] sha1Hash)
        {
            if (url == null || url.Length < 1 || url.Length >= (1 << 16))
            {
                throw new ArgumentException("'url' must have length from 1 to (2^16 - 1)");
            }
            if (sha1Hash != null && sha1Hash.Length != 20)
            {
                throw new ArgumentException("'sha1Hash' must have length == 20, if present");
            }

            this.url = url;
            this.sha1Hash = sha1Hash;
        }

        public string URL
        {
            get
            {
                return url;
            }
        }

        public byte[] Sha1Hash
        {
            get
            {
                return sha1Hash;
            }
        }

        /**
         * Encode this {@link URLAndHash} to an {@link Stream}.
         *
         * @param output the {@link Stream} to encode to.
         * @throws IOException
         */
        public void encode(Stream output)
        {
            byte[] urlEncoding = Strings.ToByteArray(this.url);
            TlsUtilities.WriteOpaque16(urlEncoding, output);

            if (this.sha1Hash == null)
            {
                TlsUtilities.WriteUint8(0, output);
            }
            else
            {
                TlsUtilities.WriteUint8(1, output);
                output.Write(this.sha1Hash, 0, this.sha1Hash.Length);
            }
        }

        /**
         * Parse a {@link URLAndHash} from an {@link InputStream}.
         * 
         * @param context
         *            the {@link TlsContext} of the current connection.
         * @param input
         *            the {@link InputStream} to parse from.
         * @return a {@link URLAndHash} object.
         * @throws IOException
         */
        public static URLAndHash parse(TlsContext context, Stream input)
        {
            byte[] urlEncoding = TlsUtilities.ReadOpaque16(input);
            if (urlEncoding.Length < 1)
            {
                throw new TlsFatalAlert(AlertDescription.illegal_parameter);
            }
            String url = Strings.FromByteArray(urlEncoding);

            byte[] sha1Hash = null;
            short padding = TlsUtilities.ReadUint8(input);
            switch (padding)
            {
                case 0:
                    if (TlsUtilities.IsTLSv12(context))
                    {
                        throw new TlsFatalAlert(AlertDescription.illegal_parameter);
                    }
                    break;
                case 1:
                    sha1Hash = TlsUtilities.ReadFully(20, input);
                    break;
                default:
                    throw new TlsFatalAlert(AlertDescription.illegal_parameter);
            }

            return new URLAndHash(url, sha1Hash);
        }
    }
}

