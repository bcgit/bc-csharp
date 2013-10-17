using System;
using System.Collections;
using System.IO;
using Org.BouncyCastle.Utilities;

namespace Org.BouncyCastle.Crypto.Tls
{

    /*
     * RFC 3546 3.3
     */
    public class CertificateURL
    {
        protected short type;
        protected IList urlAndHashList;

        /**
         * @param type
         *            see {@link CertChainType} for valid constants.
         * @param urlAndHashList
         *            a {@link IList} of {@link URLAndHash}.
         */
        public CertificateURL(short type, IList urlAndHashList)
        {
            if (!CertChainType.isValid(type))
            {
                throw new ArgumentException("'type' is not a valid CertChainType value");
            }
            if (urlAndHashList == null || urlAndHashList.Count == 0)
            {
                throw new ArgumentException("'urlAndHashList' must have length > 0");
            }

            this.type = type;
            this.urlAndHashList = urlAndHashList;
        }

        /**
         * @return {@link CertChainType}
         */
        public short Type
        {
            get
            {
                return type;
            }
        }

        /**
         * @return a {@link IList} of {@link URLAndHash} 
         */
        public IEnumerable URLAndHashList
        {
            get
            {
                return urlAndHashList;
            }
        }

        /**
         * Encode this {@link CertificateURL} to an {@link Stream}.
         *
         * @param output the {@link Stream} to encode to.
         * @throws IOException
         */
        public void Encode(Stream output)
        {
            TlsUtilities.WriteUint8(this.type, output);

            ListBuffer16 buf = new ListBuffer16();
            for (int i = 0; i < this.urlAndHashList.Count; ++i)
            {
                URLAndHash urlAndHash = (URLAndHash)this.urlAndHashList[i];
                urlAndHash.encode(buf);
            }

            buf.encodeTo(output);
        }

        /**
         * Parse a {@link CertificateURL} from an {@link InputStream}.
         * 
         * @param context
         *            the {@link TlsContext} of the current connection.
         * @param input
         *            the {@link InputStream} to parse from.
         * @return a {@link CertificateURL} object.
         * @throws IOException
         */
        public static CertificateURL Parse(TlsContext context, Stream input)
        {
            short type = TlsUtilities.ReadUint8(input);
            if (!CertChainType.isValid(type))
            {
                throw new TlsFatalAlert(AlertDescription.decode_error);
            }

            int totalLength = TlsUtilities.ReadUint16(input);
            if (totalLength < 1)
            {
                throw new TlsFatalAlert(AlertDescription.decode_error);
            }

            byte[] urlAndHashListData = TlsUtilities.ReadFully(totalLength, input);

            MemoryStream buf = new MemoryStream(urlAndHashListData);

            IList url_and_hash_list = Platform.CreateArrayList();
            while (buf.Length - buf.Position > 0)
            {
                URLAndHash url_and_hash = URLAndHash.parse(context, buf);
                url_and_hash_list.Add(url_and_hash);
            }

            return new CertificateURL(type, url_and_hash_list);
        }

        // TODO Could be more generally useful
        class ListBuffer16 : MemoryStream
        {
            public ListBuffer16()
            {
                // Reserve space for length
                TlsUtilities.WriteUint16(0, this);
            }

            public void encodeTo(Stream output)
            {
                // Patch actual length back in
                int length = (int)Length - 2;
                TlsUtilities.CheckUint16(length);
                var buf = GetBuffer();
                TlsUtilities.WriteUint16(length, buf, 0);
                output.Write(buf, 0, (int)Length);
                buf = null;
            }
        }
    }

}