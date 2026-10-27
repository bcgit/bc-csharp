using System;
using System.Collections.Generic;
using System.IO;

using Org.BouncyCastle.Asn1;
using Org.BouncyCastle.Asn1.X509;
using Org.BouncyCastle.Security.Certificates;
using Org.BouncyCastle.Utilities.IO;

namespace Org.BouncyCastle.X509
{
    /// <summary>Parser for cross certificate pairs, in DER or PEM form.</summary>
    public class X509CertPairParser
    {
        private Stream currentStream;

        private X509CertificatePair ReadDerCrossCertificatePair(Stream inStream)
        {
            using (var asn1In = new Asn1InputStream(inStream, leaveOpen: true))
            {
                return new X509CertificatePair(CertificatePair.GetInstance(asn1In.ReadObject()));
            }
        }

        /// <summary>Read the next certificate pair from the encoded data.</summary>
        /// <param name="input">The encoded data.</param>
        public X509CertificatePair ReadCertPair(byte[] input) => ReadCertPair(new MemoryStream(input, false));

        /// <summary>Read all the certificate pairs from the encoded data.</summary>
        /// <param name="input">The encoded data.</param>
        public IList<X509CertificatePair> ReadCertPairs(byte[] input) => ReadCertPairs(new MemoryStream(input, false));

        /// <summary>Read the next certificate pair from the stream.</summary>
        /// <param name="inStream">The stream to read from.</param>
        /// <returns>The pair, or null if the end of the stream has been reached.</returns>
        /// <exception cref="ArgumentNullException"><paramref name="inStream"/> is null.</exception>
        /// <exception cref="CertificateException">The data cannot be parsed.</exception>
        public X509CertificatePair ReadCertPair(Stream inStream)
        {
            if (inStream == null)
                throw new ArgumentNullException(nameof(inStream));
            if (!inStream.CanRead)
                throw new ArgumentException("must be read-able", nameof(inStream));

            if (currentStream == null)
            {
                currentStream = inStream;
            }
            else if (currentStream != inStream) // reset if input stream has changed
            {
                currentStream = inStream;
            }

            try
            {
                int tag = inStream.ReadByte();
                if (tag < 0)
                    return null;

                if (inStream.CanSeek)
                {
                    inStream.Seek(-1L, SeekOrigin.Current);
                }
                else
                {
                    PushbackStream pis = new PushbackStream(inStream);
                    pis.Unread(tag);
                    inStream = pis;
                }

                return ReadDerCrossCertificatePair(inStream);
            }
            catch (CertificateException)
            {
                throw;
            }
            catch (Exception e)
            {
                throw new CertificateException(e.ToString());
            }
        }

        /// <summary>Read all the remaining certificate pairs from the stream.</summary>
        /// <param name="inStream">The stream to read from.</param>
        /// <returns>The pairs read; the list may be empty.</returns>
        /// <exception cref="CertificateException">The data cannot be parsed.</exception>
        public IList<X509CertificatePair> ReadCertPairs(Stream inStream)
        {
            var certPairs = new List<X509CertificatePair>();

            X509CertificatePair certPair;
            while ((certPair = ReadCertPair(inStream)) != null)
            {
                certPairs.Add(certPair);
            }

            return certPairs;
        }
    }
}
