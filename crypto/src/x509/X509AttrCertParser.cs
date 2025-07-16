using System;
using System.Collections.Generic;
using System.IO;

using Org.BouncyCastle.Asn1;
using Org.BouncyCastle.Asn1.Pkcs;
using Org.BouncyCastle.Asn1.X509;
using Org.BouncyCastle.Security.Certificates;
using Org.BouncyCastle.Utilities.IO;

namespace Org.BouncyCastle.X509
{
    public class X509AttrCertParser
    {
        private static readonly PemParser PemAttrCertParser = new PemParser("ATTRIBUTE CERTIFICATE");

        private Asn1Set sData;
        private int sDataObjectCount;
        private Stream currentStream;

        private X509V2AttributeCertificate ReadDerCertificate(Asn1InputStream dIn)
        {
            Asn1Sequence seq = (Asn1Sequence)dIn.ReadObject();

            if (seq.Count > 1 && seq[0] is DerObjectIdentifier contentType)
            {
                if (PkcsObjectIdentifiers.SignedData.Equals(contentType))
                {
                    if (Asn1Utilities.TryGetOptionalContextTagged(seq[1], 0, true, out var signedData,
                        SignedData.GetTagged))
                    {
                        sData = signedData.Certificates;
                        return GetCertificate();
                    }
                }
            }

            return new X509V2AttributeCertificate(AttributeCertificate.GetInstance(seq));
        }

        private X509V2AttributeCertificate ReadPemCertificate(Stream inStream)
        {
            Asn1Sequence seq = PemAttrCertParser.ReadPemObject(inStream);

            return seq == null ? null : new X509V2AttributeCertificate(AttributeCertificate.GetInstance(seq));
        }

        private X509V2AttributeCertificate GetCertificate()
        {
            if (sData != null)
            {
                while (sDataObjectCount < sData.Count)
                {
                    if (Asn1Utilities.TryGetOptionalContextTagged(sData[sDataObjectCount++], 2, false,
                        out var attributeCertificate, AttributeCertificate.GetTagged))
                    {
                        return new X509V2AttributeCertificate(attributeCertificate);
                    }
                }
            }

            return null;
        }

        /// <summary>
        /// Create loading data from byte array.
        /// </summary>
        /// <param name="input"></param>
        public X509V2AttributeCertificate ReadAttrCert(byte[] input)
        {
            using (var inStream = new MemoryStream(input, false))
            {
                return ReadAttrCert(inStream);
            }
        }

        /// <summary>
        /// Create loading data from byte array.
        /// </summary>
        /// <param name="input"></param>
        public IList<X509V2AttributeCertificate> ReadAttrCerts(byte[] input)
        {
            using (var inStream = new MemoryStream(input, false))
            {
                return ReadAttrCerts(inStream);
            }
        }

        /**
         * Generates a certificate object and initializes it with the data
         * read from the input stream inStream.
         */
        public X509V2AttributeCertificate ReadAttrCert(Stream inStream)
        {
            if (inStream == null)
                throw new ArgumentNullException(nameof(inStream));
            if (!inStream.CanRead)
                throw new ArgumentException("Stream must be read-able", nameof(inStream));

            if (currentStream == null)
            {
                currentStream = inStream;
                sData = null;
                sDataObjectCount = 0;
            }
            else if (currentStream != inStream) // reset if input stream has changed
            {
                currentStream = inStream;
                sData = null;
                sDataObjectCount = 0;
            }

            try
            {
                if (sData != null)
                {
                    if (sDataObjectCount != sData.Count)
                        return GetCertificate();

                    sData = null;
                    sDataObjectCount = 0;
                    // TODO[api] Consider removing this and continuing directly
                    return null;
                }

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

                if (tag != 0x30)  // assume ascii PEM encoded.
                    return ReadPemCertificate(inStream);

                using (var asn1In = new Asn1InputStream(inStream, int.MaxValue, leaveOpen: true))
                {
                    return ReadDerCertificate(asn1In);
                }
            }
            catch (CertificateException)
            {
                throw;
            }
            catch (Exception e)
            {
                throw new CertificateException("Failed to read attribute certificate", e);
            }
        }

        /**
         * Returns a (possibly empty) collection view of the certificates
         * read from the given input stream inStream.
         */
        public IList<X509V2AttributeCertificate> ReadAttrCerts(Stream inStream) =>
            new List<X509V2AttributeCertificate>(ParseAttrCerts(inStream));

        public IEnumerable<X509V2AttributeCertificate> ParseAttrCerts(Stream inStream)
        {
            X509V2AttributeCertificate attrCert;
            while ((attrCert = ReadAttrCert(inStream)) != null)
            {
                yield return attrCert;
            }
        }
    }
}
