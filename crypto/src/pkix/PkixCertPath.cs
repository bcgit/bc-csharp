using System;
using System.Collections.Generic;
using System.IO;

using Org.BouncyCastle.Asn1;
using Org.BouncyCastle.Asn1.Pkcs;
using Org.BouncyCastle.Asn1.X509;
using Org.BouncyCastle.OpenSsl;
using Org.BouncyCastle.Security.Certificates;
using Org.BouncyCastle.Utilities;
using Org.BouncyCastle.Utilities.Collections;
using Org.BouncyCastle.X509;

namespace Org.BouncyCastle.Pkix
{
    /// <summary>An immutable sequence of X.509 certificates (a certification path).</summary>
    /// <remarks>
    /// By convention, X.509 certification paths are ordered starting with the target certificate and ending with a
    /// certificate issued by the trust anchor. That is, the issuer of one certificate is the subject of the following
    /// one. The certificate representing the <see cref="TrustAnchor"/> should not be included in the path.
    /// Unvalidated paths may not follow these conventions; <see cref="PkixCertPathValidator"/> will detect any
    /// departure from them that makes the path invalid and throw a <see cref="PkixCertPathValidatorException"/>.
    /// <para>
    /// A path can be encoded as "PkiPath" (the default), "PEM" or "PKCS7", see <see cref="Encodings"/>. Because the
    /// path is immutable it can safely be shared between threads.
    /// </para>
    /// </remarks>
    public class PkixCertPath
    {
        private static readonly List<string> EncodingNames = new List<string> { "PkiPath", "PEM", "PKCS7" };

        private readonly IList<X509Certificate> m_certificates;

        private static bool IsAlreadySorted(IList<X509Certificate> certs)
        {
            var issuer = certs[0].IssuerDN;
            for (int i = 1; i < certs.Count; ++i)
            {
                X509Certificate cert = certs[i];

                if (!issuer.Equivalent(cert.SubjectDN, true))
                    return false;

                issuer = cert.IssuerDN;
            }
            return true;
        }

        private static IList<X509Certificate> SortCerts(IList<X509Certificate> certs)
        {
            if (certs.Count < 2 || IsAlreadySorted(certs))
                return certs;

            // find end-entity cert
            // The inner "is anyone's issuer == subject?" scan iterates orig (the unchanging snapshot) rather than certs
            // (the working list we remove from), and --i restores the outer index after a remove. Scanning the mutating
            // certs would misclassify an intermediary as an end-entity once its child end-entity had already been
            // removed in an earlier iteration; advancing the outer index past a shifted-down element would skip it
            // entirely. Either alone produces the github (bc-java) #1269 false multi-EE detection that falls back to
            // the unsorted input.
            var retList = new List<X509Certificate>(certs.Count);
            var orig = new List<X509Certificate>(certs);

            for (int i = 0; i < certs.Count; i++)
            {
                X509Certificate cert = certs[i];
                bool found = false;

                X509Name subject = cert.SubjectDN;
                foreach (X509Certificate c in orig)
                {
                    if (c.IssuerDN.Equivalent(subject, true))
                    {
                        found = true;
                        break;
                    }
                }

                if (!found)
                {
                    retList.Add(cert);
                    certs.RemoveAt(i);
                    --i;
                }
            }

            // can only have one end entity cert - something's wrong, give up.
            if (retList.Count > 1)
                return orig;

            for (int i = 0; i != retList.Count; i++)
            {
                var issuer = retList[i].IssuerDN;

                for (int j = 0; j < certs.Count; j++)
                {
                    X509Certificate c = certs[j];
                    if (issuer.Equivalent(c.SubjectDN, true))
                    {
                        retList.Add(c);
                        certs.RemoveAt(j);
                        break;
                    }
                }
            }

            // make sure all certificates are accounted for.
            if (certs.Count > 0)
                return orig;

            return retList;
        }

        /// <summary>Creates a certification path from the given certificates.</summary>
        /// <remarks>The certificates are copied and then put into path order (target certificate first).</remarks>
        /// <param name="certificates">The certificates of the path.</param>
        public PkixCertPath(IList<X509Certificate> certificates)
        {
            m_certificates = SortCerts(new List<X509Certificate>(certificates));
        }

        /// <summary>Reads a certification path from a stream containing a PkiPath encoding.</summary>
        /// <param name="inStream">The stream to read from.</param>
        /// <exception cref="CertificateException">The data cannot be decoded.</exception>
        public PkixCertPath(Stream inStream)
            : this(inStream, "PkiPath")
        {
        }

        /// <summary>Reads a certification path from a stream in the given encoding.</summary>
        /// <param name="inStream">The stream to read from.</param>
        /// <param name="encoding">The name of the encoding: "PkiPath", "PEM" or "PKCS7" (case-insensitive).</param>
        /// <exception cref="CertificateException">The encoding is not supported or the data cannot be decoded.
        /// </exception>
        public PkixCertPath(Stream inStream, string encoding)
        {
            IList<X509Certificate> certs;
            try
            {
                if (Platform.EqualsIgnoreCase("PkiPath", encoding))
                {
                    using (var asn1In = new Asn1InputStream(inStream, leaveOpen: true))
                    {
                        if (!(asn1In.ReadObject() is Asn1Sequence asn1Sequence))
                        {
                            throw new CertificateException(
                                "input stream does not contain a ASN1 SEQUENCE while reading PkiPath encoded data to load CertPath");
                        }

                        var certArray = asn1Sequence.MapElements(
                            element => new X509Certificate(X509CertificateStructure.GetInstance(element.ToAsn1Object())));

                        Array.Reverse(certArray);

                        certs = new List<X509Certificate>(certArray);
                    }
                }
                else if (Platform.EqualsIgnoreCase("PEM", encoding) ||
                         Platform.EqualsIgnoreCase("PKCS7", encoding))
                {
                    certs = new X509CertificateParser().ReadCertificates(inStream);
                }
                else
                {
                    throw new CertificateException("unsupported encoding: " + encoding);
                }
            }
            catch (IOException ex)
            {
                throw new CertificateException("IOException throw while decoding CertPath:\n" + ex.ToString());
            }

            m_certificates = SortCerts(certs);
        }

        /// <summary>Gets the names of the encodings supported by this path, with the default encoding first.
        /// </summary>
        public virtual IEnumerable<string> Encodings
        {
            get { return CollectionUtilities.Proxy(EncodingNames); }
        }

        /// <summary>Compares this certification path for equality with the specified object.</summary>
        /// <remarks>
        /// Two paths are equal if and only if their certificate lists (and by implication the certificates in those
        /// lists) are equal. A path is never equal to an object that is not a <see cref="PkixCertPath"/>.
        /// </remarks>
        /// <param name="obj">The object to test for equality with this certification path.</param>
        /// <returns>true if the specified object is equal to this certification path, false otherwise.</returns>
        public override bool Equals(object obj)
        {
            if (this == obj)
                return true;

            if (!(obj is PkixCertPath that))
                return false;

            var thisCerts = this.Certificates;
            var thatCerts = that.Certificates;

            if (thisCerts.Count != thatCerts.Count)
                return false;

            var e1 = thisCerts.GetEnumerator();
            var e2 = thatCerts.GetEnumerator();

            while (e1.MoveNext())
            {
                e2.MoveNext();

                if (!Equals(e1.Current, e2.Current))
                    return false;
            }

            return true;
        }

        /// <summary>Returns a hash code for this certification path.</summary>
        public override int GetHashCode()
        {
            return m_certificates.GetHashCode();
        }

        /// <summary>Returns the encoded form of this certification path, using the default encoding (PkiPath).
        /// </summary>
        /// <returns>The encoded bytes.</returns>
        /// <exception cref="CertificateEncodingException">An encoding error occurs.</exception>
        public virtual byte[] GetEncoded() => GetEncoded(EncodingNames[0]);

        /// <summary>Returns the encoded form of this certification path, using the specified encoding.</summary>
        /// <param name="encoding">The name of the encoding to use: "PkiPath", "PEM" or "PKCS7" (case-insensitive).
        /// </param>
        /// <returns>The encoded bytes.</returns>
        /// <exception cref="CertificateEncodingException">
        /// An encoding error occurs or the encoding requested is not supported.
        /// </exception>
        public virtual byte[] GetEncoded(string encoding)
        {
            if (Platform.EqualsIgnoreCase(encoding, "PkiPath"))
            {
                Asn1EncodableVector v = new Asn1EncodableVector(m_certificates.Count);
                for (int i = m_certificates.Count - 1; i >= 0; i--)
                {
                    v.Add(ToAsn1Object(m_certificates[i]));
                }

                return ToDerEncoded(new DerSequence(v));
            }
            else if (Platform.EqualsIgnoreCase(encoding, "PKCS7"))
            {
                ContentInfo encInfo = new ContentInfo(PkcsObjectIdentifiers.Data, null);

                Asn1EncodableVector v = new Asn1EncodableVector(m_certificates.Count);
                foreach (var cert in m_certificates)
                {
                    v.Add(ToAsn1Object(cert));
                }

                SignedData sd = new SignedData(
                    DerInteger.One,
                    new DerSet(),
                    encInfo,
                    DerSet.FromVector(v),
                    null,
                    new DerSet());

                return ToDerEncoded(new ContentInfo(PkcsObjectIdentifiers.SignedData, sd));
            }
            else if (Platform.EqualsIgnoreCase(encoding, "PEM"))
            {
                MemoryStream bOut = new MemoryStream();

                try
                {
                    using (var pWrt = new PemWriter(new StreamWriter(bOut)))
                    {
                        foreach (var cert in m_certificates)
                        {
                            pWrt.WriteObject(cert);
                        }
                    }
                }
                catch (Exception)
                {
                    throw new CertificateEncodingException("can't encode certificate for PEM encoded path");
                }

                return bOut.ToArray();
            }
            else
            {
                throw new CertificateEncodingException("unsupported encoding: " + encoding);
            }
        }

        /// <summary>Gets the read-only list of certificates in this certification path.</summary>
        public virtual IList<X509Certificate> Certificates => CollectionUtilities.ReadOnly(m_certificates);

        /**
         * Return a DERObject containing the encoded certificate.
         *
         * @param cert the X509Certificate object to be encoded
         *
         * @return the DERObject
         */
        private Asn1Object ToAsn1Object(X509Certificate cert)
        {
            try
            {
                return cert.CertificateStructure.ToAsn1Object();
            }
            catch (Exception e)
            {
                throw new CertificateEncodingException("Exception while encoding certificate", e);
            }
        }

        private byte[] ToDerEncoded(Asn1Encodable obj)
        {
            try
            {
                return obj.GetEncoded(Asn1Encodable.Der);
            }
            catch (IOException e)
            {
                throw new CertificateEncodingException("Exception thrown", e);
            }
        }
    }
}
