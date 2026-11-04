using System;
using System.Collections.Generic;
using System.IO;

namespace Org.BouncyCastle.Asn1.X509
{
    /**
     * Generator for Version 2 TbsCertList structures.
     * <pre>
     *  TbsCertList  ::=  Sequence  {
     *       version                 Version OPTIONAL,
     *                                    -- if present, shall be v2
     *       signature               AlgorithmIdentifier,
     *       issuer                  Name,
     *       thisUpdate              Time,
     *       nextUpdate              Time OPTIONAL,
     *       revokedCertificates     Sequence OF Sequence  {
     *            userCertificate         CertificateSerialNumber,
     *            revocationDate          Time,
     *            crlEntryExtensions      Extensions OPTIONAL
     *                                          -- if present, shall be v2
     *                                 }  OPTIONAL,
     *       crlExtensions           [0]  EXPLICIT Extensions OPTIONAL
     *                                          -- if present, shall be v2
     *                                 }
     * </pre>
     *
     * <b>Note: This class may be subject to change</b>
     */
    public class V2TbsCertListGenerator
    {
        private DerInteger version = DerInteger.One;
        private AlgorithmIdentifier signature;
        private X509Name issuer;
        private Time thisUpdate, nextUpdate;
        // TODO[api] Eventually should be 'Extensions', but support X509Extensions for now
        private Asn1Encodable m_extensions;
        private List<Asn1Sequence> crlEntries;

        /// <summary>Create a new <see cref="V2TbsCertListGenerator"/>.</summary>
        public V2TbsCertListGenerator()
        {
        }

        /// <summary>Set the signature.</summary>
        /// <param name="signature">The signature.</param>
        public void SetSignature(AlgorithmIdentifier signature)
        {
            this.signature = signature;
        }

        /// <summary>Set the issuer.</summary>
        /// <param name="issuer">The issuer.</param>
        public void SetIssuer(X509Name issuer)
        {
            this.issuer = issuer;
        }

        /// <summary>Set the this update.</summary>
        /// <param name="thisUpdate">The this update.</param>
        public void SetThisUpdate(Asn1UtcTime thisUpdate)
        {
            this.thisUpdate = new Time(thisUpdate);
        }

        /// <summary>Set the next update.</summary>
        /// <param name="nextUpdate">The next update.</param>
        public void SetNextUpdate(Asn1UtcTime nextUpdate)
        {
            this.nextUpdate = (nextUpdate != null)
                ? new Time(nextUpdate)
                : null;
        }

        /// <summary>Set the this update.</summary>
        /// <param name="thisUpdate">The this update.</param>
        public void SetThisUpdate(Time thisUpdate)
        {
            this.thisUpdate = thisUpdate;
        }

        /// <summary>Set the next update.</summary>
        /// <param name="nextUpdate">The next update.</param>
        public void SetNextUpdate(Time nextUpdate)
        {
            this.nextUpdate = nextUpdate;
        }

        /// <summary>Add a CRL entry given as a ready-made sequence.</summary>
        /// <param name="crlEntry">The CRL entry.</param>
        public void AddCrlEntry(Asn1Sequence crlEntry)
        {
            if (crlEntries == null)
            {
                crlEntries = new List<Asn1Sequence>();
            }

            crlEntries.Add(crlEntry);
        }

        /// <summary>Add a CRL entry with a revocation reason.</summary>
        /// <param name="userCertificate">The serial number of the revoked certificate.</param>
        /// <param name="revocationDate">The revocation date.</param>
        /// <param name="reason">The reason code.</param>
        public void AddCrlEntry(DerInteger userCertificate, Asn1UtcTime revocationDate, int reason)
        {
            AddCrlEntry(userCertificate, new Time(revocationDate), reason);
        }

        /// <summary>Add a CRL entry with a revocation reason.</summary>
        /// <param name="userCertificate">The serial number of the revoked certificate.</param>
        /// <param name="revocationDate">The revocation date.</param>
        /// <param name="reason">The reason code.</param>
        public void AddCrlEntry(DerInteger userCertificate, Time revocationDate, int reason)
        {
            AddCrlEntry(userCertificate, revocationDate, reason, null);
        }

        /// <summary>Add a CRL entry with a revocation reason and an invalidity date.</summary>
        /// <param name="userCertificate">The serial number of the revoked certificate.</param>
        /// <param name="revocationDate">The revocation date.</param>
        /// <param name="reason">The reason code.</param>
        /// <param name="invalidityDate">The date from which the certificate is considered invalid.</param>
        public void AddCrlEntry(DerInteger userCertificate, Time revocationDate, int reason,
            Asn1GeneralizedTime invalidityDate)
        {
            var extOids = new List<DerObjectIdentifier>();
            var extValues = new List<X509Extension>();

            if (reason != 0)
            {
                CrlReason crlReason = new CrlReason(reason);

                try
                {
                    extOids.Add(X509Extensions.ReasonCode);
                    extValues.Add(new X509Extension(false, new DerOctetString(crlReason.GetEncoded())));
                }
                catch (IOException e)
                {
                    throw new ArgumentException("error encoding reason: " + e);
                }
            }

            if (invalidityDate != null)
            {
                try
                {
                    extOids.Add(X509Extensions.InvalidityDate);
                    extValues.Add(new X509Extension(false, new DerOctetString(invalidityDate.GetEncoded())));
                }
                catch (IOException e)
                {
                    throw new ArgumentException("error encoding invalidityDate: " + e);
                }
            }

            var extensions = extOids.Count < 1 ? null : new X509Extensions(extOids, extValues);

            AddCrlEntry(userCertificate, revocationDate, extensions);
        }

        /// <summary>Add a CRL entry with extensions.</summary>
        /// <param name="userCertificate">The serial number of the revoked certificate.</param>
        /// <param name="revocationDate">The revocation date.</param>
        /// <param name="extensions">The extensions of the entry.</param>
        public void AddCrlEntry(DerInteger userCertificate, Time revocationDate, X509Extensions extensions)
        {
            Asn1EncodableVector v = new Asn1EncodableVector(userCertificate, revocationDate);
            v.AddOptional(extensions);
            AddCrlEntry(new DerSequence(v));
        }

        /// <summary>Set the extensions.</summary>
        /// <param name="extensions">The extensions.</param>
        public void SetExtensions(X509Extensions extensions)
        {
            //SetExtensions(Extensions.GetInstance(extensions));
            m_extensions = extensions;
        }

        /// <summary>Set the extensions.</summary>
        /// <param name="extensions">The extensions.</param>
        public void SetExtensions(Extensions extensions)
        {
            m_extensions = extensions;
        }

        /// <summary>
        /// Generate the TBSCertList without the signature algorithm, as used when the signature is calculated before
        /// the algorithm is known.
        /// </summary>
        /// <returns>The pre-TBSCertList sequence.</returns>
        public Asn1Sequence GeneratePreTbsCertList()
        {
            if (signature != null)
                throw new InvalidOperationException("Signature should not be set in PreTBSCertList generator");
            if ((issuer == null) || (thisUpdate == null))
                throw new InvalidOperationException("Not all mandatory fields set in V2 PreTBSCertList generator");
            if (issuer.IsEmpty)
                throw new InvalidOperationException("Issuer is an empty distinguished name");

            return GenerateTbsCertificateStructure();
        }

        /// <summary>Generate the TBSCertList from the state of the generator.</summary>
        /// <returns>The TBSCertList.</returns>
        /// <exception cref="InvalidOperationException">A required field has not been set.</exception>
        public TbsCertificateList GenerateTbsCertList()
        {
            if ((signature == null) || (issuer == null) || (thisUpdate == null))
                throw new InvalidOperationException("Not all mandatory fields set in V2 TbsCertList generator.");
            if (issuer.IsEmpty)
                throw new InvalidOperationException("Issuer is an empty distinguished name");

            return TbsCertificateList.GetInstance(GenerateTbsCertificateStructure());
        }

        private Asn1Sequence GenerateTbsCertificateStructure()
        {
            Asn1EncodableVector v = new Asn1EncodableVector(7);

            v.Add(version);
            v.AddOptional(signature);
            v.Add(issuer);
            v.Add(thisUpdate);
            v.AddOptional(nextUpdate);

            // Add CRLEntries if they exist
            if (crlEntries != null && crlEntries.Count > 0)
            {
                v.Add(new DerSequence(crlEntries.ToArray()));
            }

            v.AddOptionalTagged(true, 0, m_extensions);

            return new DerSequence(v);
        }
    }
}
