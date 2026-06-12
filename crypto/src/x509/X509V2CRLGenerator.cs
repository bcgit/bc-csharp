using System;
using System.Collections.Generic;

using Org.BouncyCastle.Asn1;
using Org.BouncyCastle.Asn1.X509;
using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Math;

namespace Org.BouncyCastle.X509
{
    /// <summary>
    /// Generator for X.509 version 2 certificate revocation lists (CRLs) as defined in RFC 5280.
    /// Builds the TBSCertList structure, optional CRL extensions, and signs the result via
    /// <see cref="Generate(ISignatureFactory)"/>.
    /// </summary>
    public class X509V2CrlGenerator
    {
        private readonly X509ExtensionsGenerator m_extGenerator = new X509ExtensionsGenerator();

        private V2TbsCertListGenerator m_tbsGen;

        /// <summary>
        /// Creates an empty version 2 CRL generator.
        /// </summary>
        public X509V2CrlGenerator()
        {
            m_tbsGen = new V2TbsCertListGenerator();
        }

        /// <summary>
        /// Creates a generator for a version 2 CRL, initialised from another CRL.
        /// </summary>
        /// <param name="template">Template CRL to base the new one on.</param>
        public X509V2CrlGenerator(X509Crl template)
            : this(template.CertificateList)
        {
        }

        /// <summary>
        /// Creates a generator for a version 2 CRL, initialised from a parsed
        /// <see cref="CertificateList"/> structure.
        /// </summary>
        /// <param name="template">Template certificate list to copy issuer, dates, entries and extensions from.</param>
        public X509V2CrlGenerator(CertificateList template)
        {
            m_tbsGen = new V2TbsCertListGenerator();
            m_tbsGen.SetIssuer(template.Issuer);
            m_tbsGen.SetThisUpdate(template.ThisUpdate);
            m_tbsGen.SetNextUpdate(template.NextUpdate);

            AddCrl(new X509Crl(template));

            var extensions = template.TbsCertList.Extensions;
            if (extensions != null)
            {
                foreach (var oid in extensions.ExtensionOids)
                {
                    if (X509Extensions.AltSignatureAlgorithm.Equals(oid) ||
                        X509Extensions.AltSignatureValue.Equals(oid))
                    {
                        continue;
                    }

                    var extension = extensions.GetExtension(oid);
                    m_extGenerator.AddExtension(oid, extension.IsCritical, extension.Value.GetOctets());
                }
            }
        }

        /// <summary>
        /// Resets the generator to an empty CRL state, discarding issuer, dates, entries and extensions.
        /// </summary>
        public void Reset()
        {
            m_tbsGen = new V2TbsCertListGenerator();
            m_extGenerator.Reset();
        }

        /// <summary>
        /// Sets the issuer distinguished name — the entity whose private key signs the CRL.
        /// </summary>
        /// <param name="issuer">The issuer's distinguished name.</param>
        public void SetIssuerDN(X509Name issuer)
        {
            m_tbsGen.SetIssuer(issuer);
        }

        /// <summary>
        /// Sets the time at which this CRL was issued (<c>thisUpdate</c> in the TBSCertList).
        /// </summary>
        /// <param name="date">The issue time.</param>
        public void SetThisUpdate(DateTime date)
        {
            m_tbsGen.SetThisUpdate(new Time(date));
        }

        /// <summary>
        /// Sets the time by which the next CRL in the sequence is expected to be issued
        /// (<c>nextUpdate</c> in the TBSCertList).
        /// </summary>
        /// <param name="date">The next update time.</param>
        public void SetNextUpdate(DateTime date)
        {
            m_tbsGen.SetNextUpdate(new Time(date));
        }

        /// <summary>
        /// Adds a revoked-certificate entry with an optional <see cref="CrlReason"/> code.
        /// </summary>
        /// <param name="userCertificate">Serial number of the revoked certificate.</param>
        /// <param name="revocationDate">The revocation date.</param>
        /// <param name="reason">
        /// Reason code as defined by <see cref="CrlReason"/> (for example
        /// <see cref="CrlReason.KeyCompromise"/>), or <c>0</c> to omit a reason extension.
        /// </param>
        public void AddCrlEntry(BigInteger userCertificate, DateTime revocationDate, int reason)
        {
            m_tbsGen.AddCrlEntry(new DerInteger(userCertificate), new Time(revocationDate), reason);
        }

        /// <summary>
        /// Adds a revoked-certificate entry with <see cref="CrlReason"/> and an Invalidity Date extension.
        /// </summary>
        /// <param name="userCertificate">Serial number of the revoked certificate.</param>
        /// <param name="revocationDate">The revocation date.</param>
        /// <param name="reason">
        /// Reason code as defined by <see cref="CrlReason"/>, or <c>0</c> to omit a reason extension.
        /// </param>
        /// <param name="invalidityDate">The invalidity date carried in the Invalidity Date extension.</param>
        public void AddCrlEntry(BigInteger userCertificate, DateTime revocationDate, int reason,
            DateTime invalidityDate)
        {
            m_tbsGen.AddCrlEntry(new DerInteger(userCertificate), new Time(revocationDate), reason,
                Rfc5280Asn1Utilities.CreateGeneralizedTime(invalidityDate));
        }

        /// <summary>
        /// Adds a revoked-certificate entry with caller-supplied CRL entry extensions.
        /// </summary>
        /// <param name="userCertificate">Serial number of the revoked certificate.</param>
        /// <param name="revocationDate">The revocation date.</param>
        /// <param name="extensions">Extensions to attach to this CRL entry.</param>
        public void AddCrlEntry(BigInteger userCertificate, DateTime revocationDate, X509Extensions extensions)
        {
            m_tbsGen.AddCrlEntry(new DerInteger(userCertificate), new Time(revocationDate), extensions);
        }

        /// <summary>
        /// Copies all revoked-certificate entries from another CRL into this generator.
        /// </summary>
        /// <param name="other">The CRL whose entries are to be added.</param>
        /// <exception cref="ArgumentNullException"><paramref name="other"/> is <c>null</c>.</exception>
        public void AddCrl(X509Crl other)
        {
            if (other == null)
                throw new ArgumentNullException(nameof(other));

            var revocations = other.GetRevokedCertificates();

            if (revocations != null)
            {
                foreach (X509CrlEntry entry in revocations)
                {
                    m_tbsGen.AddCrlEntry(Asn1Sequence.GetInstance(entry.CrlEntry));
                }
            }
        }

        /// <summary>
        /// Adds a CRL extension identified by a dotted-decimal OID string.
        /// </summary>
        /// <param name="oid">Dotted-decimal object identifier.</param>
        /// <param name="critical"><c>true</c> if the extension is marked critical.</param>
        /// <param name="extensionValue">The DER-encoded extension value.</param>
        public void AddExtension(string oid, bool critical, Asn1Encodable extensionValue)
        {
            m_extGenerator.AddExtension(new DerObjectIdentifier(oid), critical, extensionValue);
        }

        /// <summary>
        /// Adds a CRL extension.
        /// </summary>
        /// <param name="oid">The extension object identifier.</param>
        /// <param name="critical"><c>true</c> if the extension is marked critical.</param>
        /// <param name="extensionValue">The DER-encoded extension value.</param>
        public void AddExtension(DerObjectIdentifier oid, bool critical, Asn1Encodable extensionValue)
        {
            m_extGenerator.AddExtension(oid, critical, extensionValue);
        }

        /// <summary>
        /// Adds a CRL extension identified by a dotted-decimal OID string.
        /// </summary>
        /// <param name="oid">Dotted-decimal object identifier.</param>
        /// <param name="critical"><c>true</c> if the extension is marked critical.</param>
        /// <param name="extensionValue">Raw octets of the extension value.</param>
        public void AddExtension(string oid, bool critical, byte[] extensionValue)
        {
            m_extGenerator.AddExtension(new DerObjectIdentifier(oid), critical, DerOctetString.FromContents(extensionValue));
        }

        /// <summary>
        /// Adds a CRL extension.
        /// </summary>
        /// <param name="oid">The extension object identifier.</param>
        /// <param name="critical"><c>true</c> if the extension is marked critical.</param>
        /// <param name="extensionValue">Raw octets of the extension value.</param>
        public void AddExtension(DerObjectIdentifier oid, bool critical, byte[] extensionValue)
        {
            m_extGenerator.AddExtension(oid, critical, DerOctetString.FromContents(extensionValue));
        }

        /// <summary>
        /// Generate a new <see cref="X509Crl"/> using the provided <see cref="ISignatureFactory"/>.
        /// </summary>
        /// <param name="signatureFactory">A <see cref="ISignatureFactory">signature factory</see> with the necessary
        /// algorithm details.</param>
        /// <returns>An <see cref="X509Crl"/>.</returns>
        public X509Crl Generate(ISignatureFactory signatureFactory)
        {
            var sigAlgID = (AlgorithmIdentifier)signatureFactory.AlgorithmDetails;

            m_tbsGen.SetSignature(sigAlgID);

            if (!m_extGenerator.IsEmpty)
            {
                m_tbsGen.SetExtensions(m_extGenerator.Generate());
            }

            var tbsCertList = m_tbsGen.GenerateTbsCertList();

            var signature = X509Utilities.GenerateSignature(signatureFactory, tbsCertList);

            return new X509Crl(CertificateList.GetInstance(new DerSequence(tbsCertList, sigAlgID, signature)));
        }

        /// <summary>
        /// Generate a new <see cref="X509Crl"/> using the provided <see cref="ISignatureFactory"/> and
        /// containing altSignatureAlgorithm and altSignatureValue extensions based on the passed
        /// <paramref name="altSignatureFactory"/>.
        /// </summary>
        /// <param name="signatureFactory">A <see cref="ISignatureFactory">signature factory</see> with the necessary
        /// algorithm details.</param>
        /// <param name="isCritical">Whether the 'alt' extensions should be marked critical.</param>
        /// <param name="altSignatureFactory">A <see cref="ISignatureFactory">signature factory</see> used to create the
        /// altSignatureAlgorithm and altSignatureValue extensions.</param>
        /// <returns>An <see cref="X509Crl"/>.</returns>
        public X509Crl Generate(ISignatureFactory signatureFactory, bool isCritical,
            ISignatureFactory altSignatureFactory)
        {
            m_tbsGen.SetSignature(null);

            var altSigAlgID = (AlgorithmIdentifier)altSignatureFactory.AlgorithmDetails;
            m_extGenerator.AddExtension(X509Extensions.AltSignatureAlgorithm, isCritical, altSigAlgID);

            m_tbsGen.SetExtensions(m_extGenerator.Generate());

            var altSignature = X509Utilities.GenerateSignature(altSignatureFactory, m_tbsGen.GeneratePreTbsCertList());
            m_extGenerator.AddExtension(X509Extensions.AltSignatureValue, isCritical, altSignature);

            return Generate(signatureFactory);
        }

        /// <summary>
        /// Allows enumeration of the signature names supported by the generator.
        /// </summary>
        [Obsolete("Will be removed")]
        public IEnumerable<string> SignatureAlgNames => X509Utilities.GetAlgNames();
    }
}
