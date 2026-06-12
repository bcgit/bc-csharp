using System;
using System.Collections.Generic;

using Org.BouncyCastle.Asn1;
using Org.BouncyCastle.Asn1.X509;
using Org.BouncyCastle.Math;
using Org.BouncyCastle.Utilities;
using Org.BouncyCastle.Utilities.Collections;
using Org.BouncyCastle.X509.Extension;

namespace Org.BouncyCastle.X509.Store
{
    public class X509CrlStoreSelector
        : ISelector<X509Crl>, ICheckingCertificate
    {
        // TODO Missing criteria?

        private X509Certificate m_certificateChecking;
        private DateTime? m_dateAndTime;
        private IList<X509Name> m_issuers;
        private BigInteger m_maxCrlNumber;
        private BigInteger m_minCrlNumber;

        private X509V2AttributeCertificate m_attrCertChecking;
        private bool m_completeCrlEnabled;
        private bool m_deltaCrlIndicatorEnabled;
        private byte[] m_issuingDistributionPoint;
        private bool m_issuingDistributionPointEnabled;
        private BigInteger m_maxBaseCrlNumber;

        public X509CrlStoreSelector()
        {
        }

        public X509CrlStoreSelector(X509CrlStoreSelector o)
        {
            m_certificateChecking = o.CertificateChecking;
            m_dateAndTime = o.DateAndTime;
            m_issuers = o.Issuers;
            m_maxCrlNumber = o.MaxCrlNumber;
            m_minCrlNumber = o.MinCrlNumber;

            m_deltaCrlIndicatorEnabled = o.DeltaCrlIndicatorEnabled;
            m_completeCrlEnabled = o.CompleteCrlEnabled;
            m_maxBaseCrlNumber = o.MaxBaseCrlNumber;
            m_attrCertChecking = o.AttrCertChecking;
            m_issuingDistributionPointEnabled = o.IssuingDistributionPointEnabled;
            m_issuingDistributionPoint = o.IssuingDistributionPoint;
        }

        public virtual object Clone() => new X509CrlStoreSelector(this);

        public X509Certificate CertificateChecking
        {
            get { return m_certificateChecking; }
            set { m_certificateChecking = value; }
        }

        public DateTime? DateAndTime
        {
            get { return m_dateAndTime; }
            set { m_dateAndTime = value; }
        }

        /// <summary>
        /// An <code>ICollection</code> of <code>X509Name</code> objects
        /// </summary>
        public IList<X509Name> Issuers
        {
            get { return new List<X509Name>(m_issuers); }
            set { m_issuers = new List<X509Name>(value); }
        }

        public BigInteger MaxCrlNumber
        {
            get { return m_maxCrlNumber; }
            set { m_maxCrlNumber = value; }
        }

        public BigInteger MinCrlNumber
        {
            get { return m_minCrlNumber; }
            set { m_minCrlNumber = value; }
        }

        /// <summary>The attribute certificate being checked.</summary>
        /// <remarks>
        /// This is not a criterion. Rather, it is optional information that may help findind CRLs that would be
        /// relevant when checking revocation for the specified attribute certificate. If <c>null</c> is specified, then
        /// no such optional information is provided.
        /// </remarks>
        public X509V2AttributeCertificate AttrCertChecking
        {
            get { return m_attrCertChecking; }
            set { m_attrCertChecking = value; }
        }

        /// <summary>
        /// If <c>true</c> only complete CRLs are returned. Defaults to <c>false</c>.
        /// </summary>
        public bool CompleteCrlEnabled
        {
            get { return m_completeCrlEnabled; }
            set { m_completeCrlEnabled = value; }
        }

        /// <summary>
        /// Whether this selector must match CRLs with the delta CRL indicator extension set. Defaults to <c>false</c>.
        /// </summary>
        public bool DeltaCrlIndicatorEnabled
        {
            get { return m_deltaCrlIndicatorEnabled; }
            set { m_deltaCrlIndicatorEnabled = value; }
        }

        /// <summary>The issuing distribution point. This is the DER-encoded OCTET STRING extension value.</summary>
        /// <remarks>
        /// <para>
        /// The issuing distribution point extension is a CRL extension which identifies the scope and the distribution
        /// point of a CRL. The scope contains among others information about revocation reasons contained in the CRL.
        /// Delta CRLs and complete CRLs must have matching issuing distribution points.
        /// </para>
        /// <para>
        /// The byte array is cloned to protect against subsequent modifications.
        /// </para>
        /// <para>
        /// You must also enable or disable this criteria with <see cref="IssuingDistributionPointEnabled"/>
        /// </para>
        /// </remarks>
        public byte[] IssuingDistributionPoint
        {
            get { return Arrays.Clone(m_issuingDistributionPoint); }
            set { m_issuingDistributionPoint = Arrays.Clone(value); }
        }

        /// <summary>
        /// Whether the issuing distribution point criteria should be applied. Defaults to <c>false</c>.
        /// </summary>
        /// <remarks>
        /// You may also set the issuing distribution point criteria; if not a missing issuing distribution point
        /// should be assumed.
        /// </remarks>
        public bool IssuingDistributionPointEnabled
        {
            get { return m_issuingDistributionPointEnabled; }
            set { m_issuingDistributionPointEnabled = value; }
        }

        /// <summary>The maximum base CRL number. Defaults to <c>null</c>. </summary>
        public BigInteger MaxBaseCrlNumber
        {
            get { return m_maxBaseCrlNumber; }
            set { m_maxBaseCrlNumber = value; }
        }

        public virtual bool Match(X509Crl c)
        {
            if (c == null)
                return false;

            if (m_dateAndTime != null)
            {
                DateTime dt = m_dateAndTime.Value;
                DateTime tu = c.ThisUpdate;
                DateTime? nu = c.NextUpdate;

                if (dt.CompareTo(tu) < 0 || nu == null || dt.CompareTo(nu.Value) >= 0)
                    return false;
            }

            if (m_issuers != null)
            {
                X509Name i = c.IssuerDN;

                bool found = false;

                foreach (X509Name issuer in m_issuers)
                {
                    if (issuer.Equivalent(i, true))
                    {
                        found = true;
                        break;
                    }
                }

                if (!found)
                    return false;
            }

            if (m_maxCrlNumber != null || m_minCrlNumber != null)
            {
                BigInteger cn = c.GetExtension(X509Extensions.CrlNumber, CrlNumber.GetInstance)?.PositiveValue;
                if (cn == null)
                    return false;

                if (m_maxCrlNumber != null && cn.CompareTo(m_maxCrlNumber) > 0)
                    return false;

                if (m_minCrlNumber != null && cn.CompareTo(m_minCrlNumber) < 0)
                    return false;
            }

            // TODO[pkix] Do we always need to parse the Delta CRL Indicator extension?
            {
                DerInteger baseCrlNumber;
                try
                {
                    baseCrlNumber = c.GetExtension(X509Extensions.DeltaCrlIndicator, DerInteger.GetInstance);
                }
                catch (Exception)
                {
                    return false;
                }

                if (baseCrlNumber == null)
                {
                    if (DeltaCrlIndicatorEnabled)
                        return false;
                }
                else
                {
                    if (CompleteCrlEnabled)
                        return false;

                    if (m_maxBaseCrlNumber != null && baseCrlNumber.PositiveValue.CompareTo(m_maxBaseCrlNumber) > 0)
                        return false;
                }
            }

            if (m_issuingDistributionPointEnabled)
            {
                Asn1OctetString idp = c.GetExtensionValue(X509Extensions.IssuingDistributionPoint);
                if (m_issuingDistributionPoint == null)
                {
                    if (idp != null)
                        return false;
                }
                else
                {
                    if (!Arrays.AreEqual(idp.GetOctets(), m_issuingDistributionPoint))
                        return false;
                }
            }

            return true;
        }
    }

    public interface ICheckingCertificate
    {
        X509Certificate CertificateChecking { get; }
    }
}
