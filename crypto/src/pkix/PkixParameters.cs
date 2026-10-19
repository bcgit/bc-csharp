using System;
using System.Collections.Generic;

using Org.BouncyCastle.Utilities.Collections;
using Org.BouncyCastle.X509;

namespace Org.BouncyCastle.Pkix
{
    /// <summary>The parameters for PKIX certification path validation and building (RFC 5280).</summary>
    /// <remarks>
    /// The parameters name the trust anchors, the stores of certificates and CRLs to draw on, constraints on the
    /// target certificate, the policy settings and the revocation checking behaviour. They are used by
    /// <see cref="PkixCertPathValidator"/> and, via <see cref="PkixBuilderParameters"/>, by
    /// <see cref="PkixCertPathBuilder"/>.
    /// </remarks>
    public class PkixParameters
    {
        /// <summary>The default PKIX validity model.</summary>
        /// <remarks>
        /// There are two variants of this: the PKIX model and the modified PKIX model. The PKIX model verifies that all
        /// involved certificates must have been valid at the current time. The modified PKIX model verifies that all
        /// involved certificates were valid at the signing time. Both are indirectly chosen with the
        /// <see cref="Date"/> property, which sets the time when <em>all</em> certificates must have been valid.
        /// </remarks>
        public const int PkixValidityModel = 0;

        /// <summary>The chain validity model.</summary>
        /// <remarks>
        /// Each certificate must have been valid at the moment where it was used. That means the end certificate must
        /// have been valid at the time the signature was done, the CA certificate which signed the end certificate
        /// must have been valid when the end certificate was signed, the CA (or root CA) certificate must have been
        /// valid when the CA certificate was signed, and so on. So the <see cref="Date"/> property sets the time when
        /// the <em>end certificate</em> must have been valid. It is used, for example, in the German signature law.
        /// </remarks>
        public const int ChainValidityModel = 1;

        private HashSet<TrustAnchor> trustAnchors;
        private DateTime? date;
        private List<PkixCertPathChecker> m_checkers;
        private bool revocationEnabled = true;
        private HashSet<string> initialPolicies;
        //private bool checkOnlyEECertificateCrl = false;
        private bool explicitPolicyRequired = false;
        private bool anyPolicyInhibited = false;
        private bool policyMappingInhibited = false;
        private bool policyQualifiersRejected = true;

        private List<IStore<X509V2AttributeCertificate>> m_storesAttrCert;
        private List<IStore<X509Certificate>> m_storesCert;
        private List<IStore<X509Crl>> m_storesCrl;

        private ISelector<X509V2AttributeCertificate> m_targetConstraintsAttrCert;
        private ISelector<X509Certificate> m_targetConstraintsCert;

        private bool additionalLocationsEnabled;
        private HashSet<TrustAnchor> trustedACIssuers;
        private HashSet<string> necessaryACAttributes;
        private HashSet<string> prohibitedACAttributes;
        private HashSet<PkixAttrCertChecker> attrCertCheckers;
        private int validityModel = PkixValidityModel;
        private bool useDeltas = false;

        /// <summary>Creates an instance of PkixParameters with the specified set of most-trusted CAs.</summary>
        /// <remarks>The set is copied to protect against subsequent modifications.</remarks>
        /// <param name="trustAnchors">A set of <see cref="TrustAnchor"/>s.</param>
        /// <exception cref="ArgumentNullException"><paramref name="trustAnchors"/> is null.</exception>
        /// <exception cref="ArgumentException"><paramref name="trustAnchors"/> contains no trust anchors.</exception>
        public PkixParameters(ISet<TrustAnchor> trustAnchors)
            : this()
        {
            SetTrustAnchors(trustAnchors);
        }

        /**
         * Creates an instance of PkixParameters with a single most-trusted CA.
         *
         * @param trustAnchor
         *            the TrustAnchor for the single most-trusted CA
         *
         * @exception NullPointerException
         *                if the specified TrustAnchor is <code>null</code>
         */
        public PkixParameters(TrustAnchor trustAnchor)
            : this()
        {
            SetTrustAnchor(trustAnchor);
        }

        private PkixParameters()
        {
            this.initialPolicies = new HashSet<string>();
            this.m_checkers = new List<PkixCertPathChecker>();
            this.m_storesAttrCert = new List<IStore<X509V2AttributeCertificate>>();
            this.m_storesCert = new List<IStore<X509Certificate>>();
            this.m_storesCrl = new List<IStore<X509Crl>>();
            this.trustedACIssuers = new HashSet<TrustAnchor>();
            this.necessaryACAttributes = new HashSet<string>();
            this.prohibitedACAttributes = new HashSet<string>();
            this.attrCertCheckers = new HashSet<PkixAttrCertChecker>();
        }

        //// TODO implement for other keystores (see Java build)?
        ///**
        // * Creates an instance of <code>PKIXParameters</code> that
        // * populates the set of most-trusted CAs from the trusted
        // * certificate entries contained in the specified <code>KeyStore</code>.
        // * Only keystore entries that contain trusted <code>X509Certificates</code>
        // * are considered; all other certificate types are ignored.
        // *
        // * @param keystore a <code>KeyStore</code> from which the set of
        // * most-trusted CAs will be populated
        // * @throws KeyStoreException if the keystore has not been initialized
        // * @throws InvalidAlgorithmParameterException if the keystore does
        // * not contain at least one trusted certificate entry
        // * @throws NullPointerException if the keystore is <code>null</code>
        // */
        //public PkixParameters(
        //    Pkcs12Store keystore)
        //{
        //    if (keystore == null)
        //        throw new ArgumentNullException("keystore");
        //    ISet trustAnchors = new HashSet();
        //    foreach (string alias in keystore.Aliases)
        //    {
        //        if (keystore.IsCertificateEntry(alias))
        //        {
        //            X509CertificateEntry x509Entry = keystore.GetCertificate(alias);
        //            trustAnchors.Add(new TrustAnchor(x509Entry.Certificate, null));
        //        }
        //    }
        //    SetTrustAnchors(trustAnchors);

        //    this.initialPolicies = new HashSet();
        //    this.certPathCheckers = new ArrayList();
        //    this.stores = new ArrayList();
        //    this.additionalStores = new ArrayList();
        //    this.trustedACIssuers = new HashSet();
        //    this.necessaryACAttributes = new HashSet();
        //    this.prohibitedACAttributes = new HashSet();
        //    this.attrCertCheckers = new HashSet();
        //}

        /// <summary>Gets or sets whether revocation checking is enabled (true by default).</summary>
        public virtual bool IsRevocationEnabled
        {
            get { return revocationEnabled; }
            set { revocationEnabled = value; }
        }

        /// <summary>Gets or sets whether an acceptable policy identifier is required in every certificate.</summary>
        public virtual bool IsExplicitPolicyRequired
        {
            get { return explicitPolicyRequired; }
            set { this.explicitPolicyRequired = value; }
        }

        /// <summary>Gets or sets whether the anyPolicy OID is inhibited (not treated as matching any policy).</summary>
        public virtual bool IsAnyPolicyInhibited
        {
            get { return anyPolicyInhibited; }
            set { this.anyPolicyInhibited = value; }
        }

        /// <summary>Gets or sets whether policy mapping is inhibited.</summary>
        public virtual bool IsPolicyMappingInhibited
        {
            get { return policyMappingInhibited; }
            set { this.policyMappingInhibited = value; }
        }

        /// <summary>
        /// Gets or sets whether paths containing a critical policy qualifier are rejected (true by default).
        /// </summary>
        public virtual bool IsPolicyQualifiersRejected
        {
            get { return policyQualifiersRejected; }
            set { this.policyQualifiersRejected = value; }
        }

        //public bool IsCheckOnlyEECertificateCrl
        //{
        //    get { return this.checkOnlyEECertificateCrl; }
        //    set { this.checkOnlyEECertificateCrl = value; }
        //}

        /// <summary>
        /// Gets or sets the time for which the validity of the path is checked, or null to use the current time.
        /// </summary>
        /// <remarks>See <see cref="PkixValidityModel"/> and <see cref="ChainValidityModel"/>.</remarks>
        public virtual DateTime? Date
        {
            get { return this.date; }
            set { this.date = value; }
        }

        /// <summary>Returns a copy of the set of most-trusted CAs.</summary>
        public virtual ISet<TrustAnchor> GetTrustAnchors()
        {
            return new HashSet<TrustAnchor>(this.trustAnchors);
        }

        /// <summary>Sets the set of most-trusted CAs.</summary>
        /// <remarks>The set is copied to protect against subsequent modifications.</remarks>
        /// <param name="tas">A set of <see cref="TrustAnchor"/>s.</param>
        /// <exception cref="ArgumentNullException"><paramref name="tas"/> is null.</exception>
        /// <exception cref="ArgumentException"><paramref name="tas"/> contains no trust anchors.</exception>
        public virtual void SetTrustAnchors(ISet<TrustAnchor> tas)
        {
            if (tas == null)
                throw new ArgumentNullException(nameof(tas));

            // Explicit copy to enforce type-safety
            this.trustAnchors = new HashSet<TrustAnchor>();
            foreach (TrustAnchor ta in tas)
            {
                if (ta != null)
                {
                    trustAnchors.Add(ta);
                }
            }

            if (trustAnchors.Count < 1)
                throw new ArgumentException("non-empty set required", nameof(tas));
        }

        // Sets a single most-trusted CA.
        public virtual void SetTrustAnchor(TrustAnchor trustAnchor)
        {
            if (trustAnchor == null)
                throw new ArgumentNullException(nameof(trustAnchor));

            this.trustAnchors = new HashSet<TrustAnchor>() { trustAnchor };
        }

        /// <summary>Returns the required constraints on the target attribute certificate, or null if none.</summary>
        /// <remarks>The selector returned is cloned to protect against subsequent modifications.</remarks>
        /// <returns>A selector specifying the constraints on the target attribute certificate (or null).</returns>
        public virtual ISelector<X509V2AttributeCertificate> GetTargetConstraintsAttrCert()
        {
            return (ISelector<X509V2AttributeCertificate>)m_targetConstraintsAttrCert?.Clone();
        }

        /// <summary>Sets the required constraints on the target attribute certificate.</summary>
        /// <remarks>The selector specified is cloned to protect against subsequent modifications.</remarks>
        /// <param name="targetConstraintsAttrCert">
        /// A selector specifying the constraints on the target attribute certificate (or null for none).
        /// </param>
        public virtual void SetTargetConstraintsAttrCert(
            ISelector<X509V2AttributeCertificate> targetConstraintsAttrCert)
        {
            this.m_targetConstraintsAttrCert = (ISelector<X509V2AttributeCertificate>)
                targetConstraintsAttrCert?.Clone();
        }

        /// <summary>Returns the required constraints on the target certificate, or null if none.</summary>
        /// <remarks>The selector returned is cloned to protect against subsequent modifications.</remarks>
        /// <returns>A selector specifying the constraints on the target certificate (or null).</returns>
        public virtual ISelector<X509Certificate> GetTargetConstraintsCert()
        {
            return (ISelector<X509Certificate>)m_targetConstraintsCert?.Clone();
        }

        /// <summary>Sets the required constraints on the target certificate.</summary>
        /// <remarks>The selector specified is cloned to protect against subsequent modifications.</remarks>
        /// <param name="targetConstraintsCert">
        /// A selector specifying the constraints on the target certificate (or null for none).
        /// </param>
        public virtual void SetTargetConstraintsCert(ISelector<X509Certificate> targetConstraintsCert)
        {
            m_targetConstraintsCert = (ISelector<X509Certificate>)targetConstraintsCert?.Clone();
        }

        /// <summary>Returns a copy of the set of initial policy identifiers (OID strings).</summary>
        /// <remarks>
        /// Any one of these policies would be acceptable to the certificate user for the purposes of certification
        /// path processing. The default is an empty set, which is interpreted as meaning that any policy would be
        /// acceptable.
        /// </remarks>
        /// <returns>The initial policy OIDs, or an empty set (implying any policy is acceptable). Never null.</returns>
        public virtual ISet<string> GetInitialPolicies()
        {
            // TODO Can it really be null?
            if (initialPolicies == null)
                return new HashSet<string>();

            return new HashSet<string>(initialPolicies);
        }

        /// <summary>Sets the set of initial policy identifiers (OID strings).</summary>
        /// <remarks>
        /// Any one of these policies would be acceptable to the certificate user for the purposes of certification
        /// path processing. By default any policy is acceptable, so there is no need to call this method to allow any
        /// policy; it may also be called with an empty set (or null). The set is copied to protect against subsequent
        /// modifications.
        /// </remarks>
        /// <param name="initialPolicies">A set of initial policy OIDs in string form (or null).</param>
        public virtual void SetInitialPolicies(ISet<string> initialPolicies)
        {
            this.initialPolicies = new HashSet<string>();
            if (initialPolicies != null)
            {
                foreach (string obj in initialPolicies)
                {
                    if (obj != null)
                    {
                        this.initialPolicies.Add(obj);
                    }
                }
            }
        }

        /// <summary>Sets the list of additional certification path checkers.</summary>
        /// <remarks>
        /// Each <see cref="PkixCertPathChecker"/> implements additional checks on a certificate. Typically these are
        /// checks to process and verify private extensions contained in certificates. Each checker should be
        /// instantiated with any initialization parameters needed to execute the check.
        /// <para>
        /// This allows sophisticated applications to extend the PKIX validator or builder: each of the checkers will be
        /// called, in turn, for each certificate processed or validated. Regardless of whether additional checkers are
        /// set, the validator or builder must perform all of the required PKIX checks on each certificate, unless
        /// <see cref="IsRevocationEnabled"/> is false.
        /// </para>
        /// <para>
        /// The list supplied is copied and each checker in it is cloned to protect against subsequent modifications.
        /// </para>
        /// </remarks>
        /// <param name="checkers">A list of checkers, or null, in which case no additional checkers will be used.
        /// </param>
        public virtual void SetCertPathCheckers(IList<PkixCertPathChecker> checkers)
        {
            m_checkers = new List<PkixCertPathChecker>();

            if (checkers != null)
            {
                foreach (var checker in checkers)
                {
                    m_checkers.Add((PkixCertPathChecker)checker.Clone());
                }
            }
        }

        /// <summary>Returns the list of certification path checkers.</summary>
        /// <remarks>Each checker in the returned list is cloned to protect against subsequent modifications.</remarks>
        /// <returns>A list of checkers (may be empty, but never null).</returns>
        public virtual IList<PkixCertPathChecker> GetCertPathCheckers()
        {
            var result = new List<PkixCertPathChecker>(m_checkers.Count);
            foreach (var checker in m_checkers)
            {
                result.Add((PkixCertPathChecker)checker.Clone());
            }
            return result;
        }

        /// <summary>Adds a checker to the list of certification path checkers.</summary>
        /// <remarks>
        /// See <see cref="SetCertPathCheckers"/> for more details. The checker is cloned to protect against subsequent
        /// modifications.
        /// </remarks>
        /// <param name="checker">The checker to add. If null, it is ignored.</param>
        public virtual void AddCertPathChecker(PkixCertPathChecker checker)
        {
            if (checker != null)
            {
                m_checkers.Add((PkixCertPathChecker)checker.Clone());
            }
        }

        /// <summary>Returns a copy of these parameters.</summary>
        public virtual object Clone()
        {
            // FIXME Check this whole method against the Java implementation!

            PkixParameters parameters = new PkixParameters(GetTrustAnchors());
            parameters.SetParams(this);
            return parameters;


            //PkixParameters obj = new PkixParameters(new HashSet());
            //obj.x509Stores = new ArrayList(x509Stores);
            //obj.certPathCheckers = new ArrayList(certPathCheckers);

            //Iterator iter = certPathCheckers.iterator();
            //obj.certPathCheckers = new ArrayList();
            //while (iter.hasNext())
            //{
            //    obj.certPathCheckers.add(((PKIXCertPathChecker)iter.next()).clone());
            //}
            //if (initialPolicies != null)
            //{
            //    obj.initialPolicies = new HashSet(initialPolicies);
            //}
            //if (trustAnchors != null)
            //{
            //    obj.trustAnchors = new HashSet(trustAnchors);
            //}
            //if (certSelector != null)
            //{
            //    obj.certSelector = (X509CertStoreSelector)certSelector.Clone();
            //}
            //return obj;
        }

        /// <summary>Copies the settings of the given parameters into this instance.</summary>
        /// <param name="parameters">The parameters to copy.</param>
        protected virtual void SetParams(PkixParameters parameters)
        {
            Date = parameters.Date;
            SetCertPathCheckers(parameters.GetCertPathCheckers());
            IsAnyPolicyInhibited = parameters.IsAnyPolicyInhibited;
            IsExplicitPolicyRequired = parameters.IsExplicitPolicyRequired;
            IsPolicyMappingInhibited = parameters.IsPolicyMappingInhibited;
            IsRevocationEnabled = parameters.IsRevocationEnabled;
            SetInitialPolicies(parameters.GetInitialPolicies());
            IsPolicyQualifiersRejected = parameters.IsPolicyQualifiersRejected;
            SetTrustAnchors(parameters.GetTrustAnchors());

            m_storesAttrCert = new List<IStore<X509V2AttributeCertificate>>(parameters.m_storesAttrCert);
            m_storesCert = new List<IStore<X509Certificate>>(parameters.m_storesCert);
            m_storesCrl = new List<IStore<X509Crl>>(parameters.m_storesCrl);

            SetTargetConstraintsAttrCert(parameters.GetTargetConstraintsAttrCert());
            SetTargetConstraintsCert(parameters.GetTargetConstraintsCert());

            validityModel = parameters.validityModel;
            useDeltas = parameters.useDeltas;
            additionalLocationsEnabled = parameters.additionalLocationsEnabled;
            trustedACIssuers = new HashSet<TrustAnchor>(parameters.trustedACIssuers);
            prohibitedACAttributes = new HashSet<string>(parameters.prohibitedACAttributes);
            necessaryACAttributes = new HashSet<string>(parameters.necessaryACAttributes);
            attrCertCheckers = new HashSet<PkixAttrCertChecker>(parameters.attrCertCheckers);
        }

        /// <summary>Gets or sets whether delta CRLs should be used for checking the revocation status.</summary>
        /// <remarks>The default is false.</remarks>
        public virtual bool IsUseDeltasEnabled
        {
            get { return useDeltas; }
            set { useDeltas = value; }
        }

        /// <summary>Gets or sets the validity model.</summary>
        /// <remarks>One of <see cref="PkixValidityModel"/> (the default) or <see cref="ChainValidityModel"/>.</remarks>
        public virtual int ValidityModel
        {
            get { return validityModel; }
            set { validityModel = value; }
        }

        /// <summary>Returns a copy of the list of stores of attribute certificates.</summary>
        public virtual IList<IStore<X509V2AttributeCertificate>> GetStoresAttrCert()
        {
            return new List<IStore<X509V2AttributeCertificate>>(m_storesAttrCert);
        }

        /// <summary>Returns a copy of the list of stores of certificates.</summary>
        public virtual IList<IStore<X509Certificate>> GetStoresCert()
        {
            return new List<IStore<X509Certificate>>(m_storesCert);
        }

        /// <summary>Returns a copy of the list of stores of CRLs.</summary>
        public virtual IList<IStore<X509Crl>> GetStoresCrl()
        {
            return new List<IStore<X509Crl>>(m_storesCrl);
        }

        /// <summary>Set the attr stores cert.</summary>
        /// <param name="storesAttrCert">The stores attr cert.</param>
        [Obsolete("Use 'SetStoresAttrCert' instead")]
        public virtual void SetAttrStoresCert(IList<IStore<X509V2AttributeCertificate>> storesAttrCert)
        {
            SetStoresAttrCert(storesAttrCert);
        }

        /// <summary>Sets the stores of attribute certificates; the list is copied, and null clears it.</summary>
        public virtual void SetStoresAttrCert(IList<IStore<X509V2AttributeCertificate>> storesAttrCert)
        {
            if (storesAttrCert == null)
            {
                m_storesAttrCert = new List<IStore<X509V2AttributeCertificate>>();
            }
            else
            {
                m_storesAttrCert = new List<IStore<X509V2AttributeCertificate>>(storesAttrCert);
            }
        }

        /// <summary>Sets the stores of certificates; the list is copied, and null clears it.</summary>
        public virtual void SetStoresCert(IList<IStore<X509Certificate>> storesCert)
        {
            if (storesCert == null)
            {
                m_storesCert = new List<IStore<X509Certificate>>();
            }
            else
            {
                m_storesCert = new List<IStore<X509Certificate>>(storesCert);
            }
        }

        /// <summary>Sets the stores of CRLs; the list is copied, and null clears it.</summary>
        public virtual void SetStoresCrl(IList<IStore<X509Crl>> storesCrl)
        {
            if (storesCrl == null)
            {
                m_storesCrl = new List<IStore<X509Crl>>();
            }
            else
            {
                m_storesCrl = new List<IStore<X509Crl>>(storesCrl);
            }
        }

        /// <summary>Adds a store of attribute certificates; null is ignored.</summary>
        public virtual void AddStoreAttrCert(IStore<X509V2AttributeCertificate> storeAttrCert)
        {
            if (storeAttrCert != null)
            {
                m_storesAttrCert.Add(storeAttrCert);
            }
        }

        /// <summary>Adds a store of certificates; null is ignored.</summary>
        public virtual void AddStoreCert(IStore<X509Certificate> storeCert)
        {
            if (storeCert != null)
            {
                m_storesCert.Add(storeCert);
            }
        }

        /// <summary>Adds a store of CRLs; null is ignored.</summary>
        public virtual void AddStoreCrl(IStore<X509Crl> storeCrl)
        {
            if (storeCrl != null)
            {
                m_storesCrl.Add(storeCrl);
            }
        }

        /// <summary>
        /// Gets whether additional stores for locations like LDAP found in certificates or CRLs should be used.
        /// </summary>
        public virtual bool IsAdditionalLocationsEnabled
        {
            get { return additionalLocationsEnabled; }
        }

        /// <summary>
        /// Sets whether additional stores for locations like LDAP found in certificates or CRLs should be used.
        /// </summary>
        /// <param name="enabled">true if additional stores are used.</param>
        public virtual void SetAdditionalLocationsEnabled(bool enabled)
        {
            additionalLocationsEnabled = enabled;
        }

        /// <summary>Returns a copy of the trusted attribute certificate issuers.</summary>
        /// <remarks>If attribute certificates are verified, the trusted AC issuers must be set.</remarks>
        /// <returns>A set of <see cref="TrustAnchor"/>s. Never null.</returns>
        public virtual ISet<TrustAnchor> GetTrustedACIssuers()
        {
            return new HashSet<TrustAnchor>(trustedACIssuers);
        }

        /// <summary>Sets the trusted attribute certificate issuers.</summary>
        /// <remarks>
        /// If attribute certificates are verified, the trusted AC issuers must be set. The given set is copied.
        /// </remarks>
        /// <param name="trustedACIssuers">A set of <see cref="TrustAnchor"/>s; null clears the set.</param>
        public virtual void SetTrustedACIssuers(ISet<TrustAnchor> trustedACIssuers)
        {
            if (trustedACIssuers == null)
            {
                this.trustedACIssuers = new HashSet<TrustAnchor>();
            }
            else
            {
                this.trustedACIssuers = new HashSet<TrustAnchor>(trustedACIssuers);
            }
        }

        /// <summary>Returns a copy of the set of attributes which must be contained in an attribute certificate.
        /// </summary>
        /// <returns>The OIDs, in string form, of the necessary attributes. Never null.</returns>
        public virtual ISet<string> GetNecessaryACAttributes()
        {
            return new HashSet<string>(necessaryACAttributes);
        }

        /// <summary>Sets the attributes which must be contained in an attribute certificate.</summary>
        /// <remarks>The given set is copied.</remarks>
        /// <param name="necessaryACAttributes">The OIDs, in string form, of the attributes; null clears the set.
        /// </param>
        public virtual void SetNecessaryACAttributes(ISet<string> necessaryACAttributes)
        {
            if (necessaryACAttributes == null)
            {
                this.necessaryACAttributes = new HashSet<string>();
            }
            else
            {
                this.necessaryACAttributes = new HashSet<string>(necessaryACAttributes);
            }
        }

        /// <summary>Returns a copy of the set of attributes which are not allowed in an attribute certificate.
        /// </summary>
        /// <returns>The OIDs, in string form, of the prohibited attributes. Never null.</returns>
        public virtual ISet<string> GetProhibitedACAttributes()
        {
            return new HashSet<string>(prohibitedACAttributes);
        }

        /// <summary>Sets the attributes which are not allowed in an attribute certificate.</summary>
        /// <remarks>The given set is copied.</remarks>
        /// <param name="prohibitedACAttributes">The OIDs, in string form, of the attributes; null clears the set.
        /// </param>
        public virtual void SetProhibitedACAttributes(ISet<string> prohibitedACAttributes)
        {
            if (prohibitedACAttributes == null)
            {
                this.prohibitedACAttributes = new HashSet<string>();
            }
            else
            {
                this.prohibitedACAttributes = new HashSet<string>(prohibitedACAttributes);
            }
        }

        /// <summary>Returns a copy of the set of attribute certificate checkers.</summary>
        /// <returns>A set of <see cref="PkixAttrCertChecker"/>s. Never null.</returns>
        public virtual ISet<PkixAttrCertChecker> GetAttrCertCheckers()
        {
            return new HashSet<PkixAttrCertChecker>(attrCertCheckers);
        }

        /// <summary>Sets the attribute certificate checkers.</summary>
        /// <remarks>The given set is copied.</remarks>
        /// <param name="attrCertCheckers">A set of <see cref="PkixAttrCertChecker"/>s; null clears the set.</param>
        public virtual void SetAttrCertCheckers(ISet<PkixAttrCertChecker> attrCertCheckers)
        {
            if (attrCertCheckers == null)
            {
                this.attrCertCheckers = new HashSet<PkixAttrCertChecker>();
            }
            else
            {
                this.attrCertCheckers = new HashSet<PkixAttrCertChecker>(attrCertCheckers);
            }
        }
    }
}
