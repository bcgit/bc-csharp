using System.Collections.Generic;
using System.Text;

using Org.BouncyCastle.Security;
using Org.BouncyCastle.Utilities.Collections;
using Org.BouncyCastle.X509;

namespace Org.BouncyCastle.Pkix
{
    /// <summary>The parameters for building a PKIX certification path with <see cref="PkixCertPathBuilder"/>.
    /// </summary>
    /// <remarks>
    /// In addition to the settings in <see cref="PkixParameters"/>, these specify the constraints on the target
    /// certificate, the maximum path length and the certificates that must not be used in a path.
    /// </remarks>
    public class PkixBuilderParameters
        : PkixParameters
    {
        private int maxPathLength = 5;

        private HashSet<X509Certificate> excludedCerts = new HashSet<X509Certificate>();

        /// <summary>Returns an instance of <c>PkixBuilderParameters</c>.</summary>
        /// <remarks>This method can be used to get a copy from other <see cref="PkixParameters"/> instances.
        /// </remarks>
        /// <param name="pkixParams">The PKIX parameters to create a copy of.</param>
        /// <returns>A <c>PkixBuilderParameters</c> instance.</returns>
        public static PkixBuilderParameters GetInstance(PkixParameters pkixParams)
        {
            PkixBuilderParameters parameters = new PkixBuilderParameters(
                pkixParams.GetTrustAnchors(),
                pkixParams.GetTargetConstraintsCert(),
                pkixParams.GetTargetConstraintsAttrCert());
            parameters.SetParams(pkixParams);
            return parameters;
        }

        /// <summary>Create parameters with constraints on the target certificate.</summary>
        /// <param name="trustAnchors">A set of <see cref="TrustAnchor"/>s.</param>
        /// <param name="targetConstraintsCert">A selector for the target certificate (or null for none).</param>
        /// <exception cref="System.ArgumentNullException"><paramref name="trustAnchors"/> is null.</exception>
        /// <exception cref="System.ArgumentException"><paramref name="trustAnchors"/> contains no trust anchors.</exception>
        public PkixBuilderParameters(ISet<TrustAnchor> trustAnchors, ISelector<X509Certificate> targetConstraintsCert)
            : this(trustAnchors, targetConstraintsCert, targetConstraintsAttrCert: null)
        {
        }

        /// <summary>Create parameters with constraints on the target certificate and attribute certificate.
        /// </summary>
        /// <param name="trustAnchors">A set of <see cref="TrustAnchor"/>s.</param>
        /// <param name="targetConstraintsCert">A selector for the target certificate (or null for none).</param>
        /// <param name="targetConstraintsAttrCert">A selector for the target attribute certificate (or null).</param>
        /// <exception cref="System.ArgumentNullException"><paramref name="trustAnchors"/> is null.</exception>
        /// <exception cref="System.ArgumentException"><paramref name="trustAnchors"/> contains no trust anchors.</exception>
        public PkixBuilderParameters(ISet<TrustAnchor> trustAnchors, ISelector<X509Certificate> targetConstraintsCert,
            ISelector<X509V2AttributeCertificate> targetConstraintsAttrCert)
            : base(trustAnchors)
        {
            SetTargetConstraintsCert(targetConstraintsCert);
            SetTargetConstraintsAttrCert(targetConstraintsAttrCert);
        }

        public PkixBuilderParameters(TrustAnchor trustAnchor, ISelector<X509Certificate> targetConstraintsCert)
            : this(trustAnchor, targetConstraintsCert, targetConstraintsAttrCert: null)
        {
        }

        public PkixBuilderParameters(TrustAnchor trustAnchor, ISelector<X509Certificate> targetConstraintsCert,
            ISelector<X509V2AttributeCertificate> targetConstraintsAttrCert)
            : base(trustAnchor)
        {
            SetTargetConstraintsCert(targetConstraintsCert);
            SetTargetConstraintsAttrCert(targetConstraintsAttrCert);
        }

        /// <summary>Gets or sets the maximum number of intermediate certificates allowed in a path.</summary>
        /// <remarks>The default is 5. A value of -1 means there is no limit.</remarks>
        /// <exception cref="InvalidParameterException">The value set is less than -1.</exception>
        public virtual int MaxPathLength
        {
            get { return maxPathLength; }
            set
            {
                if (value < -1)
                    throw new InvalidParameterException("The maximum path length parameter can not be less than -1.");

                this.maxPathLength = value;
            }
        }

        /// <summary>
        /// Excluded certificates are not used for building a certification path.
        /// </summary>
        /// <returns>the excluded certificates.</returns>
        public virtual ISet<X509Certificate> GetExcludedCerts() => new HashSet<X509Certificate>(excludedCerts);

        /// <summary>
        /// Return whether the given certificate is one of the excluded certificates, which are not used for
        /// building a certification path.
        /// </summary>
        /// <remarks>
        /// Equivalent to testing <see cref="GetExcludedCerts"/> for membership, but without copying the set.
        /// </remarks>
        /// <param name="cert">The certificate to test.</param>
        public virtual bool IsExcludedCert(X509Certificate cert) => excludedCerts.Contains(cert);

        /// <summary>
        /// Sets the excluded certificates which are not used for building a
        /// certification path. If the <code>ISet</code> is <code>null</code> an
        /// empty set is assumed.
        /// </summary>
        /// <remarks>
        /// The given set is cloned to protect it against subsequent modifications.
        /// </remarks>
        /// <param name="excludedCerts">The excluded certificates to set.</param>
        public virtual void SetExcludedCerts(ISet<X509Certificate> excludedCerts)
        {
            if (excludedCerts == null)
            {
                this.excludedCerts = new HashSet<X509Certificate>();
            }
            else
            {
                this.excludedCerts = new HashSet<X509Certificate>(excludedCerts);
            }
        }

        /// <summary>Copies the settings of the given parameters into this instance.</summary>
        /// <remarks>
        /// If <paramref name="parameters"/> is itself a <see cref="PkixBuilderParameters"/> the maximum path length and
        /// excluded certificates are copied too.
        /// </remarks>
        /// <param name="parameters">The parameters to copy.</param>
        protected override void SetParams(PkixParameters parameters)
        {
            base.SetParams(parameters);
            if (parameters is PkixBuilderParameters _params)
            {
                maxPathLength = _params.maxPathLength;
                excludedCerts = new HashSet<X509Certificate>(_params.excludedCerts);
            }
        }

        /// <summary>Makes a copy of these parameters. Changes to the copy will not affect the original and vice versa.
        /// </summary>
        /// <returns>A copy of these parameters.</returns>
        public override object Clone()
        {
            PkixBuilderParameters parameters = new PkixBuilderParameters(
                GetTrustAnchors(),
                GetTargetConstraintsCert(),
                GetTargetConstraintsAttrCert());
            parameters.SetParams(this);
            return parameters;
        }

        /// <summary>Returns a formatted string describing the parameters.</summary>
        public override string ToString()
        {
            StringBuilder s = new StringBuilder();
            s.AppendLine("PkixBuilderParameters [");
            s.Append(base.ToString());
            s.Append("  Maximum Path Length: ");
            s.Append(MaxPathLength);
            s.AppendLine();
            s.AppendLine("]");
            return s.ToString();
        }
    }
}
