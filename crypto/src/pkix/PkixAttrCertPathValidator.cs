using System;

using Org.BouncyCastle.X509;
using Org.BouncyCastle.X509.Store;

namespace Org.BouncyCastle.Pkix
{
    /// <summary>Validates X.509 attribute certificates according to RFC 3281.</summary>
    public class PkixAttrCertPathValidator
    {
        /// <summary>Validates an attribute certificate with the given certificate path.</summary>
        /// <remarks>
        /// The target constraints in <paramref name="pkixParams"/> must be an <see cref="X509AttrCertStoreSelector"/>
        /// with at least the attribute certificate criterion set. Note that target information may also be necessary
        /// to correctly validate the attribute certificate. The attribute certificate issuer must be added to the
        /// trusted attribute issuers of the parameters.
        /// </remarks>
        /// <param name="certPath">
        /// The certificate path which belongs to the attribute certificate issuer public key certificate.
        /// </param>
        /// <param name="pkixParams">The PKIX parameters.</param>
        /// <returns>The result of validating <paramref name="certPath"/>.</returns>
        /// <exception cref="ArgumentException">
        /// The target constraints of <paramref name="pkixParams"/> are not an <see cref="X509AttrCertStoreSelector"/>.
        /// </exception>
        /// <exception cref="PkixCertPathValidatorException">The verification fails.</exception>
        public virtual PkixCertPathValidatorResult Validate(PkixCertPath certPath, PkixParameters pkixParams)
        {
            if (!(pkixParams.GetTargetConstraintsAttrCert() is X509AttrCertStoreSelector attrCertSelector))
            {
                throw new ArgumentException(
                    "TargetConstraints must be an instance of " + typeof(X509AttrCertStoreSelector).FullName,
                    nameof(pkixParams));
            }

            DateTime currentDate = DateTime.UtcNow;
            DateTime validityDate = PkixCertPathValidatorUtilities.GetValidityDate(pkixParams, currentDate);

            var attrCert = attrCertSelector.AttributeCert;
            PkixCertPath holderCertPath = Rfc3281CertPathUtilities.ProcessAttrCert1(attrCert, pkixParams);
            PkixCertPathValidatorResult result = Rfc3281CertPathUtilities.ProcessAttrCert2A(certPath, pkixParams);
            X509Certificate issuerCert = (X509Certificate)certPath.Certificates[0];
            Rfc3281CertPathUtilities.ProcessAttrCert2B(attrCert, issuerCert);
            Rfc3281CertPathUtilities.ProcessAttrCert3(issuerCert, pkixParams);
            Rfc3281CertPathUtilities.ProcessAttrCert4(issuerCert, pkixParams);
            Rfc3281CertPathUtilities.ProcessAttrCert5(attrCert, validityDate);
            // 6 already done in X509AttrCertStoreSelector
            Rfc3281CertPathUtilities.ProcessAttrCert7(attrCert, certPath, holderCertPath, pkixParams);
            Rfc3281CertPathUtilities.AdditionalChecks(attrCert, pkixParams);

            Rfc3281CertPathUtilities.CheckCrls(attrCert, pkixParams, currentDate, validityDate, issuerCert,
                certPath.Certificates);
            return result;
        }
    }
}
