using System;
using System.Collections.Generic;

using Org.BouncyCastle.Security.Certificates;
using Org.BouncyCastle.Utilities;
using Org.BouncyCastle.X509;

namespace Org.BouncyCastle.Pkix
{
    /// <summary>Implements the PKIX CertPathBuilding algorithm for BouncyCastle.</summary>
    public class PkixCertPathBuilder
    {
        private readonly bool m_isForCrlCheck;

        private Exception m_certPathException;

        public PkixCertPathBuilder()
            : this(isForCrlCheck: false)
        {
        }

        internal PkixCertPathBuilder(bool isForCrlCheck)
        {
            m_isForCrlCheck = isForCrlCheck;
        }

        /// <summary>Build and validate a CertPath using the given parameter.</summary>
        /// <param name="pkixParams">Object containing all information to build the CertPath.</param>
        public virtual PkixCertPathBuilderResult Build(PkixBuilderParameters pkixParams)
        {
            var certPathList = new List<X509Certificate>();

            // check all potential target certificates
            foreach (X509Certificate tbvCert in PkixCertPathValidatorUtilities.FindTargets(pkixParams))
            {
                PkixCertPathBuilderResult result = Build(tbvCert, pkixParams, certPathList);

                if (result != null)
                    return result;
            }

            if (m_certPathException == null)
                throw new PkixCertPathBuilderException("Unable to find certificate chain.");

            throw new PkixCertPathBuilderException(m_certPathException.Message, m_certPathException.InnerException);
        }

        protected virtual PkixCertPathBuilderResult Build(X509Certificate tbvCert, PkixBuilderParameters pkixParams,
            IList<X509Certificate> tbvPath)
        {
            // If tbvCert is already present in tbvPath, it indicates having run into a cycle in the PKI graph.
            if (tbvPath.Contains(tbvCert))
                return null;

            // step out, the certificate is not allowed to appear in a certification chain.
            if (pkixParams.GetExcludedCerts().Contains(tbvCert))
                return null;

            // test if certificate path exceeds maximum length
            if (pkixParams.MaxPathLength != -1)
            {
                if (tbvPath.Count - 1 > pkixParams.MaxPathLength)
                    return null;
            }

            tbvPath.Add(tbvCert);

            PkixCertPathBuilderResult builderResult = null;
            PkixCertPathValidator validator = new PkixCertPathValidator(m_isForCrlCheck);

            try
            {
                // check whether the issuer of <tbvCert> is a TrustAnchor
                if (PkixCertPathValidatorUtilities.IsIssuerTrustAnchor(tbvCert, pkixParams.GetTrustAnchors()))
                {
                    // exception message from possibly later tried certification chains
                    PkixCertPath certPath;
                    try
                    {
                        certPath = new PkixCertPath(tbvPath);
                    }
                    catch (Exception e)
                    {
                        throw new Exception("Certification path could not be constructed from certificate list.", e);
                    }

                    PkixCertPathValidatorResult result;
                    try
                    {
                        result = validator.Validate(certPath, pkixParams);
                    }
                    catch (Exception e)
                    {
                        throw new Exception("Certification path could not be validated.", e);
                    }

                    return new PkixCertPathBuilderResult(certPath, result.TrustAnchor, result.PolicyTree,
                        result.SubjectPublicKey);
                }
                else
                {
                    // add additional X.509 stores from locations in certificate
                    try
                    {
                        PkixCertPathValidatorUtilities.AddAdditionalStoresFromAltNames(tbvCert, pkixParams);
                    }
                    catch (CertificateParsingException e)
                    {
                        throw new Exception("No additiontal X.509 stores can be added from certificate locations.", e);
                    }

                    // try to get the issuer certificate from one of the stores
                    ISet<X509Certificate> issuers;
                    try
                    {
                        issuers = PkixCertPathValidatorUtilities.FindIssuerCerts(tbvCert, pkixParams);
                    }
                    catch (Exception e)
                    {
                        throw new Exception("Cannot find issuer certificate for certificate in certification path.", e);
                    }

                    if (issuers.Count < 1)
                        throw new Exception("No issuer certificate for certificate in certification path found.");

                    foreach (X509Certificate issuer in issuers)
                    {
                        builderResult = Build(issuer, pkixParams, tbvPath);

                        if (builderResult != null)
                            break;
                    }
                }
            }
            catch (Exception e)
            {
                m_certPathException = e;
            }

            if (builderResult == null)
            {
                tbvPath.Remove(tbvCert);
            }

            return builderResult;
        }
    }
}
