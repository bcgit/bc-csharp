using System;
using System.Collections.Generic;

using Org.BouncyCastle.Utilities.Collections;
using Org.BouncyCastle.X509;
using Org.BouncyCastle.X509.Store;

namespace Org.BouncyCastle.Pkix
{
    // TODO[api] Make static
    public class PkixCrlUtilities
	{
		// TODO[api] Redundant
		public virtual ISet<X509Crl> FindCrls(X509CrlStoreSelector crlSelector, PkixParameters paramsPkix) =>
            ImplFindCrls(crlSelector, paramsPkix);

        public virtual ISet<X509Crl> FindCrls(ISelector<X509Crl> crlSelector, PkixParameters paramsPkix) =>
            ImplFindCrls(crlSelector, paramsPkix);

        // TODO[api] Redundant
        public virtual ISet<X509Crl> FindCrls(X509CrlStoreSelector crlSelector, PkixParameters paramsPkix,
			DateTime currentDate)
		{
            return ImplFindCrls(crlSelector, paramsPkix, currentDate);
        }

        public virtual ISet<X509Crl> FindCrls(ISelector<X509Crl> crlSelector, PkixParameters paramsPkix,
			DateTime currentDate)
		{
			return ImplFindCrls(crlSelector, paramsPkix, currentDate);
		}

        internal static HashSet<X509Crl> ImplFindCrls(ISelector<X509Crl> crlSelector, PkixParameters paramsPkix)
        {
            // get complete CRL(s)
            try
            {
                return ImplFindCrls(crlSelector, paramsPkix.GetStoresCrl());
            }
            catch (Exception e)
            {
                throw new Exception("Exception obtaining complete CRLs.", e);
            }
        }

        internal static HashSet<X509Crl> ImplFindCrls(ISelector<X509Crl> crlSelector, PkixParameters paramsPkix,
			DateTime currentDate)
		{
            var initialSet = ImplFindCrls(crlSelector, paramsPkix);

            var finalSet = new HashSet<X509Crl>();
			DateTime validityDate = currentDate;

			if (paramsPkix.Date != null)
			{
				validityDate = paramsPkix.Date.Value;
			}

            X509Certificate cert = null;
            if (crlSelector is ICheckingCertificate checkingCertificate)
            {
                cert = checkingCertificate.CertificateChecking;
            }

            // based on RFC 5280 6.3.3
            foreach (X509Crl crl in initialSet)
			{
                DateTime? nextUpdate = crl.NextUpdate;

                if (null == nextUpdate || nextUpdate.Value.CompareTo(validityDate) > 0)
				{
                    if (null == cert || crl.ThisUpdate.CompareTo(cert.NotAfter) < 0)
                    {
                        finalSet.Add(crl);
                    }
				}
			}

			return finalSet;
		}

        /// <summary>
        /// crl checking
        /// Return a Collection of all CRLs found in the X509Store's that are
        /// matching the crlSelect criteriums.
        /// </summary>
        /// <param name="crlSelector">a {@link X509CRLStoreSelector} object that will be used
        /// to select the CRLs</param>
        /// <param name="crlStores">a List containing only {@link Org.BouncyCastle.X509.X509Store
        /// X509Store} objects. These are used to search for CRLs</param>
        /// <returns>a Collection of all found {@link X509CRL X509CRL} objects. May be
        /// empty but never <code>null</code>.
        /// </returns>
        internal static HashSet<X509Crl> ImplFindCrls(ISelector<X509Crl> crlSelector, IEnumerable<IStore<X509Crl>> crlStores)
		{
            var crls = new HashSet<X509Crl>();

			Exception lastException = null;
			bool foundValidStore = false;

			foreach (var crlStore in crlStores)
			{
				try
				{
					crls.UnionWith(crlStore.EnumerateMatches(crlSelector));
					foundValidStore = true;
				}
				catch (Exception e)
				{
					lastException = e;
				}
			}

	        if (!foundValidStore && lastException != null)
                throw new Exception("Exception searching in X.509 CRL store.", lastException);

			return crls;
		}
	}
}
