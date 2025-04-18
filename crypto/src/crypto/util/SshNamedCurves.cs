using System;
using System.Collections.Generic;

using Org.BouncyCastle.Asn1;
using Org.BouncyCastle.Asn1.Sec;
using Org.BouncyCastle.Asn1.X9;
using Org.BouncyCastle.Crypto.EC;
using Org.BouncyCastle.Crypto.Generators;
using Org.BouncyCastle.Utilities.Collections;

namespace Org.BouncyCastle.Crypto.Utilities
{
    public static class SshNamedCurves
    {
        private static readonly Dictionary<string, DerObjectIdentifier> objIds =
            new Dictionary<string, DerObjectIdentifier>(StringComparer.OrdinalIgnoreCase);
        private static readonly Dictionary<DerObjectIdentifier, string> names =
            new Dictionary<DerObjectIdentifier, string>();

        private static void DefineCurveAlias(string name, DerObjectIdentifier oid)
        {
            if (FindByOidLazy(oid) == null)
                throw new InvalidOperationException();

            objIds.Add(name, oid);
            names.Add(oid, name);
        }

        private static X9ECParametersHolder FindByOidLazy(DerObjectIdentifier oid) =>
            ECUtilities.FindECCurveByOidLazy(oid);

        static SshNamedCurves()
        {
            DefineCurveAlias("nistp192", SecObjectIdentifiers.SecP192r1);
            DefineCurveAlias("nistp224", SecObjectIdentifiers.SecP224r1);
            DefineCurveAlias("nistp256", SecObjectIdentifiers.SecP256r1);
            DefineCurveAlias("nistp384", SecObjectIdentifiers.SecP384r1);
            DefineCurveAlias("nistp521", SecObjectIdentifiers.SecP521r1);
            DefineCurveAlias("nistb233", SecObjectIdentifiers.SecT233r1);
            DefineCurveAlias("nistb409", SecObjectIdentifiers.SecT409r1);
            DefineCurveAlias("nistk163", SecObjectIdentifiers.SecT163k1);
            DefineCurveAlias("nistk233", SecObjectIdentifiers.SecT233k1);
            DefineCurveAlias("nistk283", SecObjectIdentifiers.SecT283k1);
            DefineCurveAlias("nistk409", SecObjectIdentifiers.SecT409k1);
            DefineCurveAlias("nistt571", SecObjectIdentifiers.SecT571k1);
        }

        /// <summary>Look up the <see cref="X9ECParameters"/> for the curve with the given name.</summary>
        /// <param name="name">The name of the curve.</param>
        public static X9ECParameters GetByName(string name)
        {
            DerObjectIdentifier oid = GetOid(name);
            return oid == null ? null : GetByOid(oid);
        }

        /// <summary>Look up an <see cref="X9ECParametersHolder"/> for the curve with the given name.</summary>
        /// <remarks>
        /// Allows accessing the <see cref="Math.EC.ECCurve">curve</see> without necessarily triggering the creation of
        /// the full <see cref="X9ECParameters"/>.
        /// </remarks>
        /// <param name="name">The name of the curve.</param>
        public static X9ECParametersHolder GetByNameLazy(string name)
        {
            DerObjectIdentifier oid = GetOid(name);
            return oid == null ? null : GetByOidLazy(oid);
        }

        /// <summary>Look up the <see cref="X9ECParameters"/> for the curve with the given
        /// <see cref="DerObjectIdentifier">OID</see>.</summary>
        /// <param name="oid">The <see cref="DerObjectIdentifier">OID</see> for the curve.</param>
        public static X9ECParameters GetByOid(DerObjectIdentifier oid)
        {
            return GetByOidLazy(oid)?.Parameters;
        }

        /// <summary>Look up an <see cref="X9ECParametersHolder"/> for the curve with the given
        /// <see cref="DerObjectIdentifier">OID</see>.</summary>
        /// <remarks>
        /// Allows accessing the <see cref="Math.EC.ECCurve">curve</see> without necessarily triggering the creation of
        /// the full <see cref="X9ECParameters"/>.
        /// </remarks>
        /// <param name="oid">The <see cref="DerObjectIdentifier">OID</see> for the curve.</param>
        public static X9ECParametersHolder GetByOidLazy(DerObjectIdentifier oid)
        {
            return names.ContainsKey(oid) ? FindByOidLazy(oid) : null;
        }

        /// <summary>Look up the name of the curve with the given <see cref="DerObjectIdentifier">OID</see>.</summary>
        /// <param name="oid">The <see cref="DerObjectIdentifier">OID</see> for the curve.</param>
        public static string GetName(DerObjectIdentifier oid)
        {
            return CollectionUtilities.GetValueOrNull(names, oid);
        }

        /// <summary>Look up the <see cref="DerObjectIdentifier">OID</see> of the curve with the given name.</summary>
        /// <param name="name">The name of the curve.</param>
        public static DerObjectIdentifier GetOid(string name)
        {
            return CollectionUtilities.GetValueOrNull(objIds, name);
        }

        /// <summary>Enumerate the available curve names in this registry.</summary>
        public static IEnumerable<string> Names
        {
            get { return CollectionUtilities.Proxy(objIds.Keys); }
        }
    }
}
