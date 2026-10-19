using System.Collections.Generic;

using Org.BouncyCastle.Asn1;
using Org.BouncyCastle.Asn1.X509;

namespace Org.BouncyCastle.X509
{
    /// <summary>Base class for objects that carry X.509 extensions, such as certificates and CRLs.</summary>
    public abstract class X509ExtensionBase
        : IX509Extension
    {
        /// <summary>Returns the extensions of the object, or null if there are none.</summary>
        protected abstract X509Extensions GetX509Extensions();

        /// <summary>Returns the object identifiers of the extensions with the given criticality.</summary>
        /// <param name="critical">true for the critical extensions, false for the non-critical ones.</param>
        /// <returns>The identifiers as strings, or null if the object has no extensions.</returns>
        protected virtual ISet<string> GetExtensionOids(bool critical)
        {
            X509Extensions extensions = GetX509Extensions();
            if (extensions == null)
                return null;

            var set = new HashSet<string>();
            foreach (DerObjectIdentifier oid in extensions.ExtensionOids)
            {
                X509Extension ext = extensions.GetExtension(oid);
                if (ext.IsCritical == critical)
                {
                    set.Add(oid.Id);
                }
            }
            return set;
        }

        /// <summary>
        /// Get non critical extensions.
        /// </summary>
        /// <returns>A set of non critical extension oids.</returns>
        public virtual ISet<string> GetNonCriticalExtensionOids() => GetExtensionOids(critical: false);

        /// <summary>
        /// Get any critical extensions.
        /// </summary>
        /// <returns>A sorted list of critical entension.</returns>
        public virtual ISet<string> GetCriticalExtensionOids() => GetExtensionOids(critical: true);

        /// <summary>Return the extension with the given object identifier.</summary>
        /// <param name="oid">The object identifier of the extension.</param>
        /// <returns>The extension, or null if it is not present.</returns>
        public virtual X509Extension GetExtension(DerObjectIdentifier oid) =>
            GetX509Extensions()?.GetExtension(oid);

        /// <summary>Return the parsed value of the extension with the given object identifier.</summary>
        /// <param name="oid">The object identifier of the extension.</param>
        /// <returns>The parsed value, or null if the extension is not present.</returns>
        public virtual Asn1Object GetExtensionParsedValue(DerObjectIdentifier oid) =>
            GetX509Extensions()?.GetExtensionParsedValue(oid);

        /// <summary>Return the value (octet string) of the extension with the given object identifier.</summary>
        /// <param name="oid">The object identifier of the extension.</param>
        /// <returns>The value, or null if the extension is not present.</returns>
        public virtual Asn1OctetString GetExtensionValue(DerObjectIdentifier oid) =>
            GetX509Extensions()?.GetExtensionValue(oid);
    }
}
