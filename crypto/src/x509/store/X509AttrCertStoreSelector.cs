using System;
using System.Collections.Generic;
using System.IO;

using Org.BouncyCastle.Asn1;
using Org.BouncyCastle.Asn1.X509;
using Org.BouncyCastle.Math;
using Org.BouncyCastle.Utilities.Collections;
using Org.BouncyCastle.X509.Extension;

namespace Org.BouncyCastle.X509.Store
{
    /// <summary>
    /// A selector for attribute certificates from configurable criteria.
    /// </summary>
    public class X509AttrCertStoreSelector
        : ISelector<X509V2AttributeCertificate>
    {
        // TODO: name constraints???

        private X509V2AttributeCertificate attributeCert;
        private DateTime? attributeCertificateValid;
        private AttributeCertificateHolder holder;
        private AttributeCertificateIssuer issuer;
        private BigInteger serialNumber;
        private ISet<GeneralName> targetNames = new HashSet<GeneralName>();
        private ISet<GeneralName> targetGroups = new HashSet<GeneralName>();

        public X509AttrCertStoreSelector()
        {
        }

        private X509AttrCertStoreSelector(X509AttrCertStoreSelector o)
        {
            this.attributeCert = o.attributeCert;
            this.attributeCertificateValid = o.attributeCertificateValid;
            this.holder = o.holder;
            this.issuer = o.issuer;
            this.serialNumber = o.serialNumber;
            this.targetGroups = new HashSet<GeneralName>(o.targetGroups);
            this.targetNames = new HashSet<GeneralName>(o.targetNames);
        }

        /// <summary>
        /// Decides if the given attribute certificate should be selected.
        /// </summary>
        /// <param name="attrCert">The attribute certificate to be checked.</param>
        /// <returns><code>true</code> if the object matches this selector.</returns>
        public bool Match(X509V2AttributeCertificate attrCert)
        {
            if (attrCert == null)
                return false;

            if (this.attributeCert != null && !this.attributeCert.Equals(attrCert))
                return false;

            if (serialNumber != null && !attrCert.SerialNumber.Equals(serialNumber))
                return false;

            if (holder != null && !attrCert.Holder.Equals(holder))
                return false;

            if (issuer != null && !attrCert.Issuer.Equals(issuer))
                return false;

            if (attributeCertificateValid != null && !attrCert.IsValid(attributeCertificateValid.Value))
                return false;

            if (targetNames.Count > 0 || targetGroups.Count > 0)
            {
                TargetInformation targetInfo;
                try
                {
                    targetInfo = attrCert.GetExtension(X509Extensions.TargetInformation, TargetInformation.GetInstance);
                }
                catch (Exception)
                {
                    return false;
                }

                if (targetInfo != null)
                {
                    Targets[] targetss = targetInfo.GetTargetsObjects();

                    if (targetNames.Count > 0 && !MatchTargetNames(targetss, targetNames))
                        return false;

                    if (targetGroups.Count > 0 && !MatchTargetGroups(targetss, targetGroups))
                        return false;
                }
            }

            return true;
        }

        public object Clone() => new X509AttrCertStoreSelector(this);

        /// <summary>The attribute certificate which must be matched.</summary>
        /// <remarks>If <c>null</c> is given, any will do.</remarks>
        public X509V2AttributeCertificate AttributeCert
        {
            get { return attributeCert; }
            set { this.attributeCert = value; }
        }

        /// <summary>The criteria for validity</summary>
        /// <remarks>If <c>null</c> is given any will do.</remarks>
        public DateTime? AttributeCertificateValid
        {
            get { return attributeCertificateValid; }
            set { this.attributeCertificateValid = value; }
        }

        /// <summary>The holder.</summary>
        /// <remarks>If <c>null</c> is given any will do.</remarks>
        public AttributeCertificateHolder Holder
        {
            get { return holder; }
            set { this.holder = value; }
        }

        /// <summary>The issuer.</summary>
        /// <remarks>If <c>null</c> is given any will do.</remarks>
        public AttributeCertificateIssuer Issuer
        {
            get { return issuer; }
            set { this.issuer = value; }
        }

        /// <summary>The serial number.</summary>
        /// <remarks>If <c>null</c> is given any will do.</remarks>
        public BigInteger SerialNumber
        {
            get { return serialNumber; }
            set { this.serialNumber = value; }
        }

        /// <summary>
        /// Adds a target name criterion for the attribute certificate to the target information extension criteria.
        /// The <c>X509V2AttributeCertificate</c> must contain at least one of the specified target names.
        /// </summary>
        /// <remarks>
        /// Each attribute certificate may contain a target information extension limiting the servers where this
        /// attribute certificate can be used. If this extension is not present, the attribute certificate is not
        /// targeted and may be accepted by any server.
        /// </remarks>
        /// <param name="name">The name as a <see cref="GeneralName"/> (not <c>null</c>).</param>
        public void AddTargetName(GeneralName name)
        {
            targetNames.Add(name);
        }

        /// <summary>
        /// Adds a target name criterion for the attribute certificate to the target information extension criteria.
        /// The <c>X509V2AttributeCertificate</c> must contain at least one of the specified target names.
        /// </summary>
        /// <remarks>
        /// Each attribute certificate may contain a target information extension limiting the servers where this
        /// attribute certificate can be used. If this extension is not present, the attribute certificate is not
        /// targeted and may be accepted by any server.
        /// </remarks>
        /// <param name="name">
        /// A <c>byte[]</c> containing the name as an ASN.1 DER-encoded <see cref="GeneralName"/>.
        /// </param>
        /// <exception cref="IOException">If a parsing error occurs.</exception>
        public void AddTargetName(byte[] name) => AddTargetName(GeneralName.GetInstance(name));

        /// <summary>
        /// Adds a collection with target names criteria. If <c>null</c> is given, any will do.
        /// </summary>
        /// <remarks>
        /// The collection consists of either <see cref="GeneralName"/> objects or <c>byte[]</c> representing
        /// DER-encoded <see cref="GeneralName"/> structures.
        /// </remarks>
        /// <exception cref="IOException">If a parsing error occurs.</exception>
        /// <seealso cref="AddTargetName(byte[])"/>
        /// <seealso cref="AddTargetName(GeneralName)"/>
        public void SetTargetNames(IEnumerable<object> names)
        {
            targetNames = ExtractGeneralNames(names);
        }

        /// <summary>Enumerate the target names.</summary>
        /// <seealso cref="SetTargetNames(IEnumerable{object})"/>
        public IEnumerable<GeneralName> GetTargetNames() => CollectionUtilities.Proxy(targetNames);

        /// <summary>
        /// Adds a target group criterion for the attribute certificate to the target information extension criteria.
        /// The <c>X509V2AttributeCertificate</c> must contain at least one of the specified target groups.
        /// </summary>
        /// <remarks>
        /// Each attribute certificate may contain a target information extension limiting the servers where this
        /// attribute certificate can be used. If this extension is not present, the attribute certificate is not
        /// targeted and may be accepted by any server.
        /// </remarks>
        /// <param name="group">The target group as a <see cref="GeneralName"/> (not <c>null</c>).</param>
        public void AddTargetGroup(GeneralName group)
        {
            targetGroups.Add(group);
        }

        /// <summary>
        /// Adds a target group criterion for the attribute certificate to the target information extension criteria.
        /// The <c>X509V2AttributeCertificate</c> must contain at least one of the specified target names.
        /// </summary>
        /// <remarks>
        /// Each attribute certificate may contain a target information extension limiting the servers where this
        /// attribute certificate can be used. If this extension is not present, the attribute certificate is not
        /// targeted and may be accepted by any server.
        /// </remarks>
        /// <param name="name">
        /// A <c>byte[]</c> containing the group as an ASN.1 DER-encoded <see cref="GeneralName"/>.
        /// </param>
        /// <exception cref="IOException">If a parsing error occurs.</exception>
        public void AddTargetGroup(byte[] name)
        {
            AddTargetGroup(GeneralName.GetInstance(Asn1Object.FromByteArray(name)));
        }

        /// <summary>
        /// Adds a collection with target groups criteria. If <c>null</c> is given, any will do.
        /// </summary>
        /// <remarks>
        /// The collection consists of either <see cref="GeneralName"/> objects or <c>byte[]</c> representing
        /// DER-encoded <see cref="GeneralName"/> structures.
        /// </remarks>
        /// <exception cref="IOException">If a parsing error occurs.</exception>
        /// <seealso cref="AddTargetGroup(byte[])"/>
        /// <seealso cref="AddTargetGroup(GeneralName)"/>
        public void SetTargetGroups(IEnumerable<object> names)
        {
            targetGroups = ExtractGeneralNames(names);
        }

        /// <summary>Enumerate the target groups.</summary>
        /// <seealso cref="SetTargetGroups(IEnumerable{object})"/>
        public IEnumerable<GeneralName> GetTargetGroups() => CollectionUtilities.Proxy(targetGroups);

        private ISet<GeneralName> ExtractGeneralNames(IEnumerable<object> names)
        {
            var result = new HashSet<GeneralName>();

            if (names != null)
            {
                foreach (object o in names)
                {
                    result.Add(GeneralName.GetInstance(o));
                }
            }

            return result;
        }

        private static bool MatchTargetGroups(Targets[] targetss, ISet<GeneralName> targetGroups) =>
            MatchTargetProperty(targetss, target => target.TargetGroup, targetGroups);

        private static bool MatchTargetNames(Targets[] targetss, ISet<GeneralName> targetNames) =>
            MatchTargetProperty(targetss, target => target.TargetName, targetNames);

        private static bool MatchTargetProperty(Targets[] targetss, Func<Target, GeneralName> property,
            ISet<GeneralName> matchValues)
        {
            foreach (Targets targets in targetss)
            {
                foreach (Target target in targets.GetTargets())
                {
                    GeneralName value = property(target);

                    if (value != null && matchValues.Contains(value))
                        return true;
                }
            }
            return false;
        }
    }
}
