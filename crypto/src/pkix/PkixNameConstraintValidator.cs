using System;
using System.Collections.Generic;
using System.Text;

using Org.BouncyCastle.Asn1;
using Org.BouncyCastle.Asn1.X509;
using Org.BouncyCastle.Utilities.Collections;
using Org.BouncyCastle.Utilities.Encoders;

namespace Org.BouncyCastle.Pkix
{
    public class PkixNameConstraintValidator
    {
        // The excluded* fields are null until the first excluded subtree of that family is added, and never
        // empty once created (unions only grow). The permitted* fields are null while the family is
        // unconstrained, and empty when nothing of that family is permitted.
        private HashSet<NameConstraintDN> excludedSubtreesDN;

        private HashSet<NameConstraintDns> excludedSubtreesDns;

        private HashSet<NameConstraintEmail> excludedSubtreesEmail;

        private HashSet<NameConstraintUri> excludedSubtreesUri;

        private HashSet<NameConstraintIPRange> excludedSubtreesIP;

        private HashSet<OtherName> excludedSubtreesOtherName;

        private HashSet<NameConstraintDN> permittedSubtreesDN;

        private HashSet<NameConstraintDns> permittedSubtreesDns;

        private HashSet<NameConstraintEmail> permittedSubtreesEmail;

        private HashSet<NameConstraintUri> permittedSubtreesUri;

        private HashSet<NameConstraintIPRange> permittedSubtreesIP;

        private HashSet<OtherName> permittedSubtreesOtherName;

        public PkixNameConstraintValidator()
        {
        }

        #region DN

        public void CheckExcludedDN(Asn1Sequence dn)
        {
            CheckExcludedDN(excludedSubtreesDN, dn);
        }

        public void CheckPermittedDN(Asn1Sequence dn)
        {
            CheckPermittedDN(permittedSubtreesDN, dn);
        }

        private static void CheckExcludedDN(HashSet<NameConstraintDN> excluded, Asn1Sequence directory)
        {
            if (excluded == null)
                return;

            if (NameConstraintDN.IsConstrained(excluded, NameConstraintDN.Create(directory)))
            {
                throw new PkixNameConstraintValidatorException(
                    "Subject distinguished name is from an excluded subtree");
            }
        }

        private static void CheckPermittedDN(HashSet<NameConstraintDN> permitted, Asn1Sequence directory)
        {
            if (permitted != null
                && !(directory.Count == 0 && permitted.Count < 1)
                && !NameConstraintDN.IsConstrained(permitted, NameConstraintDN.Create(directory)))
            {
                throw new PkixNameConstraintValidatorException(
                    "Subject distinguished name is not from a permitted subtree");
            }
        }

        #endregion

        #region OtherName

        private static void CheckExcludedOtherName(HashSet<OtherName> excluded, OtherName otherName)
        {
            if (excluded == null)
                return;

            if (IsOtherNameConstrained(excluded, otherName))
                throw new PkixNameConstraintValidatorException("OtherName is from an excluded subtree.");
        }

        private static void CheckPermittedOtherName(HashSet<OtherName> permitted, OtherName otherName)
        {
            if (permitted != null && !IsOtherNameConstrained(permitted, otherName))
                throw new PkixNameConstraintValidatorException("Subject OtherName is not from a permitted subtree.");
        }

        private static bool IsOtherNameConstrained(HashSet<OtherName> constraints, OtherName otherName)
        {
            foreach (OtherName constraint in constraints)
            {
                if (IsOtherNameConstrained(constraint, otherName))
                    return true;
            }

            return false;
        }

        private static bool IsOtherNameConstrained(OtherName constraint, OtherName otherName) =>
            constraint.Equals(otherName);

        private static HashSet<OtherName> IntersectOtherName(HashSet<OtherName> permitted,
            HashSet<GeneralSubtree> otherNames)
        {
            var intersect = new HashSet<OtherName>();
            foreach (GeneralSubtree subtree in otherNames)
            {
                OtherName otherName1 = OtherName.GetInstance(subtree.Base.Name);
                if (otherName1 == null)
                    continue;

                if (permitted == null)
                {
                    intersect.Add(otherName1);
                }
                else
                {
                    foreach (OtherName otherName2 in permitted)
                    {
                        IntersectOtherName(otherName1, otherName2, intersect);
                    }
                }
            }
            return intersect;
        }

        private static void IntersectOtherName(OtherName otherName1, OtherName otherName2, HashSet<OtherName> intersect)
        {
            if (otherName1.Equals(otherName2))
            {
                intersect.Add(otherName1);
            }
        }

        private static HashSet<OtherName> UnionOtherName(HashSet<OtherName> permitted, OtherName otherName)
        {
            var union = permitted != null ? new HashSet<OtherName>(permitted) : new HashSet<OtherName>();
            union.Add(otherName);
            return union;
        }

        #endregion

        #region Email

        public void CheckExcludedEmail(string email) => CheckExcludedEmail(excludedSubtreesEmail, email);

        public void CheckPermittedEmail(string email) => CheckPermittedEmail(permittedSubtreesEmail, email);

        private static void CheckExcludedEmail(HashSet<NameConstraintEmail> excluded, string email)
        {
            if (excluded == null)
                return;

            if (NameConstraintEmail.IsConstrained(excluded, NameConstraintEmail.Create(email)))
                throw new PkixNameConstraintValidatorException("Email address is from an excluded subtree.");
        }

        private static void CheckPermittedEmail(HashSet<NameConstraintEmail> permitted, string email)
        {
            if (permitted != null
                && !(email.Length == 0 && permitted.Count < 1)
                && !NameConstraintEmail.IsConstrained(permitted, NameConstraintEmail.Create(email)))
            {
                throw new PkixNameConstraintValidatorException(
                    "Subject email address is not from a permitted subtree.");
            }
        }

        #endregion

        #region IP

        private static void CheckExcludedIP(HashSet<NameConstraintIPRange> excluded, byte[] ip)
        {
            // Strict-when-constrained: NameConstraintIPAddress.Create validates the name's structure
            // (throwing, fail-closed), but only once there are constraints to check it against. An
            // "always strict" policy would construct (and so validate) the name before this guard.
            if (excluded == null)
                return;

            if (NameConstraintIPRange.IsConstrained(excluded, NameConstraintIPAddress.Create(ip)))
                throw new PkixNameConstraintValidatorException("IP is from an excluded subtree.");
        }

        private static void CheckPermittedIP(HashSet<NameConstraintIPRange> permitted, byte[] ip)
        {
            // Strict-when-constrained: see CheckExcludedIP. NOTE: the historical escape that allowed an
            // EMPTY iPAddress name past an emptied permitted set is gone; Create rejects it, fail-closed.
            if (permitted == null)
                return;

            if (!NameConstraintIPRange.IsConstrained(permitted, NameConstraintIPAddress.Create(ip)))
                throw new PkixNameConstraintValidatorException("IP is not from a permitted subtree.");
        }

        #endregion

        #region Dns

        private static void CheckExcludedDns(HashSet<NameConstraintDns> excluded, string dns)
        {
            if (excluded == null)
                return;

            if (NameConstraintDns.IsConstrained(excluded, NameConstraintDns.Create(dns)))
                throw new PkixNameConstraintValidatorException("DNS is from an excluded subtree.");
        }

        private static void CheckPermittedDns(HashSet<NameConstraintDns> permitted, string dns)
        {
            if (permitted != null
                && !(dns.Length == 0 && permitted.Count < 1)
                && !NameConstraintDns.IsConstrained(permitted, NameConstraintDns.Create(dns)))
            {
                throw new PkixNameConstraintValidatorException("DNS is not from a permitted subtree.");
            }
        }

        #endregion

        #region Uri

        private static void CheckExcludedUri(HashSet<NameConstraintUri> excluded, string uri)
        {
            if (excluded == null)
                return;

            if (NameConstraintUri.IsConstrained(excluded, NameConstraintUri.FromUri(uri)))
                throw new PkixNameConstraintValidatorException("URI is from an excluded subtree.");
        }

        private static void CheckPermittedUri(HashSet<NameConstraintUri> permitted, string uri)
        {
            // The empty-name escape must test the RAW uri: host extraction can reduce a non-empty URI
            // (e.g. "http://") to an empty host, which must not slip through an emptied permitted set.
            if (permitted != null
                && !(uri.Length == 0 && permitted.Count < 1)
                && !NameConstraintUri.IsConstrained(permitted, NameConstraintUri.FromUri(uri)))
            {
                throw new PkixNameConstraintValidatorException("URI is not from a permitted subtree.");
            }
        }

        #endregion

        /// <exception cref="PkixNameConstraintValidatorException"/>
        [Obsolete("Use 'CheckPermittedName' instead")]
        public void checkPermitted(GeneralName name) => CheckPermittedName(name);

        /**
         * Checks if the given GeneralName is in the permitted ISet.
         *
         * @param name The GeneralName
         * @throws PkixNameConstraintValidatorException
         *          If the <code>name</code>
         */
        /// <exception cref="PkixNameConstraintValidatorException"/>
        public void CheckPermittedName(GeneralName name)
        {
            var nameValue = name.Name;

            switch (name.TagNo)
            {
            case GeneralName.OtherName:
                CheckPermittedOtherName(permittedSubtreesOtherName, OtherName.GetInstance(nameValue));
                break;
            case GeneralName.Rfc822Name:
                CheckPermittedEmail(NameConstraintUtilities.ExtractIA5String(nameValue));
                break;
            case GeneralName.DnsName:
                CheckPermittedDns(permittedSubtreesDns, NameConstraintUtilities.ExtractIA5String(nameValue));
                break;
            case GeneralName.DirectoryName:
                CheckPermittedDN(Asn1Sequence.GetInstance(nameValue));
                break;
            case GeneralName.UniformResourceIdentifier:
                CheckPermittedUri(permittedSubtreesUri, NameConstraintUtilities.ExtractIA5String(nameValue));
                break;
            case GeneralName.IPAddress:
                CheckPermittedIP(permittedSubtreesIP, Asn1OctetString.GetInstance(nameValue).GetOctets());
                break;
                // Other tags ignored
            }
        }

        /// <exception cref="PkixNameConstraintValidatorException"/>
        [Obsolete("Use 'CheckExcludedName' instead")]
        public void checkExcluded(GeneralName name) => CheckExcludedName(name);

        /**
         * Check if the given GeneralName is contained in the excluded ISet.
         *
         * @param name The GeneralName.
         * @throws PkixNameConstraintValidatorException
         *          If the <code>name</code> is
         *          excluded.
         */
        /// <exception cref="PkixNameConstraintValidatorException"/>
        public void CheckExcludedName(GeneralName name)
        {
            var nameValue = name.Name;

            switch (name.TagNo)
            {
            case GeneralName.OtherName:
                CheckExcludedOtherName(excludedSubtreesOtherName, OtherName.GetInstance(nameValue));
                break;
            case GeneralName.Rfc822Name:
                CheckExcludedEmail(NameConstraintUtilities.ExtractIA5String(nameValue));
                break;
            case GeneralName.DnsName:
                CheckExcludedDns(excludedSubtreesDns, NameConstraintUtilities.ExtractIA5String(nameValue));
                break;
            case GeneralName.DirectoryName:
                CheckExcludedDN(Asn1Sequence.GetInstance(nameValue));
                break;
            case GeneralName.UniformResourceIdentifier:
                CheckExcludedUri(excludedSubtreesUri, NameConstraintUtilities.ExtractIA5String(nameValue));
                break;
            case GeneralName.IPAddress:
                CheckExcludedIP(excludedSubtreesIP, Asn1OctetString.GetInstance(nameValue).GetOctets());
                break;
                // Other tags ignored
            }
        }

        /// <exception cref="PkixNameConstraintValidatorException">for a structurally invalid constraint</exception>
        public void IntersectPermittedSubtree(GeneralSubtree permitted) =>
            IntersectPermittedSubtree(permitted.Base.TagNo, new HashSet<GeneralSubtree>() { permitted });

        /**
         * Updates the permitted ISet of these name constraints with the intersection
         * with the given subtree.
         *
         * @param permitted The permitted subtrees
         */
        /// <exception cref="PkixNameConstraintValidatorException">for a structurally invalid constraint</exception>
        public void IntersectPermittedSubtree(Asn1Sequence permitted)
        {
            var subtreesMap = new Dictionary<int, HashSet<GeneralSubtree>>();

            // Group in HashSets in a Dictionary ordered by TagNo.
            foreach (var subtree in CollectionUtilities.Select(permitted, GeneralSubtree.GetInstance))
            {
                int tagNo = subtree.Base.TagNo;

                HashSet<GeneralSubtree> subtrees;
                if (!subtreesMap.TryGetValue(tagNo, out subtrees))
                {
                    subtrees = new HashSet<GeneralSubtree>();
                    subtreesMap[tagNo] = subtrees;
                }

                subtrees.Add(subtree);
            }

            // go through all subtree groups
            foreach (var entry in subtreesMap)
            {
                IntersectPermittedSubtree(nameType: entry.Key, subtrees: entry.Value);
            }
        }

        private void IntersectPermittedSubtree(int nameType, HashSet<GeneralSubtree> subtrees)
        {
            switch (nameType)
            {
            case GeneralName.OtherName:
                permittedSubtreesOtherName = IntersectOtherName(permittedSubtreesOtherName, subtrees);
                break;
            case GeneralName.Rfc822Name:
                permittedSubtreesEmail = NameConstraintEmail.Intersect(permittedSubtreesEmail, subtrees);
                break;
            case GeneralName.DnsName:
                permittedSubtreesDns = NameConstraintDns.Intersect(permittedSubtreesDns, subtrees);
                break;
            case GeneralName.DirectoryName:
                permittedSubtreesDN = NameConstraintDN.Intersect(permittedSubtreesDN, subtrees);
                break;
            case GeneralName.UniformResourceIdentifier:
                permittedSubtreesUri = NameConstraintUri.Intersect(permittedSubtreesUri, subtrees);
                break;
            case GeneralName.IPAddress:
                permittedSubtreesIP = NameConstraintIPRange.Intersect(permittedSubtreesIP, subtrees);
                break;
            default:
                throw new InvalidOperationException("Unknown tag encountered: " + nameType);
            }
        }

        public void IntersectEmptyPermittedSubtree(int nameType)
        {
            switch (nameType)
            {
            case GeneralName.OtherName:
                permittedSubtreesOtherName = new HashSet<OtherName>();
                break;
            case GeneralName.Rfc822Name:
                permittedSubtreesEmail = new HashSet<NameConstraintEmail>();
                break;
            case GeneralName.DnsName:
                permittedSubtreesDns = new HashSet<NameConstraintDns>();
                break;
            case GeneralName.DirectoryName:
                permittedSubtreesDN = new HashSet<NameConstraintDN>();
                break;
            case GeneralName.UniformResourceIdentifier:
                permittedSubtreesUri = new HashSet<NameConstraintUri>();
                break;
            case GeneralName.IPAddress:
                permittedSubtreesIP = new HashSet<NameConstraintIPRange>();
                break;
            default:
                throw new InvalidOperationException("Unknown tag encountered: " + nameType);
            }
        }

        /**
         * Adds a subtree to the excluded ISet of these name constraints.
         *
         * @param subtree A subtree with an excluded GeneralName.
         */
        /// <exception cref="PkixNameConstraintValidatorException">for a structurally invalid constraint</exception>
        public void AddExcludedSubtree(GeneralSubtree subtree)
        {
            var subtreeBase = subtree.Base;
            var nameValue = subtreeBase.Name;

            switch (subtreeBase.TagNo)
            {
            case GeneralName.OtherName:
                excludedSubtreesOtherName = UnionOtherName(excludedSubtreesOtherName, OtherName.GetInstance(nameValue));
                break;
            case GeneralName.Rfc822Name:
                excludedSubtreesEmail = NameConstraintEmail.Union(excludedSubtreesEmail,
                    NameConstraintEmail.Create(NameConstraintUtilities.ExtractIA5String(nameValue)));
                break;
            case GeneralName.DnsName:
                excludedSubtreesDns = NameConstraintDns.Union(excludedSubtreesDns,
                    NameConstraintDns.Create(NameConstraintUtilities.ExtractIA5String(nameValue)));
                break;
            case GeneralName.DirectoryName:
                excludedSubtreesDN = NameConstraintDN.Union(excludedSubtreesDN,
                    NameConstraintDN.Create(Asn1Sequence.GetInstance(nameValue)));
                break;
            case GeneralName.UniformResourceIdentifier:
                excludedSubtreesUri = NameConstraintUri.Union(excludedSubtreesUri,
                    NameConstraintUri.FromConstraint(NameConstraintUtilities.ExtractIA5String(nameValue)));
                break;
            case GeneralName.IPAddress:
                excludedSubtreesIP = NameConstraintIPRange.Union(excludedSubtreesIP,
                    NameConstraintIPRange.Create(Asn1OctetString.GetInstance(nameValue).GetOctets()));
                break;
            default:
                throw new InvalidOperationException("Unknown tag encountered: " + subtreeBase.TagNo);
            }
        }

        public override int GetHashCode()
        {
            return HashCollection(excludedSubtreesDN)
                + HashCollection(excludedSubtreesDns)
                + HashCollection(excludedSubtreesEmail)
                + HashCollection(excludedSubtreesIP)
                + HashCollection(excludedSubtreesUri)
                + HashCollection(excludedSubtreesOtherName)
                + HashCollection(permittedSubtreesDN)
                + HashCollection(permittedSubtreesDns)
                + HashCollection(permittedSubtreesEmail)
                + HashCollection(permittedSubtreesIP)
                + HashCollection(permittedSubtreesUri)
                + HashCollection(permittedSubtreesOtherName);
        }

        private static int HashCollection<T>(HashSet<T> c)
        {
            int hash = 0;
            if (c != null)
            {
                foreach (T o in c)
                {
                    hash += o.GetHashCode();
                }
            }
            return hash;
        }

        public override bool Equals(object o) => o is PkixNameConstraintValidator that
            && AreEqualSets(that.excludedSubtreesDN, excludedSubtreesDN)
            && AreEqualSets(that.excludedSubtreesDns, excludedSubtreesDns)
            && AreEqualSets(that.excludedSubtreesEmail, excludedSubtreesEmail)
            && AreEqualSets(that.excludedSubtreesIP, excludedSubtreesIP)
            && AreEqualSets(that.excludedSubtreesUri, excludedSubtreesUri)
            && AreEqualSets(that.excludedSubtreesOtherName, excludedSubtreesOtherName)
            && AreEqualSets(that.permittedSubtreesDN, permittedSubtreesDN)
            && AreEqualSets(that.permittedSubtreesDns, permittedSubtreesDns)
            && AreEqualSets(that.permittedSubtreesEmail, permittedSubtreesEmail)
            && AreEqualSets(that.permittedSubtreesIP, permittedSubtreesIP)
            && AreEqualSets(that.permittedSubtreesUri, permittedSubtreesUri)
            && AreEqualSets(that.permittedSubtreesOtherName, permittedSubtreesOtherName);

        private static bool AreEqualSets<T>(HashSet<T> set1, HashSet<T> set2)
        {
            if (set1 == set2)
                return true;
            if (set1 == null || set2 == null || set1.Count != set2.Count)
                return false;

            foreach (T a in set1)
            {
                if (!set2.Contains(a))
                    return false;
            }
            return true;
        }

        private static string StringifyCollection<T>(HashSet<T> c)
        {
            // Unspecified HashSet enumeration order is acceptable in an informational message; avoid
            // relying on, or trying to pin, the ordering.
            StringBuilder sb = new StringBuilder("[");
            var en = c.GetEnumerator();
            if (en.MoveNext())
            {
                for (;;)
                {
                    sb.Append(en.Current);

                    if (!en.MoveNext())
                        break;

                    sb.Append(", ");
                }
            }
            sb.Append(']');
            return sb.ToString();
        }

        private static string StringifyOtherNames(HashSet<OtherName> otherNames)
        {
            StringBuilder sb = new StringBuilder("[");
            var en = otherNames.GetEnumerator();
            if (en.MoveNext())
            {
                for (;;)
                {
                    OtherName otherName = en.Current;
                    sb.Append(otherName.TypeID.Id);
                    sb.Append(':');
                    sb.Append(Hex.ToHexString(otherName.Value.GetEncoded()));

                    if (!en.MoveNext())
                        break;

                    sb.Append(", ");
                }
            }
            sb.Append(']');
            return sb.ToString();
        }

        public override string ToString()
        {
            StringBuilder sb = new StringBuilder("permitted:");
            sb.AppendLine();
            if (permittedSubtreesDN != null)
            {
                Append(sb, "DN", StringifyCollection(permittedSubtreesDN));
            }
            if (permittedSubtreesDns != null)
            {
                Append(sb, "DNS", StringifyCollection(permittedSubtreesDns));
            }
            if (permittedSubtreesEmail != null)
            {
                Append(sb, "Email", StringifyCollection(permittedSubtreesEmail));
            }
            if (permittedSubtreesUri != null)
            {
                Append(sb, "URI", StringifyCollection(permittedSubtreesUri));
            }
            if (permittedSubtreesIP != null)
            {
                Append(sb, "IP", StringifyCollection(permittedSubtreesIP));
            }
            if (permittedSubtreesOtherName != null)
            {
                Append(sb, "OtherName", StringifyOtherNames(permittedSubtreesOtherName));
            }
            sb.AppendLine("excluded:");
            if (excludedSubtreesDN != null)
            {
                Append(sb, "DN", StringifyCollection(excludedSubtreesDN));
            }
            if (excludedSubtreesDns != null)
            {
                Append(sb, "DNS", StringifyCollection(excludedSubtreesDns));
            }
            if (excludedSubtreesEmail != null)
            {
                Append(sb, "Email", StringifyCollection(excludedSubtreesEmail));
            }
            if (excludedSubtreesUri != null)
            {
                Append(sb, "URI", StringifyCollection(excludedSubtreesUri));
            }
            if (excludedSubtreesIP != null)
            {
                Append(sb, "IP", StringifyCollection(excludedSubtreesIP));
            }
            if (excludedSubtreesOtherName != null)
            {
                Append(sb, "OtherName", StringifyOtherNames(excludedSubtreesOtherName));
            }
            return sb.ToString();
        }

        private static void Append(StringBuilder sb, string name, string value)
        {
            sb.Append(name);
            sb.AppendLine(":");
            sb.Append(value);
            sb.AppendLine();
        }
    }
}
