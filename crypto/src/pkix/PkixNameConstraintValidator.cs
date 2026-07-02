using System;
using System.Collections.Generic;
using System.Text;

using Org.BouncyCastle.Asn1;
using Org.BouncyCastle.Asn1.X500;
using Org.BouncyCastle.Asn1.X500.Style;
using Org.BouncyCastle.Asn1.X509;
using Org.BouncyCastle.Utilities;
using Org.BouncyCastle.Utilities.Collections;
using Org.BouncyCastle.Utilities.Encoders;

namespace Org.BouncyCastle.Pkix
{
    public class PkixNameConstraintValidator
    {
        private static readonly DerObjectIdentifier SerialNumberOid = X509Name.SerialNumber;

        private HashSet<Asn1Sequence> excludedSubtreesDN = new HashSet<Asn1Sequence>();

        private HashSet<string> excludedSubtreesDns = new HashSet<string>();

        private HashSet<string> excludedSubtreesEmail = new HashSet<string>();

        private HashSet<string> excludedSubtreesUri = new HashSet<string>();

        private HashSet<byte[]> excludedSubtreesIP = new HashSet<byte[]>();

        private HashSet<OtherName> excludedSubtreesOtherName = new HashSet<OtherName>();

        private HashSet<Asn1Sequence> permittedSubtreesDN;

        private HashSet<string> permittedSubtreesDns;

        private HashSet<string> permittedSubtreesEmail;

        private HashSet<string> permittedSubtreesUri;

        private HashSet<byte[]> permittedSubtreesIP;

        private HashSet<OtherName> permittedSubtreesOtherName;

        public PkixNameConstraintValidator()
        {
        }

        private static bool WithinDNSubtree(Asn1Sequence dns, Asn1Sequence subtree)
        {
            // An empty subtree would be a prefix of every DN; treat it as "no match" instead, so an empty permitted
            // base can't nullify the permittedSubtrees restriction.
            if (subtree.Count < 1)
                return false;

            // A prefix can't be longer than the DN.
            if (subtree.Count > dns.Count)
                return false;

            // Relaxed anywhere-match needed for GSMA SGP.22, gated behind a property.
            if (Properties.GetBoolean(Properties.X509Sgp22NameConstraints, false))
                return WithinDNSubtreeSgp22(dns, subtree);

            // RFC 5280 4.2.1.10 / 7.1: a directoryName constraint is satisfied only when the constraint's RDNSequence
            // is an initial prefix of the subject's. Match from index 0 only - searching for the constraint's first RDN
            // at an arbitrary offset let an attacker prepend RDNs ahead of the permitted sequence (e.g. a subject
            // C=FR,O=Attacker,C=US,O=TrustedOrg,CN=x being judged inside permitted subtree C=US,O=TrustedOrg) and still
            // pass the permittedSubtrees check.

            for (int j = 0; j < subtree.Count; j++)
            {
                // both subtree and dns are a ASN.1 Name and the elements are a RDN
                Rdn subtreeRdn = Rdn.GetInstance(subtree[j]);
                Rdn dnsRdn = Rdn.GetInstance(dns[j]);

                // Obey RFC 5280 7.1. Two relative distinguished names RDN1 and RDN2 match if they have the same number
                // of naming attributes and for each naming attribute in RDN1 there is a matching naming attribute in
                // RDN2. NOTE: this is now different from the RFC 3280 version, where only binary comparison was used.
                if (!IetfUtilities.RdnAreEqual(subtreeRdn, dnsRdn))
                    return false;
            }

            return true;
        }

        /**
         * Relaxed directoryName subtree matching for GSMA SGP.22 v2.5 (sections 4.5.2.1.0.2 and
         * 4.5.2.1.0.3), enabled only when {@link Properties#X509_SGP22_NAME_CONSTRAINTS} is set. Each
         * RDN of the permitted subtree must be matched by some RDN of the subject DN regardless of
         * position; additional subject attributes are permitted, and a serialNumber RDN is matched with
         * a startsWith comparison wherever it occurs. This deliberately departs from the contiguous
         * prefix matching of RFC 5280 7.1 implemented by {@link #withinDNSubtree(ASN1Sequence, ASN1Sequence)}.
         */
        private static bool WithinDNSubtreeSgp22(Asn1Sequence dns, Asn1Sequence subtree)
        {
            Rdn[] dnsRdns = dns.MapElements(Rdn.GetInstance);

            foreach (Rdn subtreeRdn in CollectionUtilities.Select(subtree, Rdn.GetInstance))
            {
                if (!RdnMatchesSgp22Any(subtreeRdn, dnsRdns))
                    return false;
            }
            return true;
        }

        private static bool RdnMatchesSgp22Any(Rdn subtreeRdn, Rdn[] dnsRdns)
        {
            foreach (Rdn dnsRdn in dnsRdns)
            {
                if (RdnMatchesSgp22(subtreeRdn, dnsRdn))
                    return true;
            }
            return false;
        }

        private static bool RdnMatchesSgp22(Rdn subtreeRdn, Rdn dnsRdn)
        {
            if (subtreeRdn.Count != dnsRdn.Count)
                return false;

            var subtreeFirst = subtreeRdn.GetFirst();
            var dnsFirst = dnsRdn.GetFirst();

            if (!subtreeFirst.Type.Equals(dnsFirst.Type))
                return false;

            // special treatment of serialNumber for GSMA SGP.22 RSP specification
            if (subtreeRdn.Count == 1 && subtreeFirst.Type.Equals(X509Name.SerialNumber))
            {
                var subtreeFirstValue = DerPrintableString.GetInstance(subtreeFirst.Value).GetString();
                var dnsFirstValue = DerPrintableString.GetInstance(dnsFirst.Value).GetString();
                return Platform.StartsWith(dnsFirstValue, subtreeFirstValue);
            }

            return IetfUtilities.RdnAreEqual(subtreeRdn, dnsRdn);
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

        private static void CheckExcludedDN(HashSet<Asn1Sequence> excluded, Asn1Sequence directory)
        {
            if (IsDNConstrained(excluded, directory))
            {
                throw new PkixNameConstraintValidatorException(
                    "Subject distinguished name is from an excluded subtree");
            }
        }

        private static void CheckPermittedDN(HashSet<Asn1Sequence> permitted, Asn1Sequence directory)
        {
            if (permitted != null
                && !(directory.Count == 0 && permitted.Count < 1)
                && !IsDNConstrained(permitted, directory))
            {
                throw new PkixNameConstraintValidatorException(
                    "Subject distinguished name is not from a permitted subtree");
            }
        }

        private static bool IsDNConstrained(HashSet<Asn1Sequence> constraints, Asn1Sequence directory)
        {
            foreach (var constraint in constraints)
            {
                if (WithinDNSubtree(directory, constraint))
                    return true;
            }

            return false;
        }

        private static HashSet<Asn1Sequence> IntersectDN(HashSet<Asn1Sequence> permitted, HashSet<GeneralSubtree> dns)
        {
            var intersect = new HashSet<Asn1Sequence>();
            foreach (GeneralSubtree subtree1 in dns)
            {
                Asn1Sequence dn1 = Asn1Sequence.GetInstance(subtree1.Base.Name);
                if (permitted == null)
                {
                    if (dn1 != null)
                    {
                        intersect.Add(dn1);
                    }
                }
                else
                {
                    foreach (var dn2 in permitted)
                    {
                        if (WithinDNSubtree(dn1, dn2))
                        {
                            intersect.Add(dn1);
                        }
                        else if (WithinDNSubtree(dn2, dn1))
                        {
                            intersect.Add(dn2);
                        }
                    }
                }
            }
            return intersect;
        }

        private static HashSet<Asn1Sequence> UnionDN(HashSet<Asn1Sequence> excluded, Asn1Sequence dn)
        {
            if (excluded.Count < 1)
            {
                if (dn != null)
                {
                    excluded.Add(dn);
                }
                return excluded;
            }

            var union = new HashSet<Asn1Sequence>();

            foreach (var subtree in excluded)
            {
                if (WithinDNSubtree(dn, subtree))
                {
                    union.Add(subtree);
                }
                else if (WithinDNSubtree(subtree, dn))
                {
                    union.Add(dn);
                }
                else
                {
                    union.Add(subtree);
                    union.Add(dn);
                }
            }

            return union;
        }

        #endregion

        #region OtherName

        private static void CheckExcludedOtherName(HashSet<OtherName> excluded, OtherName otherName)
        {
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

        private static void CheckExcludedEmail(HashSet<string> excluded, string email)
        {
            if (IsEmailConstrained(excluded, email))
                throw new PkixNameConstraintValidatorException("Email address is from an excluded subtree.");
        }

        private static void CheckPermittedEmail(HashSet<string> permitted, string email)
        {
            if (permitted != null
                && !(email.Length == 0 && permitted.Count < 1)
                && !IsEmailConstrained(permitted, email))
            {
                throw new PkixNameConstraintValidatorException(
                    "Subject email address is not from a permitted subtree.");
            }
        }

        private static bool IsEmailConstrained(HashSet<string> constraints, string email)
        {
            foreach (string constraint in constraints)
            {
                if (IsEmailConstrained(constraint, email))
                    return true;
            }

            return false;
        }

        private static bool IsEmailConstrained(string constraint, string email)
        {
            int atPos = constraint.IndexOf('@');

            // a particular mailbox. RFC 1034 root-label trailing dot: the dNSName path strips it (see
            // IsDnsConstrained); apply the same canonicalisation to the rfc822Name host so a trailing dot
            // (e.g. "user@bank.com.") cannot slip a leaf past an excluded/permitted "bank.com" constraint.
            if (atPos > 0)
                return Platform.EqualsIgnoreCase(StripTrailingDot(email), StripTrailingDot(constraint));

            string sub = StripTrailingDot(email.Substring(email.IndexOf('@') + 1));

            // "@domain" style
            if (atPos == 0)
                return Platform.EqualsIgnoreCase(sub, StripTrailingDot(constraint.Substring(1)));

            // address in sub domain
            if (Platform.StartsWith(constraint, "."))
                return WithinDomain(sub, constraint);

            // on particular host
            return Platform.EqualsIgnoreCase(sub, StripTrailingDot(constraint));
        }

        private static HashSet<string> IntersectEmail(HashSet<string> permitted, HashSet<GeneralSubtree> emails)
        {
            var intersect = new HashSet<string>();
            foreach (GeneralSubtree subtree1 in emails)
            {
                string email = ExtractNameAsString(subtree1);

                if (permitted == null)
                {
                    intersect.Add(email);
                }
                else
                {
                    foreach (string _permitted in permitted)
                    {
                        IntersectEmail(email, _permitted, intersect);
                    }
                }
            }
            return intersect;
        }

        /**
         * The most restricting part from <code>email1</code> and
         * <code>email2</code> is added to the intersection <code>intersect</code>.
         *
         * @param email1    Email address constraint 1.
         * @param email2    Email address constraint 2.
         * @param intersect The intersection.
         */
        private static void IntersectEmail(string email1, string email2, HashSet<string> intersect)
        {
            int email1AtPos = email1.IndexOf('@');
            int email2AtPos = email2.IndexOf('@');

            // email1 is a particular address
            if (email1AtPos != -1)
            {
                string _sub = email1.Substring(email1AtPos + 1);
                // both are a particular mailbox
                if (email2AtPos != -1)
                {
                    if (Platform.EqualsIgnoreCase(email1, email2))
                    {
                        intersect.Add(email1);
                    }
                }
                // email2 specifies a domain
                else if (Platform.StartsWith(email2, "."))
                {
                    if (WithinDomain(_sub, email2))
                    {
                        intersect.Add(email1);
                    }
                }
                // email2 specifies a particular host
                else
                {
                    if (Platform.EqualsIgnoreCase(_sub, email2))
                    {
                        intersect.Add(email1);
                    }
                }
            }
            // email specifies a domain
            else if (Platform.StartsWith(email1, "."))
            {
                if (email2AtPos != -1)
                {
                    string _sub = email2.Substring(email2AtPos + 1);
                    if (WithinDomain(_sub, email1))
                    {
                        intersect.Add(email2);
                    }
                }
                // email2 specifies a domain
                else if (Platform.StartsWith(email2, "."))
                {
                    if (IsDnsConstrained(email2, email1))
                    {
                        intersect.Add(email1);
                    }
                    else if (WithinDomain(email2, email1))
                    {
                        intersect.Add(email2);
                    }
                    else
                    {
                        // No intersection
                    }
                }
                else
                {
                    if (WithinDomain(email2, email1))
                    {
                        intersect.Add(email2);
                    }
                }
            }
            // email1 specifies a host
            else
            {
                if (email2AtPos != -1)
                {
                    string _sub = email2.Substring(email2AtPos + 1);
                    if (Platform.EqualsIgnoreCase(_sub, email1))
                    {
                        intersect.Add(email2);
                    }
                }
                // email2 specifies a domain
                else if (Platform.StartsWith(email2, "."))
                {
                    if (WithinDomain(email1, email2))
                    {
                        intersect.Add(email1);
                    }
                }
                // email2 specifies a particular host
                else
                {
                    if (Platform.EqualsIgnoreCase(email1, email2))
                    {
                        intersect.Add(email1);
                    }
                }
            }
        }

        private static string StripTrailingDot(string s)
        {
            // length > 1 so a single bare "." (theoretically the empty-label
            // root) is preserved rather than reduced to "".
            if (s != null && s.Length > 1 && s[s.Length - 1] == '.')
                return s.Substring(0, s.Length - 1);

            return s;
        }

        private static HashSet<string> UnionEmail(HashSet<string> excluded, string email)
        {
            if (excluded.Count < 1)
            {
                excluded.Add(email);
                return excluded;
            }

            var union = new HashSet<string>();
            foreach (string _excluded in excluded)
            {
                UnionEmail(_excluded, email, union);
            }
            return union;
        }

        /**
         * The common part of <code>email1</code> and <code>email2</code> is
         * added to the union <code>union</code>. If <code>email1</code> and
         * <code>email2</code> have nothing in common they are added both.
         *
         * @param email1 Email address constraint 1.
         * @param email2 Email address constraint 2.
         * @param union  The union.
         */
        private static void UnionEmail(string email1, string email2, HashSet<string> union)
        {
            int email1AtPos = email1.IndexOf('@');
            int email2AtPos = email2.IndexOf('@');

            // email1 is a particular address
            if (email1AtPos != -1)
            {
                string _sub = email1.Substring(email1AtPos + 1);
                // both are a particular mailbox
                if (email2AtPos != -1)
                {
                    if (Platform.EqualsIgnoreCase(email1, email2))
                    {
                        union.Add(email1);
                    }
                    else
                    {
                        union.Add(email1);
                        union.Add(email2);
                    }
                }
                // email2 specifies a domain
                else if (Platform.StartsWith(email2, "."))
                {
                    if (WithinDomain(_sub, email2))
                    {
                        union.Add(email2);
                    }
                    else
                    {
                        union.Add(email1);
                        union.Add(email2);
                    }
                }
                // email2 specifies a particular host
                else
                {
                    if (Platform.EqualsIgnoreCase(_sub, email2))
                    {
                        union.Add(email2);
                    }
                    else
                    {
                        union.Add(email1);
                        union.Add(email2);
                    }
                }
            }
            // email1 specifies a domain
            else if (Platform.StartsWith(email1, "."))
            {
                if (email2AtPos != -1)
                {
                    string _sub = email2.Substring(email2AtPos + 1);
                    if (WithinDomain(_sub, email1))
                    {
                        union.Add(email1);
                    }
                    else
                    {
                        union.Add(email1);
                        union.Add(email2);
                    }
                }
                // email2 specifies a domain
                else if (Platform.StartsWith(email2, "."))
                {
                    if (IsDnsConstrained(email2, email1))
                    {
                        union.Add(email2);
                    }
                    else if (WithinDomain(email2, email1))
                    {
                        union.Add(email1);
                    }
                    else
                    {
                        union.Add(email1);
                        union.Add(email2);
                    }
                }
                else
                {
                    if (WithinDomain(email2, email1))
                    {
                        union.Add(email1);
                    }
                    else
                    {
                        union.Add(email1);
                        union.Add(email2);
                    }
                }
            }
            // email specifies a host
            else
            {
                if (email2AtPos != -1)
                {
                    string _sub = email2.Substring(email2AtPos + 1);
                    if (Platform.EqualsIgnoreCase(_sub, email1))
                    {
                        union.Add(email1);
                    }
                    else
                    {
                        union.Add(email1);
                        union.Add(email2);
                    }
                }
                // email2 specifies a domain
                else if (Platform.StartsWith(email2, "."))
                {
                    if (WithinDomain(email1, email2))
                    {
                        union.Add(email2);
                    }
                    else
                    {
                        union.Add(email1);
                        union.Add(email2);
                    }
                }
                // email2 specifies a particular host
                else
                {
                    if (Platform.EqualsIgnoreCase(email1, email2))
                    {
                        union.Add(email1);
                    }
                    else
                    {
                        union.Add(email1);
                        union.Add(email2);
                    }
                }
            }
        }

        #endregion

        #region IP

        /**
         * Checks if the IP <code>ip</code> is included in the excluded ISet
         * <code>excluded</code>.
         *
         * @param excluded A <code>Set</code> of excluded IP addresses with their
         *                 subnet mask as byte arrays.
         * @param ip       The IP address.
         * @throws PkixNameConstraintValidatorException
         *          if the IP is excluded.
         */
        private static void CheckExcludedIP(HashSet<byte[]> excluded, byte[] ip)
        {
            if (IsIPConstrained(excluded, ip))
                throw new PkixNameConstraintValidatorException("IP is from an excluded subtree.");
        }

        /**
         * Checks if the IP <code>ip</code> is included in the permitted ISet
         * <code>permitted</code>.
         *
         * @param permitted A <code>Set</code> of permitted IP addresses with
         *                  their subnet mask as byte arrays.
         * @param ip        The IP address.
         * @throws PkixNameConstraintValidatorException
         *          if the IP is not permitted.
         */
        private static void CheckPermittedIP(HashSet<byte[]> permitted, byte[] ip)
        {
            if (permitted != null
                && !(ip.Length == 0 && permitted.Count < 1)
                && !IsIPConstrained(permitted, ip))
            {
                throw new PkixNameConstraintValidatorException("IP is not from a permitted subtree.");
            }
        }

        private static bool IsIPConstrained(HashSet<byte[]> constraints, byte[] ip)
        {
            foreach (byte[] constraint in constraints)
            {
                if (IsIPConstrained(constraint, ip))
                    return true;
            }

            return false;
        }

        /**
         * Checks if the IP address <code>ip</code> is constrained by
         * <code>constraint</code>.
         *
         * @param constraint The constraint. This is an IP address concatenated with
         *                   its subnetmask.
         * @param ip         The IP address.
         * @return <code>true</code> if constrained, <code>false</code>
         *         otherwise.
         */
        private static bool IsIPConstrained(byte[] constraint, byte[] ip)
        {
            // Normalise IPv4-mapped IPv6 (::ffff:0:0/96 per RFC 4291 sec. 2.5.5.2)
            // to IPv4 on BOTH sides before the length-equality pre-filter, so a
            // SAN that encodes the same IPv4 address using the 16-byte IPv4-
            // mapped IPv6 form doesn't escape an 8-byte IPv4 constraint via
            // the address-family-length mismatch. RFC 4291 makes the two forms
            // equivalent for host identification, so the normalisation is also
            // semantics-preserving in the permitted-subtree direction.
            ip = NormalizeIPv4MappedIPv6Address(ip);
            constraint = NormalizeIPv4MappedIPv6Constraint(constraint);

            int ipLength = ip.Length;
            if (ipLength != (constraint.Length / 2))
                return false;

            byte[] subnetMask = new byte[ipLength];
            Array.Copy(constraint, ipLength, subnetMask, 0, ipLength);

            byte[] permittedSubnetAddress = new byte[ipLength];

            byte[] ipSubnetAddress = new byte[ipLength];

            // the resulting IP address by applying the subnet mask
            for (int i = 0; i < ipLength; i++)
            {
                permittedSubnetAddress[i] = (byte)(constraint[i] & subnetMask[i]);
                ipSubnetAddress[i] = (byte)(ip[i] & subnetMask[i]);
            }

            return Arrays.AreEqual(permittedSubnetAddress, ipSubnetAddress);
        }

        /**
         * If {@code ip} is a 16-byte IPv4-mapped IPv6 address (RFC 4291
         * sec. 2.5.5.2: leading 80 bits zero, next 16 bits all-ones, trailing
         * 32 bits the IPv4 address), return the 4-byte IPv4 form; otherwise
         * return {@code ip} unchanged.
         */
        private static byte[] NormalizeIPv4MappedIPv6Address(byte[] ip)
        {
            if (!IsIPv4MappedIPv6Address(ip))
                return ip;

            byte[] ipv4 = new byte[4];
            Array.Copy(ip, 12, ipv4, 0, 4);
            return ipv4;
        }

        /**
         * A Name-Constraints iPAddress constraint is encoded as
         * {@code IP || subnet-mask}. If both halves are in IPv4-mapped IPv6
         * form (the IP half matches the {@code ::ffff:0:0/96} prefix and the
         * mask half is all-ones across the first 96 bits), reduce to the
         * 8-byte (4-byte IPv4 || 4-byte mask) form. Otherwise return the
         * constraint unchanged. The mask check matters: a mask narrower than
         * /96 means the constraint is really an IPv6 range that happens to
         * start at an IPv4-mapped address, and collapsing it to IPv4 would
         * change which addresses match.
         */
        private static byte[] NormalizeIPv4MappedIPv6Constraint(byte[] constraint)
        {
            if (constraint.Length != 32)
                return constraint;

            byte[] ipHalf = new byte[16];
            byte[] maskHalf = new byte[16];
            Array.Copy(constraint, 0, ipHalf, 0, 16);
            Array.Copy(constraint, 16, maskHalf, 0, 16);

            if (!IsIPv4MappedIPv6Address(ipHalf))
                return constraint;

            for (int i = 0; i < 12; i++)
            {
                if (maskHalf[i] != (byte)0xFF)
                    return constraint;
            }

            byte[] result = new byte[8];
            Array.Copy(ipHalf, 12, result, 0, 4);
            Array.Copy(maskHalf, 12, result, 4, 4);
            return result;
        }

        private static bool IsIPv4MappedIPv6Address(byte[] ip)
        {
            if (ip == null || ip.Length != 16)
                return false;

            for (int i = 0; i < 10; i++)
            {
                if (ip[i] != 0)
                    return false;
            }
            return ip[10] == (byte)0xFF && ip[11] == (byte)0xFF;
        }

        /**
         * Returns the intersection of the permitted IP ranges in
         * <code>permitted</code> with <code>ips</code>.
         *
         * @param permitted A <code>Set</code> of permitted IP addresses with
         *                  their subnet mask as byte arrays.
         * @param ips       The IP address with its subnet mask.
         * @return The <code>Set</code> of permitted IP ranges intersected with
         *         <code>ips</code>.
         */
        private static HashSet<byte[]> IntersectIP(HashSet<byte[]> permitted, HashSet<GeneralSubtree> ips)
        {
            var intersect = new HashSet<byte[]>();
            foreach (GeneralSubtree subtree in ips)
            {
                byte[] ip = Asn1OctetString.GetInstance(subtree.Base.Name).GetOctets();
                if (permitted == null)
                {
                    intersect.Add(ip);
                }
                else
                {
                    foreach (byte[] _permitted in permitted)
                    {
                        var intersection = IntersectIPRange(_permitted, ip);
                        if (intersection != null)
                        {
                            intersect.Add(intersection);
                        }
                    }
                }
            }
            return intersect;
        }

        /**
         * Calculates the interesction if two IP ranges.
         *
         * @param ipWithSubmask1 The first IP address with its subnet mask.
         * @param ipWithSubmask2 The second IP address with its subnet mask.
         * @return A single IP address with its subnet mask as a byte array, or null.
         */
        private static byte[] IntersectIPRange(byte[] ipWithSubmask1, byte[] ipWithSubmask2)
        {
            // i.e. no intersection between IPv4 and IPv6 ranges
            if (ipWithSubmask1.Length != ipWithSubmask2.Length)
                return null;

            byte[][] temp = ExtractIPsAndSubnetMasks(ipWithSubmask1, ipWithSubmask2);
            byte[] ip1 = temp[0];
            byte[] subnetmask1 = temp[1];
            byte[] ip2 = temp[2];
            byte[] subnetmask2 = temp[3];

            byte[][] minMax = MinMaxIPs(ip1, subnetmask1, ip2, subnetmask2);
            byte[] min1 = minMax[0];
            byte[] max1 = minMax[1];
            byte[] min2 = minMax[2];
            byte[] max2 = minMax[3];

            byte[] max = Min(max1, max2);
            byte[] min = Max(min1, min2);

            // minimum IP address can't be bigger than max
            if (CompareTo(min, max) > 0)
                return null;

            // OR keeps all significant bits
            byte[] ip = Or(min1, min2);
            byte[] subnetmask = Or(subnetmask1, subnetmask2);
            return IpWithSubnetMask(ip, subnetmask);
        }

        /**
         * Returns the union of the excluded IP ranges in <code>excluded</code>
         * with <code>ip</code>.
         *
         * @param excluded A <code>Set</code> of excluded IP addresses with their
         *                 subnet mask as byte arrays.
         * @param ip       The IP address with its subnet mask.
         * @return The <code>Set</code> of excluded IP ranges unified with
         *         <code>ip</code> as byte arrays.
         */
        private static HashSet<byte[]> UnionIP(HashSet<byte[]> excluded, byte[] ip)
        {
            if (excluded.Count < 1)
            {
                if (ip != null)
                {
                    excluded.Add(ip);
                }
                return excluded;
            }

            var union = new HashSet<byte[]>();
            foreach (byte[] _excluded in excluded)
            {
                union.UnionWith(UnionIPRange(_excluded, ip));
            }
            return union;
        }

        /**
         * Calculates the union if two IP ranges.
         *
         * @param ipWithSubmask1 The first IP address with its subnet mask.
         * @param ipWithSubmask2 The second IP address with its subnet mask.
         * @return A <code>Set</code> with the union of both addresses.
         */
        private static HashSet<byte[]> UnionIPRange(byte[] ipWithSubmask1, byte[] ipWithSubmask2)
        {
            var set = new HashSet<byte[]>();
            // difficult, adding always all IPs is not wrong
            if (Arrays.AreEqual(ipWithSubmask1, ipWithSubmask2))
            {
                set.Add(ipWithSubmask1);
            }
            else
            {
                set.Add(ipWithSubmask1);
                set.Add(ipWithSubmask2);
            }
            return set;
        }

        /**
         * Concatenates the IP address with its subnet mask.
         *
         * @param ip         The IP address.
         * @param subnetMask Its subnet mask.
         * @return The concatenated IP address with its subnet mask.
         */
        private static byte[] IpWithSubnetMask(byte[] ip, byte[] subnetMask) => Arrays.Concatenate(ip, subnetMask);

        /**
         * Splits the IP addresses and their subnet mask.
         *
         * @param ipWithSubmask1 The first IP address with the subnet mask.
         * @param ipWithSubmask2 The second IP address with the subnet mask.
         * @return An array with two elements. Each element contains the IP address
         *         and the subnet mask in this order.
         */
        private static byte[][] ExtractIPsAndSubnetMasks(byte[] ipWithSubmask1, byte[] ipWithSubmask2)
        {
            int ipLength = ipWithSubmask1.Length / 2;
            byte[] ip1 = new byte[ipLength];
            byte[] subnetmask1 = new byte[ipLength];
            Array.Copy(ipWithSubmask1, 0, ip1, 0, ipLength);
            Array.Copy(ipWithSubmask1, ipLength, subnetmask1, 0, ipLength);

            byte[] ip2 = new byte[ipLength];
            byte[] subnetmask2 = new byte[ipLength];
            Array.Copy(ipWithSubmask2, 0, ip2, 0, ipLength);
            Array.Copy(ipWithSubmask2, ipLength, subnetmask2, 0, ipLength);
            return new byte[][] { ip1, subnetmask1, ip2, subnetmask2 };
        }

        /**
         * Based on the two IP addresses and their subnet masks the IP range is
         * computed for each IP address - subnet mask pair and returned as the
         * minimum IP address and the maximum address of the range.
         *
         * @param ip1         The first IP address.
         * @param subnetmask1 The subnet mask of the first IP address.
         * @param ip2         The second IP address.
         * @param subnetmask2 The subnet mask of the second IP address.
         * @return A array with two elements. The first/second element contains the
         *         min and max IP address of the first/second IP address and its
         *         subnet mask.
         */
        private static byte[][] MinMaxIPs(byte[] ip1, byte[] subnetmask1, byte[] ip2, byte[] subnetmask2)
        {
            int ipLength = ip1.Length;
            byte[] min1 = new byte[ipLength];
            byte[] max1 = new byte[ipLength];

            byte[] min2 = new byte[ipLength];
            byte[] max2 = new byte[ipLength];

            for (int i = 0; i < ipLength; i++)
            {
                min1[i] = (byte)(ip1[i] & subnetmask1[i]);
                max1[i] = (byte)(ip1[i] & subnetmask1[i] | ~subnetmask1[i]);

                min2[i] = (byte)(ip2[i] & subnetmask2[i]);
                max2[i] = (byte)(ip2[i] & subnetmask2[i] | ~subnetmask2[i]);
            }

            return new byte[][] { min1, max1, min2, max2 };
        }

        /**
         * Returns the maximum IP address.
         *
         * @param ip1 The first IP address.
         * @param ip2 The second IP address.
         * @return The maximum IP address.
         */
        private static byte[] Max(byte[] ip1, byte[] ip2) => CompareTo(ip1, ip2) > 0 ? ip1 : ip2;

        /**
         * Returns the minimum IP address.
         *
         * @param ip1 The first IP address.
         * @param ip2 The second IP address.
         * @return The minimum IP address.
         */
        private static byte[] Min(byte[] ip1, byte[] ip2) => CompareTo(ip1, ip2) < 0 ? ip1 : ip2;

        /**
         * Compares IP address <code>ip1</code> with <code>ip2</code>. If ip1
         * is equal to ip2 0 is returned. If ip1 is bigger 1 is returned, -1
         * otherwise.
         *
         * @param ip1 The first IP address.
         * @param ip2 The second IP address.
         * @return 0 if ip1 is equal to ip2, 1 if ip1 is bigger, -1 otherwise.
         */
        private static int CompareTo(byte[] ip1, byte[] ip2)
        {
            for (int i = 0; i < ip1.Length; i++)
            {
                int t1 = ip1[i], t2 = ip2[i];
                if (t1 < t2)
                    return -1;
                if (t1 > t2)
                    return 1;
            }
            return 0;
        }

        /**
         * Returns the logical OR of the IP addresses <code>ip1</code> and
         * <code>ip2</code>.
         *
         * @param ip1 The first IP address.
         * @param ip2 The second IP address.
         * @return The OR of <code>ip1</code> and <code>ip2</code>.
         */
        private static byte[] Or(byte[] ip1, byte[] ip2)
        {
            byte[] temp = new byte[ip1.Length];
            for (int i = 0; i < ip1.Length; i++)
            {
                temp[i] = (byte)(ip1[i] | ip2[i]);
            }
            return temp;
        }

        #endregion

        #region Dns

        private static void CheckExcludedDns(HashSet<string> excluded, string dns)
        {
            if (IsDnsConstrained(excluded, dns))
                throw new PkixNameConstraintValidatorException("DNS is from an excluded subtree.");
        }

        private static void CheckPermittedDns(HashSet<string> permitted, string dns)
        {
            if (permitted != null
                && !(dns.Length == 0 && permitted.Count < 1)
                && !IsDnsConstrained(permitted, dns))
            {
                throw new PkixNameConstraintValidatorException("DNS is not from a permitted subtree.");
            }
        }

        private static bool IsDnsConstrained(HashSet<string> constraints, string dns)
        {
            foreach (var constraint in constraints)
            {
                if (IsDnsConstrained(constraint, dns))
                    return true;
            }

            return false;
        }

        private static bool IsDnsConstrained(string constraint, string dns)
        {
            // RFC 1034 sec. 3.1 allows a trailing dot to denote the root label of a fully-qualified domain name. A
            // dNSName SAN such as "foo.example.com." (legal IA5String per RFC 5280 sec. 4.2.1.6) used to escape
            // Name-Constraint matching because WithinDomain split it to ["foo", "example", "com", ""], misaligning the
            // per-label compare against a "example.com" constraint and returning "not constrained" — bypassing the
            // excluded subtree.  Normalise away at most one trailing dot on both sides before comparing.
            dns = StripTrailingDot(dns);
            constraint = StripTrailingDot(constraint);

            return Platform.EqualsIgnoreCase(dns, constraint) || WithinDomain(dns, constraint);
        }

        private static HashSet<string> IntersectDns(HashSet<string> permitted, HashSet<GeneralSubtree> dnss)
        {
            var intersect = new HashSet<string>();
            foreach (GeneralSubtree subtree in dnss)
            {
                string dns = ExtractNameAsString(subtree);

                if (permitted == null)
                {
                    intersect.Add(dns);
                }
                else
                {
                    foreach (string _permitted in permitted)
                    {
                        if (IsDnsConstrained(dns, _permitted))
                        {
                            intersect.Add(_permitted);
                        }
                        else if (WithinDomain(dns, _permitted))
                        {
                            intersect.Add(dns);
                        }
                        else
                        {
                            // No intersection
                        }
                    }
                }
            }
            return intersect;
        }

        private static HashSet<string> UnionDns(HashSet<string> excluded, string dns)
        {
            if (excluded.Count < 1)
            {
                excluded.Add(dns);
                return excluded;
            }

            var union = new HashSet<string>();
            foreach (string _excluded in excluded)
            {
                if (IsDnsConstrained(dns, _excluded))
                {
                    union.Add(dns);
                }
                else if (WithinDomain(dns, _excluded))
                {
                    union.Add(_excluded);
                }
                else
                {
                    union.Add(_excluded);
                    union.Add(dns);
                }
            }
            return union;
        }

        #endregion

        #region Uri

        private static void CheckExcludedUri(HashSet<string> excluded, string uri)
        {
            if (IsUriConstrained(excluded, uri))
                throw new PkixNameConstraintValidatorException("URI is from an excluded subtree.");
        }

        private static void CheckPermittedUri(HashSet<string> permitted, string uri)
        {
            if (permitted != null
                && !(uri.Length == 0 && permitted.Count < 1)
                && !IsUriConstrained(permitted, uri))
            {
                throw new PkixNameConstraintValidatorException("URI is not from a permitted subtree.");
            }
        }

        private static bool IsUriConstrained(HashSet<string> constraints, string uri)
        {
            foreach (string constraint in constraints)
            {
                if (IsUriConstrained(constraint, uri))
                    return true;
            }

            return false;
        }

        private static bool IsUriConstrained(string constraint, string uri)
        {
            // Strip an RFC 1034 root-label trailing dot from the host, matching the dNSName path, so a
            // URI host such as "competitor.example." cannot slip past a "competitor.example" constraint.
            string host = StripTrailingDot(ExtractHostFromURL(uri));

            // in sub domain or domain
            if (Platform.StartsWith(constraint, "."))
                return WithinDomain(host, constraint);

            // a host
            return Platform.EqualsIgnoreCase(host, StripTrailingDot(constraint));
        }

        private static HashSet<string> IntersectUri(HashSet<string> permitted, HashSet<GeneralSubtree> uris)
        {
            var intersect = new HashSet<string>();
            foreach (GeneralSubtree subtree in uris)
            {
                string uri = ExtractNameAsString(subtree);

                if (permitted == null)
                {
                    intersect.Add(uri);
                }
                else
                {
                    foreach (string _permitted in permitted)
                    {
                        IntersectUri(_permitted, uri, intersect);
                    }
                }
            }
            return intersect;
        }

        private static void IntersectUri(string email1, string email2, HashSet<string> intersect)
        {
            int email1AtPos = email1.IndexOf('@');
            int email2AtPos = email2.IndexOf('@');

            // email1 is a particular address
            if (email1AtPos != -1)
            {
                string _sub = email1.Substring(email1AtPos + 1);
                // both are a particular mailbox
                if (email2AtPos != -1)
                {
                    if (Platform.EqualsIgnoreCase(email1, email2))
                    {
                        intersect.Add(email1);
                    }
                }
                // email2 specifies a domain
                else if (Platform.StartsWith(email2, "."))
                {
                    if (WithinDomain(_sub, email2))
                    {
                        intersect.Add(email1);
                    }
                }
                // email2 specifies a particular host
                else
                {
                    if (Platform.EqualsIgnoreCase(_sub, email2))
                    {
                        intersect.Add(email1);
                    }
                }
            }
            // email specifies a domain
            else if (Platform.StartsWith(email1, "."))
            {
                if (email2AtPos != -1)
                {
                    string _sub = email2.Substring(email2AtPos + 1);
                    if (WithinDomain(_sub, email1))
                    {
                        intersect.Add(email2);
                    }
                }
                // email2 specifies a domain
                else if (Platform.StartsWith(email2, "."))
                {
                    if (IsDnsConstrained(email2, email1))
                    {
                        intersect.Add(email1);
                    }
                    else if (WithinDomain(email2, email1))
                    {
                        intersect.Add(email2);
                    }
                    else
                    {
                        // No intersection
                    }
                }
                else
                {
                    if (WithinDomain(email2, email1))
                    {
                        intersect.Add(email2);
                    }
                }
            }
            // email1 specifies a host
            else
            {
                if (email2AtPos != -1)
                {
                    string _sub = email2.Substring(email2AtPos + 1);
                    if (Platform.EqualsIgnoreCase(_sub, email1))
                    {
                        intersect.Add(email2);
                    }
                }
                // email2 specifies a domain
                else if (Platform.StartsWith(email2, "."))
                {
                    if (WithinDomain(email1, email2))
                    {
                        intersect.Add(email1);
                    }
                }
                // email2 specifies a particular host
                else
                {
                    if (Platform.EqualsIgnoreCase(email1, email2))
                    {
                        intersect.Add(email1);
                    }
                }
            }
        }

        private static HashSet<string> UnionUri(HashSet<string> excluded, string uri)
        {
            if (excluded.Count < 1)
            {
                excluded.Add(uri);
                return excluded;
            }

            var union = new HashSet<string>();
            foreach (string _excluded in excluded)
            {
                UnionUri(_excluded, uri, union);
            }
            return union;
        }

        private static void UnionUri(string email1, string email2, HashSet<string> union)
        {
            int email1AtPos = email1.IndexOf('@');
            int email2AtPos = email2.IndexOf('@');

            // email1 is a particular address
            if (email1AtPos != -1)
            {
                string _sub = email1.Substring(email1AtPos + 1);
                // both are a particular mailbox
                if (email2AtPos != -1)
                {
                    if (Platform.EqualsIgnoreCase(email1, email2))
                    {
                        union.Add(email1);
                    }
                    else
                    {
                        union.Add(email1);
                        union.Add(email2);
                    }
                }
                // email2 specifies a domain
                else if (Platform.StartsWith(email2, "."))
                {
                    if (WithinDomain(_sub, email2))
                    {
                        union.Add(email2);
                    }
                    else
                    {
                        union.Add(email1);
                        union.Add(email2);
                    }
                }
                // email2 specifies a particular host
                else
                {
                    if (Platform.EqualsIgnoreCase(_sub, email2))
                    {
                        union.Add(email2);
                    }
                    else
                    {
                        union.Add(email1);
                        union.Add(email2);

                    }
                }
            }
            // email1 specifies a domain
            else if (Platform.StartsWith(email1, "."))
            {
                if (email2AtPos != -1)
                {
                    string _sub = email2.Substring(email2AtPos + 1);
                    if (WithinDomain(_sub, email1))
                    {
                        union.Add(email1);
                    }
                    else
                    {
                        union.Add(email1);
                        union.Add(email2);
                    }
                }
                // email2 specifies a domain
                else if (Platform.StartsWith(email2, "."))
                {
                    if (IsDnsConstrained(email2, email1))
                    {
                        union.Add(email2);
                    }
                    else if (WithinDomain(email2, email1))
                    {
                        union.Add(email1);
                    }
                    else
                    {
                        union.Add(email1);
                        union.Add(email2);
                    }
                }
                else
                {
                    if (WithinDomain(email2, email1))
                    {
                        union.Add(email1);
                    }
                    else
                    {
                        union.Add(email1);
                        union.Add(email2);
                    }
                }
            }
            // email specifies a host
            else
            {
                if (email2AtPos != -1)
                {
                    string _sub = email2.Substring(email2AtPos + 1);
                    if (Platform.EqualsIgnoreCase(_sub, email1))
                    {
                        union.Add(email1);
                    }
                    else
                    {
                        union.Add(email1);
                        union.Add(email2);
                    }
                }
                // email2 specifies a domain
                else if (Platform.StartsWith(email2, "."))
                {
                    if (WithinDomain(email1, email2))
                    {
                        union.Add(email2);
                    }
                    else
                    {
                        union.Add(email1);
                        union.Add(email2);
                    }
                }
                // email2 specifies a particular host
                else
                {
                    if (Platform.EqualsIgnoreCase(email1, email2))
                    {
                        union.Add(email1);
                    }
                    else
                    {
                        union.Add(email1);
                        union.Add(email2);
                    }
                }
            }
        }

        private static string ExtractHostFromURL(string url)
        {
            // RFC 3986 §3.2 authority structure:
            //   authority = [ userinfo "@" ] host [ ":" port ]
            // The strip order is: scheme → "//" → path/query/fragment terminator → userinfo (last '@') → host
            // with optional bracketed IPv6 / trailing ":port".
            string sub = url;
            int schemeEnd = sub.IndexOf(':');
            if (schemeEnd >= 0)
            {
                sub = sub.Substring(schemeEnd + 1);
            }
            if (Platform.StartsWith(sub, "//"))
            {
                sub = sub.Substring(2);
            }
            for (int i = 0; i < sub.Length; ++i)
            {
                char c = sub[i];
                if (c == '/' || c == '?' || c == '#')
                {
                    sub = sub.Substring(0, i);
                    break;
                }
            }
            int atPos = sub.LastIndexOf('@');
            if (atPos >= 0)
            {
                sub = sub.Substring(atPos + 1);
            }
            if (Platform.StartsWith(sub, "["))
            {
                int closeBracket = sub.IndexOf(']');
                if (closeBracket > 0)
                {
                    return sub.Substring(1, closeBracket - 1);
                }
                return sub.Substring(1);
            }
            int portColon = sub.LastIndexOf(':');
            if (portColon >= 0)
            {
                sub = sub.Substring(0, portColon);
            }
            return sub;
        }

        #endregion

        private static bool WithinDomain(string testDomain, string domain)
        {
            if (Platform.StartsWith(domain, "."))
            {
                domain = domain.Substring(1);
            }

            // Strip the RFC 1034 root-label trailing dot so the per-label
            // compare doesn't see a phantom empty label.
            testDomain = StripTrailingDot(testDomain);
            domain = StripTrailingDot(domain);

            string[] domainParts = Strings.Split(domain, '.');
            string[] testDomainParts = Strings.Split(testDomain, '.');

            // must have at least one subdomain
            if (testDomainParts.Length <= domainParts.Length)
                return false;

            int d = testDomainParts.Length - domainParts.Length;
            if (testDomainParts[d - 1].Length < 1)
                return false;

            for (int i = 0; i < domainParts.Length; i++)
            {
                if (!Platform.EqualsIgnoreCase(domainParts[i], testDomainParts[d + i]))
                    return false;
            }
            return true;
        }

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
                CheckPermittedEmail(ExtractNameAsString(nameValue));
                break;
            case GeneralName.DnsName:
                CheckPermittedDns(permittedSubtreesDns, ExtractNameAsString(nameValue));
                break;
            case GeneralName.DirectoryName:
                CheckPermittedDN(Asn1Sequence.GetInstance(nameValue));
                break;
            case GeneralName.UniformResourceIdentifier:
                CheckPermittedUri(permittedSubtreesUri, ExtractNameAsString(nameValue));
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
                CheckExcludedEmail(ExtractNameAsString(nameValue));
                break;
            case GeneralName.DnsName:
                CheckExcludedDns(excludedSubtreesDns, ExtractNameAsString(nameValue));
                break;
            case GeneralName.DirectoryName:
                CheckExcludedDN(Asn1Sequence.GetInstance(nameValue));
                break;
            case GeneralName.UniformResourceIdentifier:
                CheckExcludedUri(excludedSubtreesUri, ExtractNameAsString(nameValue));
                break;
            case GeneralName.IPAddress:
                CheckExcludedIP(excludedSubtreesIP, Asn1OctetString.GetInstance(nameValue).GetOctets());
                break;
                // Other tags ignored
            }
        }

        public void IntersectPermittedSubtree(GeneralSubtree permitted) =>
            IntersectPermittedSubtree(permitted.Base.TagNo, new HashSet<GeneralSubtree>() { permitted });

        /**
         * Updates the permitted ISet of these name constraints with the intersection
         * with the given subtree.
         *
         * @param permitted The permitted subtrees
         */
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
                permittedSubtreesEmail = IntersectEmail(permittedSubtreesEmail, subtrees);
                break;
            case GeneralName.DnsName:
                permittedSubtreesDns = IntersectDns(permittedSubtreesDns, subtrees);
                break;
            case GeneralName.DirectoryName:
                permittedSubtreesDN = IntersectDN(permittedSubtreesDN, subtrees);
                break;
            case GeneralName.UniformResourceIdentifier:
                permittedSubtreesUri = IntersectUri(permittedSubtreesUri, subtrees);
                break;
            case GeneralName.IPAddress:
                permittedSubtreesIP = IntersectIP(permittedSubtreesIP, subtrees);
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
                permittedSubtreesEmail = new HashSet<string>();
                break;
            case GeneralName.DnsName:
                permittedSubtreesDns = new HashSet<string>();
                break;
            case GeneralName.DirectoryName:
                permittedSubtreesDN = new HashSet<Asn1Sequence>();
                break;
            case GeneralName.UniformResourceIdentifier:
                permittedSubtreesUri = new HashSet<string>();
                break;
            case GeneralName.IPAddress:
                permittedSubtreesIP = new HashSet<byte[]>();
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
                excludedSubtreesEmail = UnionEmail(excludedSubtreesEmail, ExtractNameAsString(nameValue));
                break;
            case GeneralName.DnsName:
                excludedSubtreesDns = UnionDns(excludedSubtreesDns, ExtractNameAsString(nameValue));
                break;
            case GeneralName.DirectoryName:
                excludedSubtreesDN = UnionDN(excludedSubtreesDN, Asn1Sequence.GetInstance(nameValue));
                break;
            case GeneralName.UniformResourceIdentifier:
                excludedSubtreesUri = UnionUri(excludedSubtreesUri, ExtractNameAsString(nameValue));
                break;
            case GeneralName.IPAddress:
                excludedSubtreesIP = UnionIP(excludedSubtreesIP, Asn1OctetString.GetInstance(nameValue).GetOctets());
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

        private static int HashCollection(HashSet<byte[]> c)
        {
            int hash = 0;
            if (c != null)
            {
                foreach (byte[] o in c)
                {
                    hash += Arrays.GetHashCode(o);
                }
            }
            return hash;
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

        private static bool AreEqualSets(HashSet<byte[]> set1, HashSet<byte[]> set2)
        {
            if (set1 == set2)
                return true;
            if (set1 == null || set2 == null || set1.Count != set2.Count)
                return false;

            foreach (byte[] a in set1)
            {
                if (!Contains(set2, a))
                    return false;
            }
            return true;
        }

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

        /**
         * Stringifies an IPv4 or v6 address with subnet mask.
         *
         * @param ip The IP with subnet mask.
         * @return The stringified IP address.
         */
        private static string StringifyIP(byte[] ip)
        {
            string temp = "";
            for (int i = 0; i < ip.Length / 2; i++)
            {
                temp += (ip[i] & 0x00FF) + ".";
            }
            temp = temp.Substring(0, temp.Length - 1);
            temp += "/";
            for (int i = ip.Length / 2; i < ip.Length; i++)
            {
                temp += (ip[i] & 0x00FF) + ".";
            }
            temp = temp.Substring(0, temp.Length - 1);
            return temp;
        }

        private static string StringifyIPCollection(HashSet<byte[]> ips)
        {
            string temp = "";
            temp += "[";
            foreach (byte[] ip in ips)
            {
                temp += StringifyIP(ip) + ",";
            }
            if (temp.Length > 1)
            {
                temp = temp.Substring(0, temp.Length - 1);
            }
            temp += "]";
            return temp;
        }

        private static string StringifyOtherNameCollection(HashSet<OtherName> otherNames)
        {
            StringBuilder sb = new StringBuilder('[');
            foreach (OtherName otherName in otherNames)
            {
                if (sb.Length > 1)
                {
                    sb.Append(',');
                }
                sb.Append(otherName.TypeID.Id);
                sb.Append(':');
                sb.Append(Hex.ToHexString(otherName.Value.GetEncoded()));
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
                Append(sb, "DN", permittedSubtreesDN);
            }
            if (permittedSubtreesDns != null)
            {
                Append(sb, "DNS", permittedSubtreesDns);
            }
            if (permittedSubtreesEmail != null)
            {
                Append(sb, "Email", permittedSubtreesEmail);
            }
            if (permittedSubtreesUri != null)
            {
                Append(sb, "URI", permittedSubtreesUri);
            }
            if (permittedSubtreesIP != null)
            {
                Append(sb, "IP", StringifyIPCollection(permittedSubtreesIP));
            }
            if (permittedSubtreesOtherName != null)
            {
                Append(sb, "OtherName", StringifyOtherNameCollection(permittedSubtreesOtherName));
            }
            sb.AppendLine("excluded:");
            if (excludedSubtreesDN.Count > 0)
            {
                Append(sb, "DN", excludedSubtreesDN);
            }
            if (excludedSubtreesDns.Count > 0)
            {
                Append(sb, "DNS", excludedSubtreesDns);
            }
            if (excludedSubtreesEmail.Count > 0)
            {
                Append(sb, "Email", excludedSubtreesEmail);
            }
            if (excludedSubtreesUri.Count > 0)
            {
                Append(sb, "URI", excludedSubtreesUri);
            }
            if (excludedSubtreesIP.Count > 0)
            {
                Append(sb, "IP", StringifyIPCollection(excludedSubtreesIP));
            }
            if (excludedSubtreesOtherName.Count > 0)
            {
                Append(sb, "OtherName", StringifyOtherNameCollection(excludedSubtreesOtherName));
            }
            return sb.ToString();
        }

        private static void Append(StringBuilder sb, string name, object value)
        {
            sb.Append(name);
            sb.AppendLine(":");
            sb.Append(value);
            sb.AppendLine();
        }

        private static bool Contains(HashSet<byte[]> set, byte[] search)
        {
            foreach (byte[] entry in set)
            {
                if (Arrays.AreEqual(search, entry))
                    return true;
            }
            return false;
        }

        private static string ExtractNameAsString(GeneralSubtree subtree) => ExtractNameAsString(subtree.Base.Name);

        private static string ExtractNameAsString(Asn1Encodable nameValue) =>
            DerIA5String.GetInstance(nameValue).GetString();
    }
}
