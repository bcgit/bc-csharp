using System;
using System.Collections.Generic;
using System.Text;

using Org.BouncyCastle.Asn1;
using Org.BouncyCastle.Asn1.X500;
using Org.BouncyCastle.Asn1.X500.Style;
using Org.BouncyCastle.Asn1.X509;
using Org.BouncyCastle.Utilities;
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
            if (subtree.Count < 1 || subtree.Count > dns.Count)
                return false;

            int start = 0;
            Rdn subtreeRdnStart = Rdn.GetInstance(subtree[0]);
            for (int j = 0; j < dns.Count; j++)
            {
                start = j;
                Rdn dnsRdn = Rdn.GetInstance(dns[j]);
                if (IetfUtilities.RdnAreEqual(subtreeRdnStart, dnsRdn))
                    break;
            }

            if (subtree.Count > dns.Count - start)
                return false;

            for (int j = 0; j < subtree.Count; ++j)
            {
                // both subtree and dns are a ASN.1 Name and the elements are a RDN
                Rdn subtreeRdn = Rdn.GetInstance(subtree[j]);
                Rdn dnsRdn = Rdn.GetInstance(dns[start + j]);

                // check if types and values of all naming attributes are matching, other types which are not restricted are allowed, see https://tools.ietf.org/html/rfc5280#section-7.1

                // Two relative distinguished names
                //   RDN1 and RDN2 match if they have the same number of naming attributes
                //   and for each naming attribute in RDN1 there is a matching naming attribute in RDN2.
                //   NOTE: this is checking the attributes in the same order, which might be not necessary, if this is a problem also IetfUtilities.RdnAreEqual must be changed.
                // use new RFC 5280 comparison, NOTE: this is now different from with RFC 3280, where only binary comparison is used
                // obey RFC 5280 7.1
                // special treatment of serialNumber for GSMA SGP.22 RSP specification
                if (subtreeRdn.Count == 1 && dnsRdn.Count == 1
                    && SerialNumberOid.Equals(subtreeRdn.GetFirst().Type)
                    && SerialNumberOid.Equals(dnsRdn.GetFirst().Type))
                {
                    if (!Platform.StartsWith(dnsRdn.GetFirst().Value.ToString(), subtreeRdn.GetFirst().Value.ToString()))
                        return false;
                }
                else if (!IetfUtilities.RdnAreEqual(subtreeRdn, dnsRdn))
                {
                    return false;
                }
            }

            return true;
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

            // a particular mailbox
            if (atPos > 0)
                return Platform.EqualsIgnoreCase(email, constraint);

            string sub = email.Substring(email.IndexOf('@') + 1);

            // "@domain" style
            if (atPos == 0)
                return Platform.EqualsIgnoreCase(sub, constraint.Substring(1));

            // address in sub domain
            if (Platform.StartsWith(constraint, "."))
                return WithinDomain(sub, constraint);

            // on particular host
            return Platform.EqualsIgnoreCase(sub, constraint);
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

        private static bool IsDnsConstrained(string constraint, string dns) =>
            Platform.EqualsIgnoreCase(dns, constraint) || WithinDomain(dns, constraint);

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
            string host = ExtractHostFromURL(uri);

            // in sub domain or domain
            if (Platform.StartsWith(constraint, "."))
                return WithinDomain(host, constraint);

            // a host
            return Platform.EqualsIgnoreCase(host, constraint);
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
            // see RFC 1738
            // remove ':' after protocol, e.g. http:
            string sub = url.Substring(url.IndexOf(':') + 1);
            // extract host from Common Internet Scheme Syntax, e.g. http://
            int slashesPos = sub.IndexOf("//");
            if (slashesPos != -1)
            {
                sub = sub.Substring(slashesPos + 2);
            }
            // first remove port, e.g. http://test.com:21
            int portColonPos = sub.LastIndexOf(':');
            if (portColonPos != -1)
            {
                sub = sub.Substring(0, portColonPos);
            }
            // remove user and password, e.g. http://john:password@test.com
            sub = sub.Substring(sub.IndexOf(':') + 1);
            sub = sub.Substring(sub.IndexOf('@') + 1);
            // remove local parts, e.g. http://test.com/bla
            int slashPos = sub.IndexOf('/');
            if (slashPos != -1)
            {
                sub = sub.Substring(0, slashPos);
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

        /**
         * Updates the permitted ISet of these name constraints with the intersection
         * with the given subtree.
         *
         * @param permitted The permitted subtrees
         */
        public void IntersectPermittedSubtree(Asn1Sequence permitted)
        {
            var subtreesMap = new Dictionary<int, HashSet<GeneralSubtree>>();

            // group in ISets in a map ordered by tag no.
            foreach (var element in permitted)
            {
                GeneralSubtree subtree = GeneralSubtree.GetInstance(element);

                int tagNo = subtree.Base.TagNo;

                HashSet<GeneralSubtree> subtrees;
                if (!subtreesMap.TryGetValue(tagNo, out subtrees))
                {
                    subtrees = new HashSet<GeneralSubtree>();
                    subtreesMap[tagNo] = subtrees;
                }

                subtrees.Add(subtree);
            }

            foreach (var entry in subtreesMap)
            {
                // go through all subtree groups
                int nameType = entry.Key;
                var subtrees = entry.Value;

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
