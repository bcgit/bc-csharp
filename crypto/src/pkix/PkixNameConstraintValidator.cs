using System;
using System.Collections;
using System.IO;

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
        // TODO Implement X500Name and styles
        //private static readonly DerObjectIdentifier SerialNumberOid = Rfc4519Style.SerialNumber;
        private static readonly DerObjectIdentifier SerialNumberOid = new DerObjectIdentifier("2.5.4.5");

        private ISet excludedSubtreesDN = new HashSet();

        private ISet excludedSubtreesDNS = new HashSet();

        private ISet excludedSubtreesEmail = new HashSet();

        private ISet excludedSubtreesURI = new HashSet();

        private ISet excludedSubtreesIP = new HashSet();

        private ISet excludedSubtreesOtherName = new HashSet();

        private ISet permittedSubtreesDN;

        private ISet permittedSubtreesDNS;

        private ISet permittedSubtreesEmail;

        private ISet permittedSubtreesURI;

        private ISet permittedSubtreesIP;

        private ISet permittedSubtreesOtherName;

        public PkixNameConstraintValidator()
        {
        }

        private static bool WithinDNSubtree(
            Asn1Sequence dns,
            Asn1Sequence subtree)
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
                //   NOTE: this is checking the attributes in the same order, which might be not necessary, if this is a problem also IETFUtils.rDNAreEqual mus tbe changed.
                // use new RFC 5280 comparison, NOTE: this is now different from with RFC 3280, where only binary comparison is used
                // obey RFC 5280 7.1
                // special treatment of serialNumber for GSMA SGP.22 RSP specification
                if (subtreeRdn.Count == 1 && dnsRdn.Count == 1
                    && subtreeRdn.GetFirst().GetType().Equals(SerialNumberOid)
                    && dnsRdn.GetFirst().GetType().Equals(SerialNumberOid))
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

        public void CheckPermittedDN(Asn1Sequence dn)
        {
            CheckPermittedDirectory(permittedSubtreesDN, dn);
        }

        public void CheckExcludedDN(Asn1Sequence dn)
        {
            CheckExcludedDirectory(excludedSubtreesDN, dn);
        }

        private ISet IntersectDN(ISet permitted, ISet dns)
        {
            ISet intersect = new HashSet();
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
                    foreach (object obj2 in permitted)
                    {
                        Asn1Sequence dn2 = Asn1Sequence.GetInstance(obj2);

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

        private ISet UnionDN(ISet excluded, Asn1Sequence dn)
        {
            if (excluded.IsEmpty)
            {
                if (dn == null)
                    return excluded;

                excluded.Add(dn);
                return excluded;
            }
            else
            {
                ISet union = new HashSet();

                foreach (object obj in excluded)
                {
                    Asn1Sequence subtree = Asn1Sequence.GetInstance(obj);

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
        }

        private ISet IntersectOtherName(ISet permitted, ISet otherNames)
        {
            ISet intersect = new HashSet();
            foreach (GeneralSubtree subtree1 in otherNames)
            {
                OtherName otherName1 = OtherName.GetInstance(subtree1.Base.Name);
                if (otherName1 == null)
                    continue;

                if (permitted == null)
                {
                    intersect.Add(otherName1);
                }
                else
                {
                    foreach (object obj2 in permitted)
                    {
                        OtherName otherName2 = OtherName.GetInstance(obj2);
                        if (otherName2 == null)
                            continue;

                        IntersectOtherName(otherName1, otherName2, intersect);
                    }
                }
            }
            return intersect;
        }

        private void IntersectOtherName(OtherName otherName1, OtherName otherName2, ISet intersect)
        {
            if (otherName1.Equals(otherName2))
            {
                intersect.Add(otherName1);
            }
        }

        private ISet UnionOtherName(ISet permitted, OtherName otherName)
        {
            ISet union = permitted != null ? new HashSet(permitted) : new HashSet();
            union.Add(otherName);
            return union;
        }

        private ISet IntersectEmail(ISet permitted, ISet emails)
        {
            ISet intersect = new HashSet();
            foreach (GeneralSubtree subtree1 in emails)
            {
                string email = ExtractNameAsString(subtree1.Base);

                if (permitted == null)
                {
                    if (email != null)
                    {
                        intersect.Add(email);
                    }
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

        private ISet UnionEmail(ISet excluded, string email)
        {
            if (excluded.IsEmpty)
            {
                if (email == null)
                {
                    return excluded;
                }
                excluded.Add(email);
                return excluded;
            }
            else
            {
                ISet union = new HashSet();
                foreach (string _excluded in excluded)
                {
                    UnionEmail(_excluded, email, union);
                }
                return union;
            }
        }

        /**
         * Returns the intersection of the permitted IP ranges in
         * <code>permitted</code> with <code>ip</code>.
         *
         * @param permitted A <code>Set</code> of permitted IP addresses with
         *                  their subnet mask as byte arrays.
         * @param ips       The IP address with its subnet mask.
         * @return The <code>Set</code> of permitted IP ranges intersected with
         *         <code>ip</code>.
         */
        private ISet IntersectIP(ISet permitted, ISet ips)
        {
            ISet intersect = new HashSet();
            foreach (GeneralSubtree subtree in ips)
            {
                byte[] ip = Asn1OctetString.GetInstance(subtree.Base.Name).GetOctets();
                if (permitted == null)
                {
                    if (ip != null)
                    {
                        intersect.Add(ip);
                    }
                }
                else
                {
                    foreach (byte[] _permitted in permitted)
                    {
                        intersect.AddAll(IntersectIPRange(_permitted, ip));
                    }
                }
            }
            return intersect;
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
        private ISet UnionIP(ISet excluded, byte[] ip)
        {
            if (excluded.IsEmpty)
            {
                if (ip == null)
                {
                    return excluded;
                }
                excluded.Add(ip);

                return excluded;
            }
            else
            {
                ISet union = new HashSet();
                foreach (byte[] _excluded in excluded)
                {
                    union.AddAll(UnionIPRange(_excluded, ip));
                }
                return union;
            }
        }

        /**
         * Calculates the union if two IP ranges.
         *
         * @param ipWithSubmask1 The first IP address with its subnet mask.
         * @param ipWithSubmask2 The second IP address with its subnet mask.
         * @return A <code>Set</code> with the union of both addresses.
         */
        private ISet UnionIPRange(byte[] ipWithSubmask1, byte[] ipWithSubmask2)
        {
            ISet set = new HashSet();
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
         * Calculates the interesction if two IP ranges.
         *
         * @param ipWithSubmask1 The first IP address with its subnet mask.
         * @param ipWithSubmask2 The second IP address with its subnet mask.
         * @return A <code>Set</code> with the single IP address with its subnet
         *         mask as a byte array or an empty <code>Set</code>.
         */
        private ISet IntersectIPRange(byte[] ipWithSubmask1, byte[] ipWithSubmask2)
        {
            if (ipWithSubmask1.Length != ipWithSubmask2.Length)
            {
                //Collections.EMPTY_SET;
                return new HashSet();
            }

            byte[][] temp = ExtractIPsAndSubnetMasks(ipWithSubmask1, ipWithSubmask2);
            byte[] ip1 = temp[0];
            byte[] subnetmask1 = temp[1];
            byte[] ip2 = temp[2];
            byte[] subnetmask2 = temp[3];

            byte[][] minMax = MinMaxIPs(ip1, subnetmask1, ip2, subnetmask2);
            byte[] min;
            byte[] max;
            max = Min(minMax[1], minMax[3]);
            min = Max(minMax[0], minMax[2]);

            // minimum IP address must be bigger than max
            if (CompareTo(min, max) == 1)
            {
                //return Collections.EMPTY_SET;
                return new HashSet();
            }
            // OR keeps all significant bits
            byte[] ip = Or(minMax[0], minMax[2]);
            byte[] subnetmask = Or(subnetmask1, subnetmask2);

                //return new HashSet( ICollectionsingleton(IpWithSubnetMask(ip, subnetmask));
            ISet hs = new HashSet();
            hs.Add(IpWithSubnetMask(ip, subnetmask));

            return hs;
        }

        /**
         * Concatenates the IP address with its subnet mask.
         *
         * @param ip         The IP address.
         * @param subnetMask Its subnet mask.
         * @return The concatenated IP address with its subnet mask.
         */
        private byte[] IpWithSubnetMask(byte[] ip, byte[] subnetMask)
        {
            int ipLength = ip.Length;
            byte[] temp = new byte[ipLength * 2];
            Array.Copy(ip, 0, temp, 0, ipLength);
            Array.Copy(subnetMask, 0, temp, ipLength, ipLength);
            return temp;
        }

        /**
         * Splits the IP addresses and their subnet mask.
         *
         * @param ipWithSubmask1 The first IP address with the subnet mask.
         * @param ipWithSubmask2 The second IP address with the subnet mask.
         * @return An array with two elements. Each element contains the IP address
         *         and the subnet mask in this order.
         */
        private byte[][] ExtractIPsAndSubnetMasks(
            byte[] ipWithSubmask1,
            byte[] ipWithSubmask2)
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
            return new byte[][]{ ip1, subnetmask1, ip2, subnetmask2 };
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
        private byte[][] MinMaxIPs(
            byte[] ip1,
            byte[] subnetmask1,
            byte[] ip2,
            byte[] subnetmask2)
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

            return new byte[][]{ min1, max1, min2, max2 };
        }

        private bool IsOtherNameConstrained(OtherName constraint, OtherName otherName)
        {
            return constraint.Equals(otherName);
        }

        private bool IsOtherNameConstrained(ISet constraints, OtherName otherName)
        {
            foreach (object obj in constraints)
            {
                OtherName constraint = OtherName.GetInstance(obj);

                if (IsOtherNameConstrained(constraint, otherName))
                    return true;
            }

            return false;
        }

        private void CheckPermittedOtherName(ISet permitted, OtherName name)
        {
            if (permitted != null && !IsOtherNameConstrained(permitted, name))
            {
                throw new PkixNameConstraintValidatorException(
                    "Subject OtherName is not from a permitted subtree.");
            }
        }

        private void CheckExcludedOtherName(ISet excluded, OtherName name)
        {
            if (IsOtherNameConstrained(excluded, name))
            {
                throw new PkixNameConstraintValidatorException(
                    "OtherName is from an excluded subtree.");
            }
        }

        private bool IsEmailConstrained(string constraint, string email)
        {
            string sub = email.Substring(email.IndexOf('@') + 1);
            // a particular mailbox
            if (constraint.IndexOf('@') != -1)
            {
                if (Platform.ToUpperInvariant(email).Equals(Platform.ToUpperInvariant(constraint)))
                {
                    return true;
                }
            }
            // on particular host
            else if (!(constraint[0].Equals('.')))
            {
                if (Platform.ToUpperInvariant(sub).Equals(Platform.ToUpperInvariant(constraint)))
                {
                    return true;
                }
            }
            // address in sub domain
            else if (WithinDomain(sub, constraint))
            {
                return true;
            }
            return false;
        }

        private bool IsEmailConstrained(ISet constraints, string email)
        {
            foreach (string constraint in constraints)
            {
                if (IsEmailConstrained(constraint, email))
                    return true;
            }

            return false;
        }

        private void CheckPermittedEmail(ISet permitted, string email)
        {
            if (permitted != null
                && !(email.Length == 0 && permitted.IsEmpty)
                && !IsEmailConstrained(permitted, email))
            {
                throw new PkixNameConstraintValidatorException(
                    "Subject email address is not from a permitted subtree.");
            }
        }

        private void CheckExcludedEmail(ISet excluded, string email)
        {
            if (IsEmailConstrained(excluded, email))
            {
                throw new PkixNameConstraintValidatorException(
                    "Email address is from an excluded subtree.");
            }
        }

        private bool IsDnsConstrained(string constraint, string dns)
        {
            return WithinDomain(dns, constraint) || Platform.EqualsIgnoreCase(dns, constraint);
        }

        private bool IsDnsConstrained(ISet constraints, string dns)
        {
            foreach (string constraint in constraints)
            {
                if (IsDnsConstrained(constraint, dns))
                    return true;
            }

            return false;
        }

        private void CheckPermittedDns(ISet permitted, string dns)
        {
            if (permitted != null
                && !(dns.Length == 0 && permitted.IsEmpty)
                && !IsDnsConstrained(permitted, dns))
            {
                throw new PkixNameConstraintValidatorException(
                    "DNS is not from a permitted subtree.");
            }
        }

        private void CheckExcludedDns(ISet excluded, string dns)
        {
            if (IsDnsConstrained(excluded, dns))
            {
                throw new PkixNameConstraintValidatorException(
                    "DNS is from an excluded subtree.");
            }
        }

        private bool IsDirectoryConstrained(ISet constraints, Asn1Sequence directory)
        {
            foreach (object obj in constraints)
            {
                Asn1Sequence constraint = Asn1Sequence.GetInstance(obj);

                if (WithinDNSubtree(directory, constraint))
                    return true;
            }

            return false;
        }

        private void CheckPermittedDirectory(ISet permitted, Asn1Sequence directory)
        {
            if (permitted != null
                && !(directory.Count == 0 && permitted.IsEmpty)
                && !IsDirectoryConstrained(permitted, directory))
            {
                throw new PkixNameConstraintValidatorException(
                    "Subject distinguished name is not from a permitted subtree");
            }
        }

        private void CheckExcludedDirectory(ISet excluded, Asn1Sequence directory)
        {
            if (IsDirectoryConstrained(excluded, directory))
            {
                throw new PkixNameConstraintValidatorException(
                    "Subject distinguished name is from an excluded subtree");
            }
        }

        private bool IsUriConstrained(string constraint, string uri)
        {
            string host = ExtractHostFromURL(uri);

            if (Platform.StartsWith(constraint, "."))
            {
                // in sub domain or domain
                return WithinDomain(host, constraint);
            }

            // a host
            return Platform.EqualsIgnoreCase(host, constraint);
        }

        private bool IsUriConstrained(ISet constraints, string uri)
        {
            foreach (string constraint in constraints)
            {
                if (IsUriConstrained(constraint, uri))
                    return true;
            }

            return false;
        }

        private void CheckPermittedUri(ISet permitted, string uri)
        {
            if (permitted != null
                && !(uri.Length == 0 && permitted.IsEmpty)
                && !IsUriConstrained(permitted, uri))
            {
                throw new PkixNameConstraintValidatorException(
                    "URI is not from a permitted subtree.");
            }
        }

        private void CheckExcludedUri(ISet excluded, string uri)
        {
            if (IsUriConstrained(excluded, uri))
            {
                throw new PkixNameConstraintValidatorException(
                    "URI is from an excluded subtree.");
            }
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
        private bool IsIPConstrained(byte[] constraint, byte[] ip)
        {
            int ipLength = ip.Length;
            if (ipLength != (constraint.Length / 2))
            {
                return false;
            }

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

        private bool IsIPConstrained(ISet constraints, byte[] ip)
        {
            foreach (byte[] constraint in constraints)
            {
                if (IsIPConstrained(constraint, ip))
                    return true;
            }

            return false;
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
        private void CheckPermittedIP(ISet permitted, byte[] ip)
        {
            if (permitted != null
                && !(ip.Length == 0 && permitted.IsEmpty)
                && !IsIPConstrained(permitted, ip))
            {
                throw new PkixNameConstraintValidatorException(
                    "IP is not from a permitted subtree.");
            }
        }

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
        private void CheckExcludedIP(ISet excluded, byte[] ip)
        {
            if (IsIPConstrained(excluded, ip))
            {
                throw new PkixNameConstraintValidatorException(
                    "IP is from an excluded subtree.");
            }
        }

        private bool WithinDomain(string testDomain, string domain)
        {
            string tempDomain = domain;
            if (Platform.StartsWith(tempDomain, "."))
            {
                tempDomain = tempDomain.Substring(1);
            }

            string[] domainParts = tempDomain.Split('.'); // Strings.split(tempDomain, '.');
            string[] testDomainParts = testDomain.Split('.'); // Strings.split(testDomain, '.');

            // must have at least one subdomain
            if (testDomainParts.Length <= domainParts.Length)
                return false;

            int d = testDomainParts.Length - domainParts.Length;
            for (int i = -1; i < domainParts.Length; i++)
            {
                if (i == -1)
                {
                    if (testDomainParts[i + d].Length < 1)
                    {
                        return false;
                    }
                }
                else if (!Platform.EqualsIgnoreCase(testDomainParts[i + d], domainParts[i]))
                {
                    return false;
                }
            }
            return true;
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
        private void UnionEmail(string email1, string email2, ISet union)
        {
            // email1 is a particular address
            if (email1.IndexOf('@') != -1)
            {
                string _sub = email1.Substring(email1.IndexOf('@') + 1);
                // both are a particular mailbox
                if (email2.IndexOf('@') != -1)
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
                if (email2.IndexOf('@') != -1)
                {
                    string _sub = email2.Substring(email1.IndexOf('@') + 1);
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
                    if (WithinDomain(email1, email2) || Platform.EqualsIgnoreCase(email1, email2))
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
                if (email2.IndexOf('@') != -1)
                {
                    string _sub = email2.Substring(email1.IndexOf('@') + 1);
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

        private void unionURI(string email1, string email2, ISet union)
        {
            // email1 is a particular address
            if (email1.IndexOf('@') != -1)
            {
                string _sub = email1.Substring(email1.IndexOf('@') + 1);
                // both are a particular mailbox
                if (email2.IndexOf('@') != -1)
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
                if (email2.IndexOf('@') != -1)
                {
                    string _sub = email2.Substring(email1.IndexOf('@') + 1);
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
                    if (WithinDomain(email1, email2) || Platform.EqualsIgnoreCase(email1, email2))
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
                if (email2.IndexOf('@') != -1)
                {
                    string _sub = email2.Substring(email1.IndexOf('@') + 1);
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

        private ISet IntersectDns(ISet permitted, ISet dnss)
        {
            ISet intersect = new HashSet();
            foreach (GeneralSubtree subtree in dnss)
            {
                string dns = ExtractNameAsString(subtree.Base);
                if (permitted == null)
                {
                    if (dns != null)
                    {
                        intersect.Add(dns);
                    }
                }
                else
                {
                    foreach (string _permitted in permitted)
                    {
                        if (WithinDomain(_permitted, dns))
                        {
                            intersect.Add(_permitted);
                        }
                        else if (WithinDomain(dns, _permitted))
                        {
                            intersect.Add(dns);
                        }
                    }
                }
            }

            return intersect;
        }

        private ISet UnionDns(ISet excluded, string dns)
        {
            if (excluded.IsEmpty)
            {
                if (dns == null)
                    return excluded;

                excluded.Add(dns);
                return excluded;
            }
            else
            {
                ISet union = new HashSet();
                foreach (string _excluded in excluded)
                {
                    if (WithinDomain(_excluded, dns))
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
        }

        /**
         * The most restricting part from <code>email1</code> and
         * <code>email2</code> is added to the intersection <code>intersect</code>.
         *
         * @param email1    Email address constraint 1.
         * @param email2    Email address constraint 2.
         * @param intersect The intersection.
         */
        private void IntersectEmail(string email1, string email2, ISet intersect)
        {
            // email1 is a particular address
            if (email1.IndexOf('@') != -1)
            {
                string _sub = email1.Substring(email1.IndexOf('@') + 1);
                // both are a particular mailbox
                if (email2.IndexOf('@') != -1)
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
                if (email2.IndexOf('@') != -1)
                {
                    string _sub = email2.Substring(email1.IndexOf('@') + 1);
                    if (WithinDomain(_sub, email1))
                    {
                        intersect.Add(email2);
                    }
                }
                // email2 specifies a domain
                else if (Platform.StartsWith(email2, "."))
                {
                    if (WithinDomain(email1, email2) || Platform.EqualsIgnoreCase(email1, email2))
                    {
                        intersect.Add(email1);
                    }
                    else if (WithinDomain(email2, email1))
                    {
                        intersect.Add(email2);
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
                if (email2.IndexOf('@') != -1)
                {
                    string _sub = email2.Substring(email2.IndexOf('@') + 1);
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

        private ISet IntersectUri(ISet permitted, ISet uris)
        {
            ISet intersect = new HashSet();
            foreach (GeneralSubtree subtree in uris)
            {
                string uri = ExtractNameAsString(subtree.Base);
                if (permitted == null)
                {
                    if (uri != null)
                    {
                        intersect.Add(uri);
                    }
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

        private ISet UnionUri(ISet excluded, string uri)
        {
            if (excluded.IsEmpty)
            {
                if (uri == null)
                    return excluded;

                excluded.Add(uri);
                return excluded;
            }
            else
            {
                ISet union = new HashSet();
                foreach (string _excluded in excluded)
                {
                    unionURI(_excluded, uri, union);
                }
                return union;
            }
        }

        private void IntersectUri(string email1, string email2, ISet intersect)
        {
            // email1 is a particular address
            if (email1.IndexOf('@') != -1)
            {
                string _sub = email1.Substring(email1.IndexOf('@') + 1);
                // both are a particular mailbox
                if (email2.IndexOf('@') != -1)
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
                if (email2.IndexOf('@') != -1)
                {
                    string _sub = email2.Substring(email1.IndexOf('@') + 1);
                    if (WithinDomain(_sub, email1))
                    {
                        intersect.Add(email2);
                    }
                }
                // email2 specifies a domain
                else if (Platform.StartsWith(email2, "."))
                {
                    if (WithinDomain(email1, email2) || Platform.EqualsIgnoreCase(email1, email2))
                    {
                        intersect.Add(email1);
                    }
                    else if (WithinDomain(email2, email1))
                    {
                        intersect.Add(email2);
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
                if (email2.IndexOf('@') != -1)
                {
                    string _sub = email2.Substring(email2.IndexOf('@') + 1);
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

        private static string ExtractHostFromURL(string url)
        {
            // see RFC 1738
            // remove ':' after protocol, e.g. http:
            string sub = url.Substring(url.IndexOf(':') + 1);
            // extract host from Common Internet Scheme Syntax, e.g. http://
            int idxOfSlashes = Platform.IndexOf(sub, "//");
            if (idxOfSlashes != -1)
            {
                sub = sub.Substring(idxOfSlashes + 2);
            }
            // first remove port, e.g. http://test.com:21
            if (sub.LastIndexOf(':') != -1)
            {
                sub = sub.Substring(0, sub.LastIndexOf(':'));
            }
            // remove user and password, e.g. http://john:password@test.com
            sub = sub.Substring(sub.IndexOf(':') + 1);
            sub = sub.Substring(sub.IndexOf('@') + 1);
            // remove local parts, e.g. http://test.com/bla
            if (sub.IndexOf('/') != -1)
            {
                sub = sub.Substring(0, sub.IndexOf('/'));
            }
            return sub;
        }

        /**
         * Checks if the given GeneralName is in the permitted ISet.
         *
         * @param name The GeneralName
         * @throws PkixNameConstraintValidatorException
         *          If the <code>name</code>
         */
        public void checkPermitted(GeneralName name)
        //throws PkixNameConstraintValidatorException
        {
            switch (name.TagNo)
            {
            case GeneralName.OtherName:
                CheckPermittedOtherName(permittedSubtreesOtherName, OtherName.GetInstance(name.Name));
                break;
            case GeneralName.Rfc822Name:
                CheckPermittedEmail(permittedSubtreesEmail, ExtractNameAsString(name));
                break;
            case GeneralName.DnsName:
                CheckPermittedDns(permittedSubtreesDNS, ExtractNameAsString(name));
                break;
            case GeneralName.DirectoryName:
                CheckPermittedDN(Asn1Sequence.GetInstance(name.Name.ToAsn1Object()));
                break;
            case GeneralName.UniformResourceIdentifier:
                CheckPermittedUri(permittedSubtreesURI, ExtractNameAsString(name));
                break;
            case GeneralName.IPAddress:
                CheckPermittedIP(permittedSubtreesIP, Asn1OctetString.GetInstance(name.Name).GetOctets());
                break;
            }
        }

        /**
         * Check if the given GeneralName is contained in the excluded ISet.
         *
         * @param name The GeneralName.
         * @throws PkixNameConstraintValidatorException
         *          If the <code>name</code> is
         *          excluded.
         */
        public void checkExcluded(GeneralName name)
        //throws PkixNameConstraintValidatorException
        {
            switch (name.TagNo)
            {
            case GeneralName.OtherName:
                CheckExcludedOtherName(excludedSubtreesOtherName, OtherName.GetInstance(name.Name));
                break;
            case GeneralName.Rfc822Name:
                CheckExcludedEmail(excludedSubtreesEmail, ExtractNameAsString(name));
                break;
            case GeneralName.DnsName:
                CheckExcludedDns(excludedSubtreesDNS, ExtractNameAsString(name));
                break;
            case GeneralName.DirectoryName:
                CheckExcludedDN(Asn1Sequence.GetInstance(name.Name.ToAsn1Object()));
                break;
            case GeneralName.UniformResourceIdentifier:
                CheckExcludedUri(excludedSubtreesURI, ExtractNameAsString(name));
                break;
            case GeneralName.IPAddress:
                CheckExcludedIP(excludedSubtreesIP, Asn1OctetString.GetInstance(name.Name).GetOctets());
                break;
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
            IDictionary subtreesMap = Platform.CreateHashtable();

            // group in ISets in a map ordered by tag no.
            foreach (object obj in permitted)
            {
                GeneralSubtree subtree = GeneralSubtree.GetInstance(obj);

                int tagNo = subtree.Base.TagNo;
                if (subtreesMap[tagNo] == null)
                {
                    subtreesMap[tagNo] = new HashSet();
                }

                ((ISet)subtreesMap[tagNo]).Add(subtree);
            }

            foreach (DictionaryEntry entry in subtreesMap)
            {
                // go through all subtree groups
                switch ((int)entry.Key)
                {
                case GeneralName.OtherName:
                    permittedSubtreesOtherName = IntersectOtherName(permittedSubtreesOtherName,
                        (ISet)entry.Value);
                    break;
                case GeneralName.Rfc822Name:
                    permittedSubtreesEmail = IntersectEmail(permittedSubtreesEmail,
                        (ISet)entry.Value);
                    break;
                case GeneralName.DnsName:
                    permittedSubtreesDNS = IntersectDns(permittedSubtreesDNS,
                        (ISet)entry.Value);
                    break;
                case GeneralName.DirectoryName:
                    permittedSubtreesDN = IntersectDN(permittedSubtreesDN,
                        (ISet)entry.Value);
                    break;
                case GeneralName.UniformResourceIdentifier:
                    permittedSubtreesURI = IntersectUri(permittedSubtreesURI,
                        (ISet)entry.Value);
                    break;
                case GeneralName.IPAddress:
                    permittedSubtreesIP = IntersectIP(permittedSubtreesIP,
                        (ISet)entry.Value);
                    break;
                }
            }
        }

        private string ExtractNameAsString(GeneralName name)
        {
            return DerIA5String.GetInstance(name.Name).GetString();
        }

        public void IntersectEmptyPermittedSubtree(int nameType)
        {
            switch (nameType)
            {
            case GeneralName.OtherName:
                permittedSubtreesOtherName = new HashSet();
                break;
            case GeneralName.Rfc822Name:
                permittedSubtreesEmail = new HashSet();
                break;
            case GeneralName.DnsName:
                permittedSubtreesDNS = new HashSet();
                break;
            case GeneralName.DirectoryName:
                permittedSubtreesDN = new HashSet();
                break;
            case GeneralName.UniformResourceIdentifier:
                permittedSubtreesURI = new HashSet();
                break;
            case GeneralName.IPAddress:
                permittedSubtreesIP = new HashSet();
                break;
            }
        }

        /**
         * Adds a subtree to the excluded ISet of these name constraints.
         *
         * @param subtree A subtree with an excluded GeneralName.
         */
        public void AddExcludedSubtree(GeneralSubtree subtree)
        {
            GeneralName subTreeBase = subtree.Base;

            switch (subTreeBase.TagNo)
            {
            case GeneralName.OtherName:
                excludedSubtreesOtherName = UnionOtherName(excludedSubtreesOtherName,
                    OtherName.GetInstance(subTreeBase.Name));
                break;
            case GeneralName.Rfc822Name:
                excludedSubtreesEmail = UnionEmail(excludedSubtreesEmail,
                    ExtractNameAsString(subTreeBase));
                break;
            case GeneralName.DnsName:
                excludedSubtreesDNS = UnionDns(excludedSubtreesDNS,
                    ExtractNameAsString(subTreeBase));
                break;
            case GeneralName.DirectoryName:
                excludedSubtreesDN = UnionDN(excludedSubtreesDN,
                    (Asn1Sequence)subTreeBase.Name.ToAsn1Object());
                break;
            case GeneralName.UniformResourceIdentifier:
                excludedSubtreesURI = UnionUri(excludedSubtreesURI,
                    ExtractNameAsString(subTreeBase));
                break;
            case GeneralName.IPAddress:
                excludedSubtreesIP = UnionIP(excludedSubtreesIP,
                    Asn1OctetString.GetInstance(subTreeBase.Name).GetOctets());
                break;
            }
        }

        /**
         * Returns the maximum IP address.
         *
         * @param ip1 The first IP address.
         * @param ip2 The second IP address.
         * @return The maximum IP address.
         */
        private static byte[] Max(byte[] ip1, byte[] ip2)
        {
            for (int i = 0; i < ip1.Length; i++)
            {
                if ((ip1[i] & 0xFFFF) > (ip2[i] & 0xFFFF))
                {
                    return ip1;
                }
            }
            return ip2;
        }

        /**
         * Returns the minimum IP address.
         *
         * @param ip1 The first IP address.
         * @param ip2 The second IP address.
         * @return The minimum IP address.
         */
        private static byte[] Min(byte[] ip1, byte[] ip2)
        {
            for (int i = 0; i < ip1.Length; i++)
            {
                if ((ip1[i] & 0xFFFF) < (ip2[i] & 0xFFFF))
                {
                    return ip1;
                }
            }
            return ip2;
        }

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
            if (Org.BouncyCastle.Utilities.Arrays.AreEqual(ip1, ip2))
            {
                return 0;
            }
            if (Org.BouncyCastle.Utilities.Arrays.AreEqual(Max(ip1, ip2), ip1))
            {
                return 1;
            }
            return -1;
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

		[Obsolete("Use GetHashCode instead")]
		public int HashCode()
		{
			return GetHashCode();
		}

		public override int GetHashCode()
        {
            return HashCollection(excludedSubtreesDN)
                + HashCollection(excludedSubtreesDNS)
                + HashCollection(excludedSubtreesEmail)
                + HashCollection(excludedSubtreesIP)
                + HashCollection(excludedSubtreesURI)
                + HashCollection(excludedSubtreesOtherName)
                + HashCollection(permittedSubtreesDN)
                + HashCollection(permittedSubtreesDNS)
                + HashCollection(permittedSubtreesEmail)
                + HashCollection(permittedSubtreesIP)
                + HashCollection(permittedSubtreesURI)
                + HashCollection(permittedSubtreesOtherName);
        }

        private int HashCollection(ICollection c)
        {
            if (c == null)
                return 0;

            int hash = 0;
            foreach (Object o in c)
            {
                if (o is byte[])
                {
                    hash += Arrays.GetHashCode((byte[])o);
                }
                else
                {
                    hash += o.GetHashCode();
                }
            }
            return hash;
        }

		public override bool Equals(Object o)
		{
			if (!(o is PkixNameConstraintValidator))
				return false;

			PkixNameConstraintValidator constraintValidator = (PkixNameConstraintValidator)o;

            return CollectionsAreEqual(constraintValidator.excludedSubtreesDN, excludedSubtreesDN)
                && CollectionsAreEqual(constraintValidator.excludedSubtreesDNS, excludedSubtreesDNS)
                && CollectionsAreEqual(constraintValidator.excludedSubtreesEmail, excludedSubtreesEmail)
                && CollectionsAreEqual(constraintValidator.excludedSubtreesIP, excludedSubtreesIP)
                && CollectionsAreEqual(constraintValidator.excludedSubtreesURI, excludedSubtreesURI)
                && CollectionsAreEqual(constraintValidator.excludedSubtreesOtherName, excludedSubtreesOtherName)
                && CollectionsAreEqual(constraintValidator.permittedSubtreesDN, permittedSubtreesDN)
                && CollectionsAreEqual(constraintValidator.permittedSubtreesDNS, permittedSubtreesDNS)
                && CollectionsAreEqual(constraintValidator.permittedSubtreesEmail, permittedSubtreesEmail)
                && CollectionsAreEqual(constraintValidator.permittedSubtreesIP, permittedSubtreesIP)
                && CollectionsAreEqual(constraintValidator.permittedSubtreesURI, permittedSubtreesURI)
                && CollectionsAreEqual(constraintValidator.permittedSubtreesOtherName, permittedSubtreesOtherName);
		}

        private bool CollectionsAreEqual(ICollection coll1, ICollection coll2)
        {
            if (coll1 == coll2)
                return true;
            if (coll1 == null || coll2 == null || coll1.Count != coll2.Count)
                return false;

            foreach (Object a in coll1)
            {
                bool found = false;
                foreach (Object b in coll2)
                {
                    if (SpecialEquals(a, b))
                    {
                        found = true;
                        break;
                    }
                }

                if (!found)
                    return false;
            }
            return true;
        }

        private bool SpecialEquals(Object o1, Object o2)
        {
            if (o1 == o2)
            {
                return true;
            }
            if (o1 == null || o2 == null)
            {
                return false;
            }
            if ((o1 is byte[]) && (o2 is byte[]))
            {
                return Arrays.AreEqual((byte[])o1, (byte[])o2);
            }
            else
            {
                return o1.Equals(o2);
            }
        }

        /**
         * Stringifies an IPv4 or v6 address with subnet mask.
         *
         * @param ip The IP with subnet mask.
         * @return The stringified IP address.
         */
        private string StringifyIP(byte[] ip)
        {
            string temp = "";
            for (int i = 0; i < ip.Length / 2; i++)
            {
                //temp += Integer.toString(ip[i] & 0x00FF) + ".";
                temp += (ip[i] & 0x00FF) + ".";
            }
            temp = temp.Substring(0, temp.Length - 1);
            temp += "/";
            for (int i = ip.Length / 2; i < ip.Length; i++)
            {
                //temp += Integer.toString(ip[i] & 0x00FF) + ".";
                temp += (ip[i] & 0x00FF) + ".";
            }
            temp = temp.Substring(0, temp.Length - 1);
            return temp;
        }

        private string StringifyIPCollection(ISet ips)
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

        private string StringifyOtherNameCollection(ISet otherNames)
        {
            string temp = "";
            temp += "[";
            foreach (object obj in otherNames)
            {
                OtherName name = OtherName.GetInstance(obj);
                if (temp.Length > 1)
                {
                    temp += ",";
                }
                temp += name.TypeID.Id;
                temp += ":";
                try
                {
                    temp += Hex.ToHexString(name.Value.ToAsn1Object().GetEncoded());
                }
                catch (IOException e)
                {
                    temp += e.ToString();
                }
            }
            temp += "]";
            return temp;
        }

        public override string ToString()
        {
            string temp = "";

            temp += "permitted:\n";
            if (permittedSubtreesDN != null)
            {
                temp += "DN:\n";
                temp += permittedSubtreesDN.ToString() + "\n";
            }
            if (permittedSubtreesDNS != null)
            {
                temp += "DNS:\n";
                temp += permittedSubtreesDNS.ToString() + "\n";
            }
            if (permittedSubtreesEmail != null)
            {
                temp += "Email:\n";
                temp += permittedSubtreesEmail.ToString() + "\n";
            }
            if (permittedSubtreesURI != null)
            {
                temp += "URI:\n";
                temp += permittedSubtreesURI.ToString() + "\n";
            }
            if (permittedSubtreesIP != null)
            {
                temp += "IP:\n";
                temp += StringifyIPCollection(permittedSubtreesIP) + "\n";
            }
            if (permittedSubtreesOtherName != null)
            {
                temp += "OtherName:\n";
                temp += StringifyOtherNameCollection(permittedSubtreesOtherName);
            }
            temp += "excluded:\n";
            if (!(excludedSubtreesDN.IsEmpty))
            {
                temp += "DN:\n";
                temp += excludedSubtreesDN.ToString() + "\n";
            }
            if (!excludedSubtreesDNS.IsEmpty)
            {
                temp += "DNS:\n";
                temp += excludedSubtreesDNS.ToString() + "\n";
            }
            if (!excludedSubtreesEmail.IsEmpty)
            {
                temp += "Email:\n";
                temp += excludedSubtreesEmail.ToString() + "\n";
            }
            if (!excludedSubtreesURI.IsEmpty)
            {
                temp += "URI:\n";
                temp += excludedSubtreesURI.ToString() + "\n";
            }
            if (!excludedSubtreesIP.IsEmpty)
            {
                temp += "IP:\n";
                temp += StringifyIPCollection(excludedSubtreesIP) + "\n";
            }
            if (!excludedSubtreesOtherName.IsEmpty)
            {
                temp += "OtherName:\n";
                temp += StringifyOtherNameCollection(excludedSubtreesOtherName);
            }
            return temp;
        }
    }
}
