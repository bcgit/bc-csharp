using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using System.Text;
using System.Threading;

using Org.BouncyCastle.Asn1.Pkcs;
using Org.BouncyCastle.Asn1.X500.Style;
using Org.BouncyCastle.Utilities.Collections;
using Org.BouncyCastle.Utilities.Encoders;

namespace Org.BouncyCastle.Asn1.X509
{
    /**
    * <pre>
    *     RDNSequence ::= SEQUENCE OF RelativeDistinguishedName
    *
    *     RelativeDistinguishedName ::= SET SIZE (1..MAX) OF AttributeTypeAndValue
    *
    *     AttributeTypeAndValue ::= SEQUENCE {
    *                                   type  OBJECT IDENTIFIER,
    *                                   value ANY }
    * </pre>
    */
    // TODO[api] sealed (and adjust protected constructors)
    // TODO[api] Implement IAsn1Choice (or just switch over to X500Name)?
    public class X509Name
        : Asn1Encodable
    {
        /**
        * country code - StringType(SIZE(2))
        */
        public static readonly DerObjectIdentifier C = new DerObjectIdentifier("2.5.4.6");

        /**
        * organization - StringType(SIZE(1..64))
        */
        public static readonly DerObjectIdentifier O = new DerObjectIdentifier("2.5.4.10");

        /**
        * organizational unit name - StringType(SIZE(1..64))
        */
        public static readonly DerObjectIdentifier OU = new DerObjectIdentifier("2.5.4.11");

        /**
        * Title
        */
        public static readonly DerObjectIdentifier T = new DerObjectIdentifier("2.5.4.12");

        /**
        * common name - StringType(SIZE(1..64))
        */
        public static readonly DerObjectIdentifier CN = new DerObjectIdentifier("2.5.4.3");

        /**
        * street - StringType(SIZE(1..64))
        */
        public static readonly DerObjectIdentifier Street = new DerObjectIdentifier("2.5.4.9");

        /**
        * device serial number name - StringType(SIZE(1..64))
        */
        public static readonly DerObjectIdentifier SerialNumber = new DerObjectIdentifier("2.5.4.5");

        /**
        * locality name - StringType(SIZE(1..64))
        */
        public static readonly DerObjectIdentifier L = new DerObjectIdentifier("2.5.4.7");

        /**
        * state, or province name - StringType(SIZE(1..64))
        */
        public static readonly DerObjectIdentifier ST = new DerObjectIdentifier("2.5.4.8");

        /**
        * Naming attributes of type X520name
        */
        public static readonly DerObjectIdentifier Surname = new DerObjectIdentifier("2.5.4.4");
        public static readonly DerObjectIdentifier GivenName = new DerObjectIdentifier("2.5.4.42");
        public static readonly DerObjectIdentifier Initials = new DerObjectIdentifier("2.5.4.43");
        public static readonly DerObjectIdentifier Generation = new DerObjectIdentifier("2.5.4.44");
        public static readonly DerObjectIdentifier UniqueIdentifier = new DerObjectIdentifier("2.5.4.45");

        public static readonly DerObjectIdentifier Description = new DerObjectIdentifier("2.5.4.13");

        /**
         * businessCategory - DirectoryString(SIZE(1..128)
         */
        public static readonly DerObjectIdentifier BusinessCategory = new DerObjectIdentifier("2.5.4.15");

        /**
         * postalCode - DirectoryString(SIZE(1..40)
         */
        public static readonly DerObjectIdentifier PostalCode = new DerObjectIdentifier("2.5.4.17");

        /**
         * dnQualifier - DirectoryString(SIZE(1..64)
         */
        public static readonly DerObjectIdentifier DnQualifier = new DerObjectIdentifier("2.5.4.46");

        /**
         * RFC 3039 Pseudonym - DirectoryString(SIZE(1..64)
         */
        public static readonly DerObjectIdentifier Pseudonym = new DerObjectIdentifier("2.5.4.65");

        public static readonly DerObjectIdentifier Role = new DerObjectIdentifier("2.5.4.72");

        /**
         * RFC 3039 DateOfBirth - GeneralizedTime - YYYYMMDD000000Z
         */
        public static readonly DerObjectIdentifier DateOfBirth = X509ObjectIdentifiers.id_pda.Branch("1");

        /**
         * RFC 3039 PlaceOfBirth - DirectoryString(SIZE(1..128)
         */
        public static readonly DerObjectIdentifier PlaceOfBirth = X509ObjectIdentifiers.id_pda.Branch("2");

        /**
         * RFC 3039 DateOfBirth - PrintableString (SIZE(1)) -- "M", "F", "m" or "f"
         */
        public static readonly DerObjectIdentifier Gender = X509ObjectIdentifiers.id_pda.Branch("3");

        /**
         * RFC 3039 CountryOfCitizenship - PrintableString (SIZE (2)) -- ISO 3166
         * codes only
         */
        public static readonly DerObjectIdentifier CountryOfCitizenship = X509ObjectIdentifiers.id_pda.Branch("4");

        /**
         * RFC 3039 CountryOfCitizenship - PrintableString (SIZE (2)) -- ISO 3166
         * codes only
         */
        public static readonly DerObjectIdentifier CountryOfResidence = X509ObjectIdentifiers.id_pda.Branch("5");

        /**
         * ISIS-MTT NameAtBirth - DirectoryString(SIZE(1..64)
         */
        public static readonly DerObjectIdentifier NameAtBirth =  new DerObjectIdentifier("1.3.36.8.3.14");

        /**
         * RFC 3039 PostalAddress - SEQUENCE SIZE (1..6) OF
         * DirectoryString(SIZE(1..30))
         */
        public static readonly DerObjectIdentifier PostalAddress = new DerObjectIdentifier("2.5.4.16");

        /**
         * RFC 2256 dmdName
         */
        public static readonly DerObjectIdentifier DmdName = new DerObjectIdentifier("2.5.4.54");

        /**
         * id-at-telephoneNumber
         */
        public static readonly DerObjectIdentifier TelephoneNumber = X509ObjectIdentifiers.id_at_telephoneNumber;

        /**
         * id-at-organizationIdentifier
         */
        public static readonly DerObjectIdentifier OrganizationIdentifier = X509ObjectIdentifiers.id_at_organizationIdentifier;

        /**
         * id-at-name
         */
        public static readonly DerObjectIdentifier Name = X509ObjectIdentifiers.id_at_name;

        /**
        * Email address (RSA PKCS#9 extension) - IA5String.
        * <p>Note: if you're trying to be ultra orthodox, don't use this! It shouldn't be in here.</p>
        */
        public static readonly DerObjectIdentifier EmailAddress = PkcsObjectIdentifiers.Pkcs9AtEmailAddress;

        /**
        * more from PKCS#9
        */
        public static readonly DerObjectIdentifier UnstructuredName = PkcsObjectIdentifiers.Pkcs9AtUnstructuredName;
        public static readonly DerObjectIdentifier UnstructuredAddress = PkcsObjectIdentifiers.Pkcs9AtUnstructuredAddress;

        /**
        * email address in Verisign certificates
        */
        public static readonly DerObjectIdentifier E = EmailAddress;

        /*
        * others...
        */
        public static readonly DerObjectIdentifier DC = new DerObjectIdentifier("0.9.2342.19200300.100.1.25");

        /**
        * LDAP User id.
        */
        // TODO[api] Change to 'Uid'
        public static readonly DerObjectIdentifier UID = new DerObjectIdentifier("0.9.2342.19200300.100.1.1");

        /**
         * CA/Browser Forum https://cabforum.org/uploads/CA-Browser-Forum-BR-v2.0.0.pdf, Table 78
         */
        public static readonly DerObjectIdentifier JurisdictionC = new DerObjectIdentifier("1.3.6.1.4.1.311.60.2.1.3");

        /**
         * CA/Browser Forum https://cabforum.org/uploads/CA-Browser-Forum-BR-v2.0.0.pdf, Table 78
         */
        public static readonly DerObjectIdentifier JurisdictionST = new DerObjectIdentifier("1.3.6.1.4.1.311.60.2.1.2");

        /**
         * CA/Browser Forum https://cabforum.org/uploads/CA-Browser-Forum-BR-v2.0.0.pdf, Table 78
         */
        public static readonly DerObjectIdentifier JurisdictionL = new DerObjectIdentifier("1.3.6.1.4.1.311.60.2.1.1");

        /**
        * determines whether or not strings should be processed and printed
        * from back to front.
        */
        public static bool DefaultReverse
        {
            get { return Convert.ToBoolean(Interlocked.Read(ref defaultReverse)); }
            set { Interlocked.Exchange(ref defaultReverse, Convert.ToInt64(value)); }
        }

        // TODO[api] Replace this global switch
        private static long defaultReverse = 0;

        /**
        * default look up table translating OID values into their common symbols following
        * the convention in RFC 2253 with a few extras
        */
        private static readonly IDictionary<DerObjectIdentifier, string> DefaultSymbolsInternal =
            new Dictionary<DerObjectIdentifier, string>();
        public static readonly IDictionary<DerObjectIdentifier, string> DefaultSymbols =
            CollectionUtilities.ReadOnly(DefaultSymbolsInternal);

        /**
         * look up table translating OID values into their common symbols following the convention in RFC 2253
         */
        private static readonly IDictionary<DerObjectIdentifier, string> RFC2253SymbolsInternal =
            new Dictionary<DerObjectIdentifier, string>();
        public static readonly IDictionary<DerObjectIdentifier, string> RFC2253Symbols =
            CollectionUtilities.ReadOnly(RFC2253SymbolsInternal);

        /**
         * look up table translating OID values into their common symbols following the convention in RFC 1779
         *
         */
        private static readonly IDictionary<DerObjectIdentifier, string> RFC1779SymbolsInternal =
            new Dictionary<DerObjectIdentifier, string>();
        public static readonly IDictionary<DerObjectIdentifier, string> RFC1779Symbols =
            CollectionUtilities.ReadOnly(RFC1779SymbolsInternal);

        /**
        * look up table translating common symbols into their OIDS.
        */
        private static readonly IDictionary<string, DerObjectIdentifier> DefaultLookupInternal =
            new Dictionary<string, DerObjectIdentifier>(StringComparer.OrdinalIgnoreCase);
        public static readonly IDictionary<string, DerObjectIdentifier> DefaultLookup =
            CollectionUtilities.ReadOnly(DefaultLookupInternal);

        static X509Name()
        {
            DefaultSymbolsInternal.Add(C, "C");
            DefaultSymbolsInternal.Add(O, "O");
            DefaultSymbolsInternal.Add(T, "T");
            DefaultSymbolsInternal.Add(OU, "OU");
            DefaultSymbolsInternal.Add(CN, "CN");
            DefaultSymbolsInternal.Add(L, "L");
            DefaultSymbolsInternal.Add(ST, "ST");
            DefaultSymbolsInternal.Add(SerialNumber, "SERIALNUMBER");
            DefaultSymbolsInternal.Add(EmailAddress, "E");
            DefaultSymbolsInternal.Add(DC, "DC");
            DefaultSymbolsInternal.Add(UID, "UID");
            DefaultSymbolsInternal.Add(Street, "STREET");
            DefaultSymbolsInternal.Add(Surname, "SURNAME");
            DefaultSymbolsInternal.Add(GivenName, "GIVENNAME");
            DefaultSymbolsInternal.Add(Initials, "INITIALS");
            DefaultSymbolsInternal.Add(Generation, "GENERATION");
            DefaultSymbolsInternal.Add(Description, "DESCRIPTION");
            DefaultSymbolsInternal.Add(Role, "ROLE");
            DefaultSymbolsInternal.Add(UnstructuredAddress, "unstructuredAddress");
            DefaultSymbolsInternal.Add(UnstructuredName, "unstructuredName");
            DefaultSymbolsInternal.Add(UniqueIdentifier, "UniqueIdentifier");
            DefaultSymbolsInternal.Add(DnQualifier, "DN");
            DefaultSymbolsInternal.Add(Pseudonym, "Pseudonym");
            DefaultSymbolsInternal.Add(PostalAddress, "PostalAddress");
            DefaultSymbolsInternal.Add(NameAtBirth, "NameAtBirth");
            DefaultSymbolsInternal.Add(CountryOfCitizenship, "CountryOfCitizenship");
            DefaultSymbolsInternal.Add(CountryOfResidence, "CountryOfResidence");
            DefaultSymbolsInternal.Add(Gender, "Gender");
            DefaultSymbolsInternal.Add(PlaceOfBirth, "PlaceOfBirth");
            DefaultSymbolsInternal.Add(DateOfBirth, "DateOfBirth");
            DefaultSymbolsInternal.Add(PostalCode, "PostalCode");
            DefaultSymbolsInternal.Add(BusinessCategory, "BusinessCategory");
            DefaultSymbolsInternal.Add(TelephoneNumber, "TelephoneNumber");
            DefaultSymbolsInternal.Add(Name, "Name");
            DefaultSymbolsInternal.Add(OrganizationIdentifier, "organizationIdentifier");
            DefaultSymbolsInternal.Add(JurisdictionC, "jurisdictionCountry");
            DefaultSymbolsInternal.Add(JurisdictionST, "jurisdictionState");
            DefaultSymbolsInternal.Add(JurisdictionL, "jurisdictionLocality");

            RFC2253SymbolsInternal.Add(C, "C");
            RFC2253SymbolsInternal.Add(O, "O");
            RFC2253SymbolsInternal.Add(OU, "OU");
            RFC2253SymbolsInternal.Add(CN, "CN");
            RFC2253SymbolsInternal.Add(L, "L");
            RFC2253SymbolsInternal.Add(ST, "ST");
            RFC2253SymbolsInternal.Add(Street, "STREET");
            RFC2253SymbolsInternal.Add(DC, "DC");
            RFC2253SymbolsInternal.Add(UID, "UID");

            RFC1779SymbolsInternal.Add(C, "C");
            RFC1779SymbolsInternal.Add(O, "O");
            RFC1779SymbolsInternal.Add(OU, "OU");
            RFC1779SymbolsInternal.Add(CN, "CN");
            RFC1779SymbolsInternal.Add(L, "L");
            RFC1779SymbolsInternal.Add(ST, "ST");
            RFC1779SymbolsInternal.Add(Street, "STREET");

            DefaultLookupInternal.Add("c", C);
            DefaultLookupInternal.Add("o", O);
            DefaultLookupInternal.Add("t", T);
            DefaultLookupInternal.Add("ou", OU);
            DefaultLookupInternal.Add("cn", CN);
            DefaultLookupInternal.Add("l", L);
            DefaultLookupInternal.Add("st", ST);
            DefaultLookupInternal.Add("sn", Surname);
            DefaultLookupInternal.Add("serialnumber", SerialNumber);
            DefaultLookupInternal.Add("street", Street);
            DefaultLookupInternal.Add("emailaddress", E);
            DefaultLookupInternal.Add("dc", DC);
            DefaultLookupInternal.Add("e", E);
            DefaultLookupInternal.Add("uid", UID);
            DefaultLookupInternal.Add("surname", Surname);
            DefaultLookupInternal.Add("givenname", GivenName);
            DefaultLookupInternal.Add("initials", Initials);
            DefaultLookupInternal.Add("generation", Generation);
            DefaultLookupInternal.Add("description", Description);
            DefaultLookupInternal.Add("role", Role);
            DefaultLookupInternal.Add("unstructuredaddress", UnstructuredAddress);
            DefaultLookupInternal.Add("unstructuredname", UnstructuredName);
            DefaultLookupInternal.Add("uniqueidentifier", UniqueIdentifier);
            DefaultLookupInternal.Add("dn", DnQualifier);
            DefaultLookupInternal.Add("pseudonym", Pseudonym);
            DefaultLookupInternal.Add("postaladdress", PostalAddress);
            DefaultLookupInternal.Add("nameatbirth", NameAtBirth);
            DefaultLookupInternal.Add("countryofcitizenship", CountryOfCitizenship);
            DefaultLookupInternal.Add("countryofresidence", CountryOfResidence);
            DefaultLookupInternal.Add("gender", Gender);
            DefaultLookupInternal.Add("placeofbirth", PlaceOfBirth);
            DefaultLookupInternal.Add("dateofbirth", DateOfBirth);
            DefaultLookupInternal.Add("postalcode", PostalCode);
            DefaultLookupInternal.Add("businesscategory", BusinessCategory);
            DefaultLookupInternal.Add("telephonenumber", TelephoneNumber);
            DefaultLookupInternal.Add("name", Name);
            DefaultLookupInternal.Add("organizationidentifier", OrganizationIdentifier);
            DefaultLookupInternal.Add("jurisdictioncountry", JurisdictionC);
            DefaultLookupInternal.Add("jurisdictionstate", JurisdictionST);
            DefaultLookupInternal.Add("jurisdictionlocality", JurisdictionL);
        }

        public static X509Name GetInstance(object obj)
        {
            if (obj == null)
                return null;
            if (obj is X509Name x509Name)
                return x509Name;
            return new X509Name(Asn1Sequence.GetInstance(obj));
        }

        /**
        * Return a X509Name based on the passed in tagged object.
        *
        * @param obj tag object holding name.
        * @param explicitly true if explicitly tagged false otherwise.
        * @return the X509Name
        */
        public static X509Name GetInstance(Asn1TaggedObject obj, bool explicitly) =>
            new X509Name(Asn1Sequence.GetInstance(obj, explicitly));

        public static X509Name GetOptional(Asn1Encodable element)
        {
            if (element == null)
                throw new ArgumentNullException(nameof(element));

            if (element is X509Name x509Name)
                return x509Name;

            Asn1Sequence asn1Sequence = Asn1Sequence.GetOptional(element);
            if (asn1Sequence != null)
                return new X509Name(asn1Sequence);

            return null;
        }

        public static X509Name GetTagged(Asn1TaggedObject taggedObject, bool declaredExplicit) =>
            new X509Name(Asn1Sequence.GetTagged(taggedObject, declaredExplicit));

        private readonly List<DerObjectIdentifier> m_ordering = new List<DerObjectIdentifier>();
        private readonly X509NameEntryConverter converter;

        private List<string> m_values = new List<string>();
        private List<bool> m_added = new List<bool>();
        private Asn1Sequence seq;

        protected X509Name()
        {
        }

        /**
        * Constructor from Asn1Sequence
        *
        * the principal will be a list of constructed sets, each containing an (OID, string) pair.
        */
        protected X509Name(Asn1Sequence seq)
        {
            // RDNSequence ::= SEQUENCE OF RelativeDistinguishedName
            this.seq = seq;

            foreach (Asn1Encodable asn1Obj in seq)
            {
                // RelativeDistinguishedName ::= SET SIZE(1..MAX) OF AttributeTypeAndValue
                Asn1Set rdn = Asn1Set.GetInstance(asn1Obj);

                // TODO Apply this check? (Currently "breaks" CertificateTest.CheckDudCertificate)
                //if (rdn.Count < 1)
                //    throw new ArgumentException("badly sized RelativeDistinguishedName");

                for (int i = 0; i < rdn.Count; ++i)
                {
                    Asn1Sequence attributeTypeAndValue = Asn1Sequence.GetInstance(rdn[i]);
                    if (attributeTypeAndValue.Count != 2)
                        throw new ArgumentException("badly sized AttributeTypeAndValue");

                    var type = attributeTypeAndValue[0].ToAsn1Object();
                    var value = attributeTypeAndValue[1].ToAsn1Object();

                    m_ordering.Add(DerObjectIdentifier.GetInstance(type));

                    if (value is IAsn1String asn1String && !(value is DerUniversalString))
                    {
                        string v = asn1String.GetString();
                        if (v.StartsWith("#"))
                        {
                            v = "\\" + v;
                        }

                        m_values.Add(v);
                    }
                    else
                    {
                        m_values.Add("#" + Hex.ToHexString(value.GetEncoded()));
                    }

                    m_added.Add(i != 0);
                }
            }
        }

        /**
        * Constructor from a table of attributes with ordering.
        * <p>
        * it's is assumed the table contains OID/string pairs, and the contents
        * of the table are copied into an internal table as part of the
        * construction process. The ordering ArrayList should contain the OIDs
        * in the order they are meant to be encoded or printed in ToString.</p>
        */
        public X509Name(IList<DerObjectIdentifier> ordering, IDictionary<DerObjectIdentifier, string> attributes)
            : this(ordering, attributes, new X509DefaultEntryConverter())
        {
        }

        /**
        * Constructor from a table of attributes with ordering.
        * <p>
        * it's is assumed the table contains OID/string pairs, and the contents
        * of the table are copied into an internal table as part of the
        * construction process. The ordering ArrayList should contain the OIDs
        * in the order they are meant to be encoded or printed in ToString.</p>
        * <p>
        * The passed in converter will be used to convert the strings into their
        * ASN.1 counterparts.</p>
        */
        public X509Name(IList<DerObjectIdentifier> ordering, IDictionary<DerObjectIdentifier, string> attributes,
            X509NameEntryConverter converter)
        {
            this.converter = converter;

            foreach (DerObjectIdentifier oid in ordering)
            {
                if (!attributes.TryGetValue(oid, out var attribute))
                    throw new ArgumentException("No attribute for object id - " + oid + " - passed to distinguished name");

                m_ordering.Add(oid);
                m_values.Add(attribute);
                m_added.Add(false);
            }
        }

        /**
        * Takes two vectors one of the oids and the other of the values.
        */
        public X509Name(IList<DerObjectIdentifier> oids, IList<string> values)
            : this(oids, values, new X509DefaultEntryConverter())
        {
        }

        /**
        * Takes two vectors one of the oids and the other of the values.
        * <p>
        * The passed in converter will be used to convert the strings into their
        * ASN.1 counterparts.</p>
        */
        public X509Name(IList<DerObjectIdentifier> oids, IList<string> values, X509NameEntryConverter converter)
        {
            this.converter = converter;

            if (oids.Count != values.Count)
                throw new ArgumentException("'oids' must be same length as 'values'.");

            for (int i = 0; i < oids.Count; i++)
            {
                m_ordering.Add(oids[i]);
                m_values.Add(values[i]);
                m_added.Add(false);
            }
        }

        /**
        * Takes an X509 dir name as a string of the format "C=AU, ST=Victoria", or
        * some such, converting it into an ordered set of name attributes.
        */
        public X509Name(string dirName)
            : this(DefaultReverse, DefaultLookup, dirName)
        {
        }

        /**
        * Takes an X509 dir name as a string of the format "C=AU, ST=Victoria", or
        * some such, converting it into an ordered set of name attributes with each
        * string value being converted to its associated ASN.1 type using the passed
        * in converter.
        */
        public X509Name(string dirName, X509NameEntryConverter converter)
            : this(DefaultReverse, DefaultLookup, dirName, converter)
        {
        }

        /**
        * Takes an X509 dir name as a string of the format "C=AU, ST=Victoria", or
        * some such, converting it into an ordered set of name attributes. If reverse
        * is true, create the encoded version of the sequence starting from the
        * last element in the string.
        */
        public X509Name(bool reverse, string dirName)
            : this(reverse, DefaultLookup, dirName)
        {
        }

        /**
        * Takes an X509 dir name as a string of the format "C=AU, ST=Victoria", or
        * some such, converting it into an ordered set of name attributes with each
        * string value being converted to its associated ASN.1 type using the passed
        * in converter. If reverse is true the ASN.1 sequence representing the DN will
        * be built by starting at the end of the string, rather than the start.
        */
        public X509Name(bool reverse, string dirName, X509NameEntryConverter converter)
            : this(reverse, DefaultLookup, dirName, converter)
        {
        }

        /**
        * Takes an X509 dir name as a string of the format "C=AU, ST=Victoria", or
        * some such, converting it into an ordered set of name attributes. lookUp
        * should provide a table of lookups, indexed by lowercase only strings and
        * yielding a DerObjectIdentifier, other than that OID. and numeric oids
        * will be processed automatically.
        * <br/>
        * If reverse is true, create the encoded version of the sequence
        * starting from the last element in the string.
        * @param reverse true if we should start scanning from the end (RFC 2553).
        * @param lookUp table of names and their oids.
        * @param dirName the X.500 string to be parsed.
        */
        public X509Name(bool reverse, IDictionary<string, DerObjectIdentifier> lookup, string dirName)
            : this(reverse, lookup, dirName, new X509DefaultEntryConverter())
        {
        }

        private DerObjectIdentifier DecodeOid(string name, IDictionary<string, DerObjectIdentifier> lookup)
        {
            if (name.StartsWith("OID.", StringComparison.OrdinalIgnoreCase))
                return new DerObjectIdentifier(name.Substring("OID.".Length));

            if (DerObjectIdentifier.TryFromID(name, out var oid) ||
                lookup.TryGetValue(name, out oid))
            {
                return oid;
            }

            throw new ArgumentException("Unknown object id - " + name + " - passed to distinguished name");
        }

        /**
        * Takes an X509 dir name as a string of the format "C=AU, ST=Victoria", or
        * some such, converting it into an ordered set of name attributes. lookUp
        * should provide a table of lookups, indexed by lowercase only strings and
        * yielding a DerObjectIdentifier, other than that OID. and numeric oids
        * will be processed automatically. The passed in converter is used to convert the
        * string values to the right of each equals sign to their ASN.1 counterparts.
        * <br/>
        * @param reverse true if we should start scanning from the end, false otherwise.
        * @param lookUp table of names and oids.
        * @param dirName the string dirName
        * @param converter the converter to convert string values into their ASN.1 equivalents
        */
        public X509Name(bool reverse, IDictionary<string, DerObjectIdentifier> lookup, string dirName,
            X509NameEntryConverter converter)
        {
            this.converter = converter;

            X509NameTokenizer nameTokenizer = new X509NameTokenizer(dirName);

            while (nameTokenizer.HasMoreTokens())
            {
                string rdn = NextToken(nameTokenizer);

                X509NameTokenizer rdnTokenizer = new X509NameTokenizer(rdn, '+');

                AddAttribute(lookup, NextToken(rdnTokenizer), false);

                while (rdnTokenizer.HasMoreTokens())
                {
                    AddAttribute(lookup, NextToken(rdnTokenizer), true);
                }
            }

            if (reverse)
            {
                var o = new List<DerObjectIdentifier>();
                var v = new List<string>();
                var a = new List<bool>();
                int count = 1;

                for (int i = 0; i < m_ordering.Count; i++)
                {
                    count &= m_added[i] ? -1 : 0;
                    o.Insert(count, m_ordering[i]);
                    v.Insert(count, m_values[i]);
                    a.Insert(count, m_added[i]);
                    ++count;
                }

                m_ordering = o;
                m_values = v;
                m_added = a;
            }
        }

        /**
        * return an IList of the oids in the name, in the order they were found.
        */
        public IList<DerObjectIdentifier> GetOidList() => new List<DerObjectIdentifier>(m_ordering);

        /**
        * return an IList of the values found in the name, in the order they
        * were found.
        */
        public IList<string> GetValueList() => GetValueList(null);

        /**
         * return an IList of the values found in the name, in the order they
         * were found, with the DN label corresponding to passed in oid.
         */
        public IList<string> GetValueList(DerObjectIdentifier oid)
        {
            var v = new List<string>();
            for (int i = 0; i != m_values.Count; i++)
            {
                if (null == oid || oid.Equals(m_ordering[i]))
                {
                    string value = m_values[i];
                    if (value.StartsWith("\\#"))
                    {
                        value = value.Substring(1);
                    }

                    v.Add(value);
                }
            }
            return v;
        }

        public override Asn1Object ToAsn1Object()
        {
            if (seq == null)
            {
                Asn1EncodableVector vec = new Asn1EncodableVector();
                Asn1EncodableVector sVec = new Asn1EncodableVector();
                DerObjectIdentifier oid = null;

                for (int i = 0; i != m_ordering.Count; i++)
                {
                    if (oid != null && !m_added[i])
                    {
                        vec.Add(DerSet.FromVector(sVec));
                        sVec = new Asn1EncodableVector();
                    }

                    oid = m_ordering[i];
                    var convertedValue = converter.GetConvertedValue(oid, m_values[i]);
                    sVec.Add(new DerSequence(oid, convertedValue));
                }

                vec.Add(DerSet.FromVector(sVec));

                this.seq = new DerSequence(vec);
            }

            return seq;
        }

        /// <param name="other">The X509Name object to test equivalency against.</param>
        /// <param name="inOrder">If true, the order of elements must be the same,
        /// as well as the values associated with each element.</param>
        public bool Equivalent(X509Name	other, bool inOrder)
        {
            if (!inOrder)
                return this.Equivalent(other);

            if (other == null)
                return false;

            if (other == this)
                return true;

            int orderingSize = m_ordering.Count;

            if (orderingSize != other.m_ordering.Count)
                return false;

            for (int i = 0; i < orderingSize; i++)
            {
                DerObjectIdentifier thisOid = m_ordering[i];
                DerObjectIdentifier thatOid = other.m_ordering[i];

                if (!thisOid.Equals(thatOid))
                    return false;

                string thisValue = m_values[i];
                string thatValue = other.m_values[i];

                if (!EquivalentStrings(thisValue, thatValue))
                    return false;
            }

            return true;
        }

        /**
         * test for equivalence - note: case is ignored.
         */
        public bool Equivalent(X509Name other)
        {
            if (other == null)
                return false;

            if (other == this)
                return true;

            int orderingSize = m_ordering.Count;
            if (orderingSize != other.m_ordering.Count)
                return false;

            if (orderingSize == 0)
                return true;

            bool[] indexes = new bool[orderingSize];
            int start, end, delta;

            if (m_ordering[0].Equals(other.m_ordering[0]))   // guess forward
            {
                start = 0;
                end = orderingSize;
                delta = 1;
            }
            else  // guess reversed - most common problem
            {
                start = orderingSize - 1;
                end = -1;
                delta = -1;
            }

            for (int i = start; i != end; i += delta)
            {
                DerObjectIdentifier oid = m_ordering[i];
                string value = m_values[i];

                bool found = false;
                for (int j = 0; j < orderingSize; j++)
                {
                    if (indexes[j])
                        continue;

                    if (oid.Equals(other.m_ordering[j]))
                    {
                        if (EquivalentStrings(value, other.m_values[j]))
                        {
                            indexes[j] = true;
                            found = true;
                            break;
                        }
                    }
                }

                if (!found)
                    return false;
            }

            return true;
        }

        /**
        * convert the structure to a string - if reverse is true the
        * oids and values are listed out starting with the last element
        * in the sequence (ala RFC 2253), otherwise the string will begin
        * with the first element of the structure. If no string definition
        * for the oid is found in oidSymbols the string value of the oid is
        * added. Two standard symbol tables are provided DefaultSymbols, and
        * RFC2253Symbols as part of this class.
        *
        * @param reverse if true start at the end of the sequence and work back.
        * @param oidSymbols look up table strings for oids.
        */
        public string ToString(bool reverse, IDictionary<DerObjectIdentifier, string> oidSymbols)
        {
            var components = new List<StringBuilder>();

            StringBuilder ava = null;

            for (int i = 0; i < m_ordering.Count; i++)
            {
                if (m_added[i])
                {
                    ava.Append('+');
                    AppendValue(ava, oidSymbols, m_ordering[i], m_values[i]);
                }
                else
                {
                    ava = new StringBuilder();
                    AppendValue(ava, oidSymbols, m_ordering[i], m_values[i]);
                    components.Add(ava);
                }
            }

            if (reverse)
            {
                components.Reverse();
            }

            StringBuilder buf = new StringBuilder();

            if (components.Count > 0)
            {
                buf.Append(components[0].ToString());

                for (int i = 1; i < components.Count; ++i)
                {
                    buf.Append(',');
                    buf.Append(components[i].ToString());
                }
            }

            return buf.ToString();
        }

        public override string ToString() => ToString(DefaultReverse, DefaultSymbols);

        private void AddAttribute(IDictionary<string, DerObjectIdentifier> lookup, string token, bool added)
        {
            X509NameTokenizer tokenizer = new X509NameTokenizer(token, '=');

            string typeToken = NextToken(tokenizer, true);
            string valueToken = NextToken(tokenizer, false);

            DerObjectIdentifier oid = DecodeOid(typeToken.Trim(), lookup);
            string value = IetfUtilities.Unescape(valueToken);

            m_ordering.Add(oid);
            m_values.Add(value);
            m_added.Add(added);
        }

        // TODO Refactor common code between this and IetfUtilities.ValueToString
        private static void AppendValue(StringBuilder buf, IDictionary<DerObjectIdentifier, string> oidSymbols,
            DerObjectIdentifier oid, string val)
        {
            if (oidSymbols.TryGetValue(oid, out var sym))
            {
                buf.Append(sym);
            }
            else
            {
                buf.Append(oid.Id);
            }

            buf.Append('=');
            int start = buf.Length;

            buf.Append(val);
            int end = buf.Length;

            int index = start;
            if (index + 1 < end && buf[index] == '\\' && buf[index + 1] == '#')
            {
                index += 2;
            }

            while (index != end)
            {
                switch (buf[index])
                {
                case ',':
                case '"':
                case '\\':
                case '+':
                case '=':
                case '<':
                case '>':
                case ';':
                {
                    buf.Insert(index, "\\");
                    index += 2;
                    ++end;
                    break;
                }
                default:
                {
                    ++index;
                    break;
                }
                }
            }

            Debug.Assert(end == buf.Length);

            while (start < end && buf[start] == ' ')
            {
                buf.Insert(start, '\\');
                start += 2;
                ++end;
            }

            Debug.Assert(end == buf.Length);

            while (--end > start && buf[end] == ' ')
            {
                buf.Insert(end, '\\');
            }
        }

        private static string Canonicalize(string s)
        {
            string v = s.ToLowerInvariant().Trim();

            if (v.StartsWith("#"))
            {
                Asn1Object obj = DecodeObject(v);
                if (obj is IAsn1String str)
                {
                    v = str.GetString().ToLowerInvariant().Trim();
                }
            }

            return v;
        }

        private static Asn1Object DecodeObject(string v)
        {
            try
            {
                return Asn1Object.FromByteArray(Hex.DecodeStrict(v, 1, v.Length - 1));
            }
            catch (IOException e)
            {
                throw new InvalidOperationException("unknown encoding in name: " + e.Message, e);
            }
        }

        private static bool EquivalentStrings(string s1, string s2)
        {
            if (s1 != s2)
            {
                string v1 = Canonicalize(s1);
                string v2 = Canonicalize(s2);

                if (v1 != v2)
                {
                    v1 = StripInternalSpaces(v1);
                    v2 = StripInternalSpaces(v2);

                    if (v1 != v2)
                        return false;
                }
            }

            return true;
        }

        private static string NextToken(X509NameTokenizer tokenizer)
        {
            return tokenizer.NextToken() ?? throw new ArgumentException("badly formatted directory string");
        }

        private static string NextToken(X509NameTokenizer tokenizer, bool expectMoreTokens)
        {
            string token = tokenizer.NextToken();
            if (token == null || tokenizer.HasMoreTokens() != expectMoreTokens)
                throw new ArgumentException("badly formatted directory string");

            return token;
        }

        private static string StripInternalSpaces(string str)
        {
            StringBuilder res = new StringBuilder();

            if (str.Length != 0)
            {
                char c1 = str[0];

                res.Append(c1);

                for (int k = 1; k < str.Length; k++)
                {
                    char c2 = str[k];
                    if (!(c1 == ' ' && c2 == ' '))
                    {
                        res.Append(c2);
                    }
                    c1 = c2;
                }
            }

            return res.ToString();
        }
    }
}
