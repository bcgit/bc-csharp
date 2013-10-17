namespace Org.BouncyCastle.Asn1.X500
{
    /**
     * It turns out that the number of standard ways the fields in a DN should be 
     * encoded into their ASN.1 counterparts is rapidly approaching the
     * number of machines on the internet. By default the X500Name class
     * will produce UTF8Strings in line with the current recommendations (RFC 3280).
     */
    public interface X500NameStyle
    {
        /**
         * Convert the passed in String value into the appropriate ASN.1
         * encoded object.
         * 
         * @param oid the OID associated with the value in the DN.
         * @param value the value of the particular DN component.
         * @return the ASN.1 equivalent for the value.
         */
        Asn1Encodable stringToValue(DerObjectIdentifier oid, string value);

        /**
         * Return the OID associated with the passed in name.
         *
         * @param attrName the string to match.
         * @return an OID
         */
        DerObjectIdentifier attrNameToOID(string attrName);

        /**
         * Return an array of RDN generated from the passed in String.
         * @param dirName  the String representation.
         * @return  an array of corresponding RDNs.
         */
        RDN[] fromString(string dirName);

        /**
         * Return true if the two names are equal.
         *
         * @param name1 first name for comparison.
         * @param name2 second name for comparison.
         * @return true if name1 = name 2, false otherwise.
         */
        bool areEqual(X500Name name1, X500Name name2);

        /**
         * Calculate a hashCode for the passed in name.
         *
         * @param name the name the hashCode is required for.
         * @return the calculated hashCode.
         */
        int calculateHashCode(X500Name name);

        /**
         * Convert the passed in X500Name to a String.
         * @param name the name to convert.
         * @return a String representation.
         */
        string ToString(X500Name name);

        /**
         * Return the display name for toString() associated with the OID.
         *
         * @param oid  the OID of interest.
         * @return the name displayed in toString(), null if no mapping provided.
         */
        string oidToDisplayName(DerObjectIdentifier oid);

        /**
         * Return the acceptable names in a String DN that map to OID.
         *
         * @param oid  the OID of interest.
         * @return an array of String aliases for the OID, zero length if there are none.
         */
        string[] oidToAttrNames(DerObjectIdentifier oid);
    }

}