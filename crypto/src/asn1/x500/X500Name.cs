using System;
using Org.BouncyCastle.Asn1.Crmf;
using Org.BouncyCastle.Asn1.X500.Style;

namespace Org.BouncyCastle.Asn1.X500
{

    /**
     * <pre>
     *     Name ::= CHOICE {
     *                       RDNSequence }
     *
     *     RDNSequence ::= SEQUENCE OF RelativeDistinguishedName
     *
     *     RelativeDistinguishedName ::= SET SIZE (1..MAX) OF AttributeTypeAndValue
     *
     *     AttributeTypeAndValue ::= SEQUENCE {
     *                                   type  OBJECT IDENTIFIER,
     *                                   value ANY }
     * </pre>
     */
    public class X500Name : Asn1Encodable, IAsn1Choice
    {
        private static X500NameStyle defaultStyle = BCStyle.INSTANCE;

        private bool isHashCodeCalculated;
        private int hashCodeValue;

        private X500NameStyle style;
        private RDN[] rdns;

        public X500Name(X500NameStyle style, X500Name name)
        {
            this.rdns = name.rdns;
            this.style = style;
        }

        /**
         * Return a X500Name based on the passed in tagged object.
         * 
         * @param obj tag object holding name.
         * @param explicit true if explicitly tagged false otherwise.
         * @return the X500Name
         */
        public static X500Name GetInstance(
            Asn1TaggedObject obj,
            bool isExplicit)
        {
            // must be true as choice item
            return GetInstance(Asn1Sequence.GetInstance(obj, true));
        }

        public static X500Name GetInstance(object obj)
        {
            if (obj is X500Name)
            {
                return (X500Name)obj;
            }
            else if (obj != null)
            {
                return new X500Name(Asn1Sequence.GetInstance(obj));
            }

            return null;
        }

        public static X500Name GetInstance(
            X500NameStyle style,
            object obj)
        {
            if (obj is X500Name)
            {
                return GetInstance(style, ((X500Name)obj).ToAsn1Object());
            }
            else if (obj != null)
            {
                return new X500Name(style, Asn1Sequence.GetInstance(obj));
            }

            return null;
        }

        /**
         * Constructor from ASN1Sequence
         *
         * the principal will be a list of constructed sets, each containing an (OID, String) pair.
         */
        private X500Name(Asn1Sequence seq)
            : this(defaultStyle, seq)
        {

        }

        private X500Name(
            X500NameStyle style,
            Asn1Sequence seq)
        {
            this.style = style;
            this.rdns = new RDN[seq.Count];

            int index = 0;            

            foreach (var e in seq)
            {
                rdns[index++] = RDN.GetInstance(e);
            }
        }

        public X500Name(
            RDN[] rDNs)
            : this(defaultStyle, rDNs)
        {
            
        }

        public X500Name(
            X500NameStyle style,
            RDN[] rDNs)
        {
            this.rdns = rDNs;
            this.style = style;
        }

        public X500Name(
            String dirName)
            : this(defaultStyle, dirName)
        {
            
        }

        public X500Name(
            X500NameStyle style,
            String dirName)
            : this(style.fromString(dirName))
        {
            this.style = style;
        }

        /**
         * return an array of RDNs in structure order.
         *
         * @return an array of RDN objects.
         */
        public RDN[] getRDNs()
        {
            RDN[] tmp = new RDN[this.rdns.Length];

            Array.Copy(rdns, 0, tmp, 0, tmp.Length);

            return tmp;
        }

        /**
         * return an array of OIDs contained in the attribute type of each RDN in structure order.
         *
         * @return an array, possibly zero length, of ASN1ObjectIdentifiers objects.
         */
        public DerObjectIdentifier[] getAttributeTypes()
        {
            int count = 0;

            for (int i = 0; i != rdns.Length; i++)
            {
                RDN rdn = rdns[i];

                count += rdn.Count;
            }

            DerObjectIdentifier[] res = new DerObjectIdentifier[count];

            count = 0;

            for (int i = 0; i != rdns.Length; i++)
            {
                RDN rdn = rdns[i];

                if (rdn.isMultiValued())
                {
                    AttributeTypeAndValue[] attr = rdn.GetTypesAndValues();
                    for (int j = 0; j != attr.Length; j++)
                    {
                        res[count++] = attr[j].Type;
                    }
                }
                else if (rdn.Count != 0)
                {
                    res[count++] = rdn.GetFirst().Type;
                }
            }

            return res;
        }

        /**
         * return an array of RDNs containing the attribute type given by OID in structure order.
         *
         * @param attributeType the type OID we are looking for.
         * @return an array, possibly zero length, of RDN objects.
         */
        public RDN[] getRDNs(DerObjectIdentifier attributeType)
        {
            RDN[] res = new RDN[rdns.Length];
            int count = 0;

            for (int i = 0; i != rdns.Length; i++)
            {
                RDN rdn = rdns[i];

                if (rdn.isMultiValued())
                {
                    AttributeTypeAndValue[] attr = rdn.GetTypesAndValues();
                    for (int j = 0; j != attr.Length; j++)
                    {
                        if (attr[j].Type.Equals(attributeType))
                        {
                            res[count++] = rdn;
                            break;
                        }
                    }
                }
                else
                {
                    if (rdn.GetFirst().Type.Equals(attributeType))
                    {
                        res[count++] = rdn;
                    }
                }
            }

            RDN[] tmp = new RDN[count];

            Array.Copy(res, 0, tmp, 0, tmp.Length);

            return tmp;
        }

        public override Asn1Object ToAsn1Object()
        {
            return new DerSequence(rdns);
        }

        //public override int Asn1GetHashCode()
        //{
        //    if (isHashCodeCalculated)
        //    {
        //        return hashCodeValue;
        //    }

        //    isHashCodeCalculated = true;

        //    hashCodeValue = style.calculateHashCode(this);

        //    return hashCodeValue;
        //}

        ///**
        // * test for equality - note: case is ignored.
        // */

        //protected override bool Asn1Equals(Asn1Object obj)
        //{            
        //    if (obj == this)
        //    {
        //        return true;
        //    }

        //    if (!(obj is X500Name || obj is Asn1Sequence))
        //    {
        //        return false;
        //    }

        //    Asn1Object derO = ((Asn1Encodable)obj).ToAsn1Object();

        //    if (this.ToAsn1Object().Equals(derO))
        //    {
        //        return true;
        //    }

        //    try
        //    {
        //        return style.AreEqual(this, new X500Name(Asn1Sequence.GetInstance(((Asn1Encodable)obj).ToAsn1Object())));
        //    }
        //    catch (Exception e)
        //    {
        //        return false;
        //    }
        //}

        public override string ToString()
        {
            return style.ToString(this);
        }

        /**
         * Set the default style for X500Name construction.
         *
         * @param style  an X500NameStyle
         */
        public static X500NameStyle DefaultStyle
        {
            set
            {
                if (value == null)
                {
                    throw new ArgumentNullException("cannot set style to null");
                }

                defaultStyle = value;
            }
            get
            {
                return defaultStyle;
            }
        }
    }

}