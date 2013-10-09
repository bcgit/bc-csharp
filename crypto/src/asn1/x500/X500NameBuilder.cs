using Org.BouncyCastle.Asn1.X500.Style;
using System.Collections;
using Org.BouncyCastle.Asn1.Crmf;
using Org.BouncyCastle.Utilities;

namespace Org.BouncyCastle.Asn1.X500
{

    public class X500NameBuilder
    {
        private X500NameStyle template;
        private IList rdns = Platform.CreateArrayList();

        public X500NameBuilder()
            : this(BCStyle.INSTANCE)
        {
            
        }

        public X500NameBuilder(X500NameStyle template)
        {
            this.template = template;
        }

        public X500NameBuilder addRDN(DerObjectIdentifier oid, string value)
        {
            this.addRDN(oid, template.stringToValue(oid, value));

            return this;
        }

        public X500NameBuilder addRDN(DerObjectIdentifier oid, Asn1Encodable value)
        {
            rdns.Add(new RDN(oid, value));

            return this;
        }

        public X500NameBuilder addRDN(AttributeTypeAndValue attrTAndV)
        {
            rdns.Add(new RDN(attrTAndV));

            return this;
        }

        public X500NameBuilder addMultiValuedRDN(DerObjectIdentifier[] oids, string[] values)
        {
            Asn1Encodable[] vals = new Asn1Encodable[values.Length];

            for (int i = 0; i != vals.Length; i++)
            {
                vals[i] = template.stringToValue(oids[i], values[i]);
            }

            return addMultiValuedRDN(oids, vals);
        }

        public X500NameBuilder addMultiValuedRDN(DerObjectIdentifier[] oids, Asn1Encodable[] values)
        {
            AttributeTypeAndValue[] avs = new AttributeTypeAndValue[oids.Length];

            for (int i = 0; i != oids.Length; i++)
            {
                avs[i] = new AttributeTypeAndValue(oids[i], values[i]);
            }

            return addMultiValuedRDN(avs);
        }

        public X500NameBuilder addMultiValuedRDN(AttributeTypeAndValue[] attrTAndVs)
        {
            rdns.Add(new RDN(attrTAndVs));

            return this;
        }

        public X500Name build()
        {
            RDN[] vals = new RDN[rdns.Count];

            for (int i = 0; i != vals.Length; i++)
            {
                vals[i] = (RDN)rdns[i];
            }

            return new X500Name(template, vals);
        }
    }
}