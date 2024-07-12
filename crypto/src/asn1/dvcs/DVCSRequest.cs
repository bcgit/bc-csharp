using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using Org.BouncyCastle.Asn1;
using Org.BouncyCastle.Asn1.X509;

namespace Org.BouncyCastle.asn1.dvcs
{

    /**
     * <pre>
     *     DVCSRequest ::= SEQUENCE  {
     *         requestInformation         DVCSRequestInformation,
     *         data                       Data,
     *         transactionIdentifier      GeneralName OPTIONAL
     *     }
     * </pre>
     */
    public class DVCSRequest : Asn1Object
    {
        private DVCSRequestInformation requestInformation;
        private Data data;
        private GeneralName transactionIdentifier;


        public DVCSRequest(DVCSRequestInformation requestInformation, Data data) : this(requestInformation, data, null) { }

        public DVCSRequest(DVCSRequestInformation requestInformation, Data data, GeneralName transactionIdentifier)
        {
            this.requestInformation = requestInformation;
            this.data = data;
            this.transactionIdentifier = transactionIdentifier;
        }

        private DVCSRequest(Asn1Sequence seq)
        {
            requestInformation = DVCSRequestInformation.GetInstance(seq[0]);
            data = Data.GetInstance(seq[1]);
            if (seq.Count > 2)
            {
                transactionIdentifier = GeneralName.GetInstance(seq[2]);
            }
        }


        public static DVCSRequest GetInstance(Object obj)
        {
            if (obj is DVCSRequest)
            {
                return (DVCSRequest)obj;
            }
            else if (obj != null)
            {
                return new DVCSRequest(Asn1Sequence.GetInstance(obj));
            }

            return null;
        }

        public static DVCSRequest GetInstance(
            Asn1TaggedObject obj,
            bool expl)
        {
            return GetInstance(Asn1Sequence.GetInstance(obj, expl));
        }


        public Asn1Object ToASN1Primitive()
        {
            Asn1EncodableVector v = new Asn1EncodableVector(3);
            v.Add(requestInformation);
            v.Add(data);
            if (transactionIdentifier != null)
            {
                v.Add(transactionIdentifier);
            }
            return new DerSequence(v);
        }

        public override string ToString()
        {
            return "DVCSRequest {\n" +
                   "requestInformation: " + requestInformation + "\n" +
                   "data: " + data + "\n" +
                   (transactionIdentifier != null ? "transactionIdentifier: " + transactionIdentifier + "\n" : "") +
                   "}\n";
        }
        public Data GetData()
        {
            return data;
        }
        public DVCSRequestInformation GetRequestInformation()
        {
            return requestInformation;
        }

        public GeneralName GetTransactionIdentifier()
        {
            return transactionIdentifier;
        }

        internal override IAsn1Encoding GetEncoding(int encoding)
        {
            return ToASN1Primitive().GetEncoding(encoding); 
        }

        internal override IAsn1Encoding GetEncodingImplicit(int encoding, int tagClass, int tagNo)
        {
            return ToASN1Primitive().GetEncodingImplicit(encoding, tagClass, tagNo); 
        }

        internal override DerEncoding GetEncodingDer()
        {
            return ToASN1Primitive().GetEncodingDer(); 
        }

        internal override DerEncoding GetEncodingDerImplicit(int tagClass, int tagNo)
        {
            return ToASN1Primitive().GetEncodingDerImplicit(tagClass, tagNo); 
        }

        protected override bool Asn1Equals(Asn1Object asn1Object)
        {
            return ToASN1Primitive().CallAsn1Equals(asn1Object); 
        }

        protected override int Asn1GetHashCode()
        {
            return ToASN1Primitive().CallAsn1GetHashCode();
        }
    }
}
