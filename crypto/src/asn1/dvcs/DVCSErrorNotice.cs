using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using Org.BouncyCastle.Asn1;
using Org.BouncyCastle.Asn1.Cmp;
using Org.BouncyCastle.Asn1.X509;

namespace Org.BouncyCastle.asn1.dvcs
{

 /**
 * <pre>
 *     DVCSErrorNotice ::= SEQUENCE {
 *         transactionStatus           PKIStatusInfo ,
 *         transactionIdentifier       GeneralName OPTIONAL
 *     }
 * </pre>
 */
    public class DVCSErrorNotice :Asn1Object
    {
        private PkiStatusInfo transactionStatus;
        private GeneralName transactionIdentifier;


        public DVCSErrorNotice(PkiStatusInfo status):this(status , null)
        {
           
        }

        public DVCSErrorNotice(PkiStatusInfo status, GeneralName transactionIdentifier)
        {
            this.transactionStatus = status;
            this.transactionIdentifier = transactionIdentifier;
        }

        private DVCSErrorNotice(Asn1Sequence seq)
        {
            this.transactionStatus = PkiStatusInfo.GetInstance(seq[0]);
            if (seq.Count > 1)
            {
                this.transactionIdentifier = GeneralName.GetInstance(seq[1]);
            }
        }

        public static DVCSErrorNotice GetInstance(Object obj)
        {
            if (obj is DVCSErrorNotice)
            {
                return (DVCSErrorNotice)obj;
            }
            else if (obj != null)
            {
                return new DVCSErrorNotice(Asn1Sequence.GetInstance(obj));
            }

            return null;
        }

        public static DVCSErrorNotice GetInstance(
            Asn1TaggedObject obj,
            bool explicited)
        {
            return GetInstance(Asn1Sequence.GetInstance(obj, explicited));
        }


        public Asn1Object ToASN1Primitive()
        {
            Asn1EncodableVector v = new Asn1EncodableVector(2);
            v.Add(transactionStatus);
            if (transactionIdentifier != null)
            {
                v.Add(transactionIdentifier);
            }
            return new DerSequence(v);
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

        public override string ToString()
        {
            return "DVCSErrorNotice {\n" +
                   "transactionStatus: " + transactionStatus + "\n" +
                   (transactionIdentifier != null ? "transactionIdentifier: " + transactionIdentifier + "\n" : "") +
                   "}\n";
        }

        public PkiStatusInfo GetTransactionStatus()
        {
            return transactionStatus;
        }

        public GeneralName GetTransactionIdentifier()
        {
            return transactionIdentifier;
        }

    }
}
