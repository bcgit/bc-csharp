using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using Org.BouncyCastle.Asn1;

namespace Org.BouncyCastle.asn1.dvcs
{
    /**
    * ServiceType ::= ENUMERATED { cpd(1), vsd(2), cpkc(3), ccpd(4) }
    */
    public class ServiceType : Asn1Object
    {
     /**
    * Identifier of CPD service (Certify Possession of Data).
    */
        public static  ServiceType CPD = new ServiceType(1);

        /**
         * Identifier of VSD service (Verify Signed Document).
         */
        public static  ServiceType VSD = new ServiceType(2);

        /**
         * Identifier of VPKC service (Verify Public Key Certificates (also referred to as CPKC)).
         */
        public static  ServiceType VPKC = new ServiceType(3);

        /**
         * Identifier of CCPD service (Certify Claim of Possession of Data).
         */
        public static  ServiceType CCPD = new ServiceType(4);


        private DerEnumerated value;

        public ServiceType(int value)
        {
            this.value = new DerEnumerated(value);
        }

        private ServiceType(DerEnumerated value)
        {
            this.value = value;
        }

        public static ServiceType GetInstance(Object obj)
        {
            if (obj is ServiceType)
            {
                return (ServiceType)obj;
            }
            else if (obj != null)
            {
                return new ServiceType(DerEnumerated.GetInstance(obj));
            }

            return null;
        }

        public static ServiceType GetInstance(
            Asn1TaggedObject obj,
            bool expl)
        {
            return GetInstance(DerEnumerated.GetInstance(obj, expl));
        }

        public Asn1Object ToASN1Primitive()
        {
            return value;
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
            int num = value.IntValueExact;
            return "" + num + (
                num == CPD.value.IntValueExact ? "(CPD)" :
                num == VSD.value.IntValueExact ? "(VSD)" :
                num == VPKC.value.IntValueExact ? "(VPKC)" :
                num == CCPD.value.IntValueExact ? "(CCPD)" :
                "?");
        }
    }
}
