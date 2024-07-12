using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using Org.BouncyCastle.Asn1;
using Org.BouncyCastle.Asn1.Cms;

namespace Org.BouncyCastle.asn1.dvcs
{
    /**
    * <pre>
    *     DVCSTime ::= CHOICE  {
    *         genTime                      GeneralizedTime,
    *         timeStampToken               ContentInfo
    *     }
    * </pre>
    */
    public class DVCSTime : Asn1Object, IAsn1Choice
    {
        private readonly Asn1GeneralizedTime genTime;
        private readonly ContentInfo timeStampToken;


        public DVCSTime(DateTime time) : this(new Asn1GeneralizedTime(time))
        {

        }

        public DVCSTime(Asn1GeneralizedTime genTime)
        {
            this.genTime = genTime;
            this.timeStampToken = null;
        }

        public DVCSTime(ContentInfo timeStampToken)
        {
            this.genTime = null;
            this.timeStampToken = timeStampToken;
        }


        public static DVCSTime GetInstance(Object obj)
        {
            if (obj is DVCSTime)
            {
                return (DVCSTime)obj;
            }
            else if (obj is Asn1GeneralizedTime)
            {
                return new DVCSTime(Asn1GeneralizedTime.GetInstance(obj));
            }
            else if (obj != null)
            {
                return new DVCSTime(ContentInfo.GetInstance(obj));
            }

            return null;
        }

        public static DVCSTime GetInstance(
            Asn1TaggedObject obj,
            bool expl)
        {
            if (!expl)
            {
                throw new ArgumentException("choice item must be explicitly tagged");
            }

            return GetInstance(Asn1TaggedObject.GetInstance(obj, Asn1Tags.ContextSpecific).GetExplicitBaseObject()); 
        }

        public Asn1Object ToASN1Primitive()
        {
            if (genTime != null)
            {
                return genTime;
            }
            else
            {
                return timeStampToken.ToAsn1Object();
            }
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

        public Asn1GeneralizedTime GetGenTime()
        {
            return genTime;
        }

        public ContentInfo GetTimeStampToken()
        {
            return timeStampToken;
        }

        public override string ToString()
        {
            if (genTime != null)
            {
                return genTime.ToString();
            }
            else
            {
                return timeStampToken.ToString();
            }
        }
    }
}
