using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using Org.BouncyCastle.Asn1;

namespace Org.BouncyCastle.asn1.dvcs
{
    /**
    * <pre>
    *     DVCSResponse ::= CHOICE
    *     {
    *         dvCertInfo         DVCSCertInfo ,
    *         dvErrorNote        [0] DVCSErrorNotice
    *     }
    * </pre>
    */
    public class DVCSResponse : Asn1Object, IAsn1Choice
    {
        private DVCSCertInfo dvCertInfo;
        private DVCSErrorNotice dvErrorNote;


        public DVCSCertInfo CertInfo
        {
            get { return dvCertInfo; }
        }

        public DVCSErrorNotice ErrorNotice
        {
            get { return dvErrorNote; }
        }

        public DVCSResponse(DVCSCertInfo dvCertInfo)
        {
            this.dvCertInfo = dvCertInfo;
        }

        public DVCSResponse(DVCSErrorNotice dvErrorNote)
        {
            this.dvErrorNote = dvErrorNote;
        }



        public static DVCSResponse GetInstance(Object obj)
        {
            if (obj == null || obj is DVCSResponse)
            {
                return (DVCSResponse)obj;
            }
            else
            {
                if (obj is byte[])
                {
                    try
                    {
                        return GetInstance(Asn1Object.FromByteArray((byte[])obj));
                    }
                    catch (IOException e)
                    {
                        throw new ArgumentException("failed to construct sequence from byte[]: " + e.Message);
                    }
                }
                if (obj is Asn1Sequence)
                {
                    DVCSCertInfo dvCertInfo = DVCSCertInfo.GetInstance(obj);

                    return new DVCSResponse(dvCertInfo);
                }
                if (obj is Asn1TaggedObject)
                {
                    Asn1TaggedObject t = Asn1TaggedObject.GetInstance(obj);
                    DVCSErrorNotice dvErrorNote = DVCSErrorNotice.GetInstance(t, false);

                    return new DVCSResponse(dvErrorNote);
                }
            }

            throw new ArgumentException("Couldn't convert from object to DVCSResponse: " + obj.GetType().Name);
        }

        public static DVCSResponse GetInstance(
            Asn1TaggedObject obj,
            bool expl)
        {
            return GetInstance(Asn1Sequence.GetInstance(obj, expl));
        }

        public Asn1Object ToASN1Primitive()
        {
            if (dvCertInfo != null)
            {
                return dvCertInfo.ToASN1Primitive();
            }
            else
            {
                return new DerTaggedObject(false, 0, dvErrorNote);
            }
        }

        public override string ToString()
        {
            if (dvCertInfo != null)
            {
                return "DVCSResponse {\ndvCertInfo: " + dvCertInfo.ToString() + "}\n";
            }
            else
            {
                return "DVCSResponse {\ndvErrorNote: " + dvErrorNote.ToString() + "}\n";
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
    }
}
