using System;

namespace Org.BouncyCastle.Asn1
{
    internal class DLSet
        : DerSet
    {
        internal static new readonly DLSet Empty = new DLSet();

        internal static new DLSet FromVector(Asn1EncodableVector elementVector)
        {
            return elementVector.Count < 1 ? Empty : new DLSet(elementVector);
        }

        private int m_contentsLengthDL = -1;

        /**
         * create an empty set
         */
        internal DLSet()
            : base()
        {
        }

        /**
         * create a set containing one object
         */
        internal DLSet(Asn1Encodable element)
            : base(element)
        {
        }

        internal DLSet(params Asn1Encodable[] elements)
            : base(elements, false)
        {
        }

        /**
         * create a set containing a vector of objects.
         */
        internal DLSet(Asn1EncodableVector elementVector)
            : base(elementVector, false)
        {
        }

        internal DLSet(bool isSorted, Asn1Encodable[] elements)
            : base(isSorted, elements)
        {
        }

        internal override int EncodedLength(int encoding, bool withID)
        {
            if (Asn1OutputStream.EncodingDer == encoding)
                return base.EncodedLength(encoding, withID);

            // TODO[asn1] Force DL encoding when supported
            //encoding = Asn1OutputStream.EncodingDL;

            int count = elements.Length;
            int contentsLength = 0;

            for (int i = 0; i < count; ++i)
            {
                Asn1Object asn1Object = elements[i].ToAsn1Object();
                contentsLength += asn1Object.EncodedLength(encoding, true);
            }

            return Asn1OutputStream.GetLengthOfEncodingDL(withID, contentsLength);
        }

        internal override void Encode(Asn1OutputStream asn1Out, bool withID)
        {
            if (Asn1OutputStream.EncodingDer == asn1Out.Encoding)
            {
                base.Encode(asn1Out, withID);
                return;
            }

            // TODO[asn1] Force DL encoding when supported
            //asn1Out = asn1Out.GetDLSubStream();

            asn1Out.WriteIdentifier(withID, Asn1Tags.Constructed | Asn1Tags.Set);

            int count = elements.Length;
            if (m_contentsLengthDL >= 0 || count > 16)
            {
                asn1Out.WriteDL(GetContentsLengthDL());

                for (int i = 0; i < count; ++i)
                {
                    Asn1Object asn1Object = elements[i].ToAsn1Object();
                    asn1Object.Encode(asn1Out, true);
                }
            }
            else
            {
                int contentsLength = 0;

                Asn1Object[] asn1Objects = new Asn1Object[count];
                for (int i = 0; i < count; ++i)
                {
                    Asn1Object asn1Object = elements[i].ToAsn1Object();
                    asn1Objects[i] = asn1Object;
                    contentsLength += asn1Object.EncodedLength(asn1Out.Encoding, true);
                }

                this.m_contentsLengthDL = contentsLength;
                asn1Out.WriteDL(contentsLength);

                for (int i = 0; i < count; ++i)
                {
                    asn1Objects[i].Encode(asn1Out, true);
                }
            }
        }

        private int GetContentsLengthDL()
        {
            if (m_contentsLengthDL < 0)
            {
                // TODO[asn1] Use DL encoding when supported
                m_contentsLengthDL = CalculateContentsLength(Asn1OutputStream.EncodingBer);
            }
            return m_contentsLengthDL;
        }
    }
}
