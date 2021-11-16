using System;

namespace Org.BouncyCastle.Asn1
{
    internal class DLSequence
        : DerSequence
    {
        internal static new readonly DLSequence Empty = new DLSequence();

        internal static new DLSequence FromVector(Asn1EncodableVector elementVector)
        {
            return elementVector.Count < 1 ? Empty : new DLSequence(elementVector);
        }

        private int m_contentsLengthDL = -1;

        /**
		 * create an empty sequence
		 */
        internal DLSequence()
            : base()
        {
        }

        /**
		 * create a sequence containing one object
		 */
        internal DLSequence(Asn1Encodable element)
            : base(element)
        {
        }

        internal DLSequence(params Asn1Encodable[] elements)
            : base(elements)
        {
        }

        /**
		 * create a sequence containing a vector of objects.
		 */
        internal DLSequence(Asn1EncodableVector elementVector)
            : base(elementVector)
        {
        }

        internal DLSequence(Asn1Encodable[] elements, bool clone)
            : base(elements, clone)
        {
        }

        internal override int EncodedLength(int encoding, bool withID)
        {
            if (Asn1OutputStream.EncodingDer == encoding)
                return base.EncodedLength(encoding, withID);

            return Asn1OutputStream.GetLengthOfEncodingDL(withID, GetContentsLengthDL());
        }

        internal override void Encode(Asn1OutputStream asn1Out, bool withID)
        {
            if (Asn1OutputStream.EncodingDer == asn1Out.Encoding)
            {
                base.Encode(asn1Out, withID);
                return;
            }

            // TODO[asn1] Use DL encoding when supported
            //asn1Out = asn1Out.GetDLSubStream();

            asn1Out.WriteIdentifier(withID, Asn1Tags.Constructed | Asn1Tags.Sequence);

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

        internal override Asn1Set ToAsn1Set()
        {
            return new DLSet(false, elements);
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
