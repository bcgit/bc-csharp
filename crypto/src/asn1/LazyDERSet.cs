using System;
using System.Collections;

namespace Org.BouncyCastle.Asn1
{
    internal class LazyDerSet
        : DerSet
    {
        private byte[] encoded;

        internal LazyDerSet(byte[] encoded)
            : base()
        {
            if (null == encoded)
                throw new ArgumentNullException("encoded");

            this.encoded = encoded;
        }

        private void Parse()
        {
            lock (this)
            {
                if (encoded != null)
                {
                    Asn1InputStream e = new LazyAsn1InputStream(encoded);
                    Asn1EncodableVector v = e.ReadVector();

                    this.elements = v.TakeElements();
                    this.encoded = null;
                }
            }
        }

        public override Asn1Encodable this[int index]
        {
            get
            {
                Parse();

                return base[index];
            }
        }

        public override IEnumerator GetEnumerator()
        {
            Parse();

            return base.GetEnumerator();
        }

        public override int Count
        {
            get
            {
                Parse();

                return base.Count;
            }
        }

        internal override int EncodedLength(bool withID)
        {
            lock (this)
            {
                if (encoded == null)
                {
                    return base.EncodedLength(withID);
                }
                else
                {
                    return Asn1OutputStream.GetLengthOfEncodingDL(withID, encoded.Length);
                }
            }
        }

        internal override void Encode(Asn1OutputStream asn1Out, bool withID)
        {
            lock (this)
            {
                if (encoded == null)
                {
                    base.Encode(asn1Out, withID);
                }
                else
                {
                    asn1Out.WriteEncodingDL(withID, Asn1Tags.Constructed | Asn1Tags.Set, encoded);
                }
            }
        }
    }
}
