using System;
using System.IO;

namespace Org.BouncyCastle.Asn1
{
	public class Asn1StreamParser
	{
		private readonly Stream _in;
		private readonly int _limit;

        private readonly byte[][] tmpBuffers;

        public Asn1StreamParser(Stream input)
			: this(input, Asn1InputStream.FindLimit(input))
		{
		}

        public Asn1StreamParser(byte[] encoding)
            : this(new MemoryStream(encoding, false), encoding.Length)
        {
        }

        public Asn1StreamParser(Stream input, int limit)
            : this(input, limit, new byte[16][])
		{
        }

        internal Asn1StreamParser(Stream input, int limit, byte[][] tmpBuffers)
        {
            if (!input.CanRead)
                throw new ArgumentException("Expected stream to be readable", "input");

            this._in = input;
            this._limit = limit;
            this.tmpBuffers = tmpBuffers;
        }

        internal IAsn1Convertible ReadIndef(int tagNo)
		{
			// Note: INDEF => CONSTRUCTED

			// TODO There are other tags that may be constructed (e.g. BIT_STRING)
			switch (tagNo)
			{
			case Asn1Tags.External:
				return new DerExternalParser(this);
			case Asn1Tags.OctetString:
				return new BerOctetStringParser(this);
			case Asn1Tags.Sequence:
				return new BerSequenceParser(this);
			case Asn1Tags.Set:
				return new BerSetParser(this);
			default:
				throw new Asn1Exception("unknown BER object encountered: 0x" + tagNo.ToString("X"));
			}
		}

		internal IAsn1Convertible ReadImplicit(bool constructed, int tagNo)
		{
			if (_in is IndefiniteLengthInputStream)
			{
				if (!constructed)
					throw new IOException("indefinite-length primitive encoding encountered");

				return ReadIndef(tagNo);
			}

			if (constructed)
			{
				switch (tagNo)
				{
				case Asn1Tags.Set:
					return new DerSetParser(this);
				case Asn1Tags.Sequence:
					return new DerSequenceParser(this);
				case Asn1Tags.OctetString:
					return new BerOctetStringParser(this);
				}
			}
			else
			{
				switch (tagNo)
				{
				case Asn1Tags.Set:
					throw new Asn1Exception("sequences must use constructed encoding (see X.690 8.9.1/8.10.1)");
				case Asn1Tags.Sequence:
					throw new Asn1Exception("sets must use constructed encoding (see X.690 8.11.1/8.12.1)");
				case Asn1Tags.OctetString:
					return new DerOctetStringParser((DefiniteLengthInputStream)_in);
				}
			}

			throw new Asn1Exception("implicit tagging not implemented");
		}

		internal Asn1Object ReadTaggedObject(int tagClass, int tagNo, bool constructed)
		{
            if (!constructed)
			{
                // Note: !CONSTRUCTED => IMPLICIT
                byte[] contentsOctets = ((DefiniteLengthInputStream)_in).ToArray();
                return Asn1TaggedObject.CreatePrimitive(tagClass, tagNo, contentsOctets);
			}

            bool isIL = (_in is IndefiniteLengthInputStream);
            Asn1EncodableVector contentsElements = ReadVector();
            return Asn1TaggedObject.CreateConstructed(tagClass, tagNo, isIL, contentsElements);
		}

		public virtual IAsn1Convertible ReadObject()
		{
			int tagHdr = _in.ReadByte();
			if (tagHdr == -1)
				return null;

			// turn off looking for "00" while we resolve the tag
			Set00Check(false);

			//
			// calculate tag number
			//
			int tagNo = Asn1InputStream.ReadTagNumber(_in, tagHdr);

			bool isConstructed = (tagHdr & Asn1Tags.Constructed) != 0;

			//
			// calculate length
			//
			int length = Asn1InputStream.ReadLength(_in, _limit,
                tagNo == Asn1Tags.OctetString || tagNo == Asn1Tags.Sequence || tagNo == Asn1Tags.Set ||
                tagNo == Asn1Tags.External);

			if (length < 0) // indefinite-length method
			{
				if (!isConstructed)
					throw new IOException("indefinite-length primitive encoding encountered");

                IndefiniteLengthInputStream indIn = new IndefiniteLengthInputStream(_in, _limit);
                Asn1StreamParser sp = new Asn1StreamParser(indIn, _limit, tmpBuffers);

                int tagClass = tagHdr & Asn1Tags.Private;
                if (0 != tagClass)
                {
                    if (Asn1Tags.Application == tagClass)
                        return new BerApplicationSpecificParser(tagNo, sp);

                    return new BerTaggedObjectParser(tagClass, tagNo, true, sp);
                }

                return sp.ReadIndef(tagNo);
			}
			else
			{
				DefiniteLengthInputStream defIn = new DefiniteLengthInputStream(_in, length, _limit);

                int tagClass = tagHdr & Asn1Tags.Private;
                if (0 != tagClass)
                {
                    Asn1StreamParser sub = new Asn1StreamParser(defIn, defIn.Remaining, tmpBuffers);

                    if (Asn1Tags.Application == tagClass)
                        return (DLApplicationSpecific)sub.ReadTaggedObject(tagClass, tagNo, isConstructed);

                    return new BerTaggedObjectParser(tagClass, tagNo, isConstructed, sub);
                }

                if (!isConstructed)
                {
                    // Some primitive encodings can be handled by parsers too...
                    switch (tagNo)
                    {
                    case Asn1Tags.OctetString:
                        return new DerOctetStringParser(defIn);
                    }

                    try
                    {
                        return Asn1InputStream.CreatePrimitiveDerObject(tagNo, defIn, tmpBuffers);
                    }
                    catch (ArgumentException e)
                    {
                        throw new Asn1Exception("corrupted stream detected", e);
                    }
                }

                Asn1StreamParser sp = new Asn1StreamParser(defIn, defIn.Remaining, tmpBuffers);

                // TODO There are other tags that may be constructed (e.g. BitString)
                switch (tagNo)
				{
				case Asn1Tags.OctetString:
					return new BerOctetStringParser(sp);
				case Asn1Tags.Sequence:
					return new DerSequenceParser(sp);
				case Asn1Tags.Set:
					return new DerSetParser(sp);
				case Asn1Tags.External:
					return new DerExternalParser(sp);
				default:
                    throw new IOException("unknown tag " + tagNo + " encountered");
                }
			}
		}

		private void Set00Check(
			bool enabled)
		{
			if (_in is IndefiniteLengthInputStream)
			{
				((IndefiniteLengthInputStream) _in).SetEofOn00(enabled);
			}
		}

        internal Asn1EncodableVector ReadVector()
        {
            IAsn1Convertible obj = ReadObject();
            if (null == obj)
                return new Asn1EncodableVector(0);

            Asn1EncodableVector v = new Asn1EncodableVector();
            do
            {
                v.Add(obj.ToAsn1Object());
            }
            while ((obj = ReadObject()) != null);
            return v;
        }
	}
}
