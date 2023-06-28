﻿using System;
using System.Collections.Generic;
using System.IO;
using System.Text;

using NUnit.Framework;

using Org.BouncyCastle.Math;
using Org.BouncyCastle.Utilities.Test;

namespace Org.BouncyCastle.Bcpg.OpenPgp.Tests
{
    [TestFixture]
    public class IgnoreMarkerPacketInCertificatesTest
        : SimpleTest
    {
        // [PUBLIC KEY, MARKER, USER-ID, SIGNATURE, SUBKEY, SIGNATURE]
        private static readonly string CERT_WITH_MARKER = "" +
            "-----BEGIN PGP PUBLIC KEY BLOCK-----\n" +
            "\n" +
            "xsDNBF2lnPIBDAC5cL9PQoQLTMuhjbYvb4Ncuuo0bfmgPRFywX53jPhoFf4Zg6mv\n" +
            "/seOXpgecTdOcVttfzC8ycIKrt3aQTiwOG/ctaR4Bk/t6ayNFfdUNxHWk4WCKzdz\n" +
            "/56fW2O0F23qIRd8UUJp5IIlN4RDdRCtdhVQIAuzvp2oVy/LaS2kxQoKvph/5pQ/\n" +
            "5whqsyroEWDJoSV0yOb25B/iwk/pLUFoyhDG9bj0kIzDxrEqW+7Ba8nocQlecMF3\n" +
            "X5KMN5kp2zraLv9dlBBpWW43XktjcCZgMy20SouraVma8Je/ECwUWYUiAZxLIlMv\n" +
            "9CurEOtxUw6N3RdOtLmYZS9uEnn5y1UkF88o8Nku890uk6BrewFzJyLAx5wRZ4F0\n" +
            "qV/yq36UWQ0JB/AUGhHVPdFf6pl6eaxBwT5GXvbBUibtf8YI2og5RsgTWtXfU7eb\n" +
            "SGXrl5ZMpbA6mbfhd0R8aPxWfmDWiIOhBufhMCvUHh1sApMKVZnvIff9/0Dca3wb\n" +
            "vLIwa3T4CyshfT0AEQEAAcoDUEdQzSFCb2IgQmFiYmFnZSA8Ym9iQG9wZW5wZ3Au\n" +
            "ZXhhbXBsZT7CwQ4EEwEKADgCGwMFCwkIBwIGFQoJCAsCBBYCAwECHgECF4AWIQTR\n" +
            "pm4aI7GCyZgPeIz7/MgqAV5zMAUCXaWe+gAKCRD7/MgqAV5zMG9sC/9U2T3RrqEb\n" +
            "w533FPNfEflhEVRIZ8gDXKM8hU6cqqEzCmzZT6xYTe6sv4y+PJBGXJFXyhj0g6FD\n" +
            "kSyboM5litOcTupURObVqMgA/Y4UKERznm4fzzH9qek85c4ljtLyNufedoL2pp3v\n" +
            "kGtn7eD0QFRaLLmnxPKQ/TlZKdLE1G3u8Uot8QHicaR6GnAdc5UXQJE3BiV7jZuD\n" +
            "yWmZ1cUNwJkKL6oRtp+ZNDOQCrLNLecKHcgCqrpjSQG5oouba1I1Q6VlsP44dhA1\n" +
            "nkmLHtxlTOzpeHj4jnk1FaXmyasurrrI5CgU/L2Oi39DGKTH/A/cywDN4ZplIQ9z\n" +
            "R8enkbXquUZvFDe+Xz+6xRXtb5MwQyWODB3nHw85HocLwRoIN9WdQEI+L8a/56Au\n" +
            "Owhs8llkSuiITjR7r9SgKJC2WlAHl7E8lhJ3VDW3ELC56KH308d6mwOGZRAqIAKz\n" +
            "M1T5FGjMBhq7ZV0eqdEntBh3EcOIfj2M8rg1MzJv+0mHZOIjByawikbOwM0EXaWc\n" +
            "8gEMANYwv1xsYyunXYK0X1vY/rP1NNPvhLyLIE7NpK90YNBj+xS1ldGDbUdZqZee\n" +
            "f2xJe8gMQg05DoD1DF3GipZ0Ies65beh+d5hegb7N4pzh0LzrBrVNHar29b5ExdI\n" +
            "7i4iYD5TO6Vr/qTUOiAN/byqELEzAb+L+b2DVz/RoCm4PIp1DU9ewcc2WB38Ofqu\n" +
            "t3nLYA5tqJ9XvAiEQme+qAVcM3ZFcaMt4I4dXhDZZNg+D9LiTWcxdUPBleu8iwDR\n" +
            "jAgyAhPzpFp+nWoqWA81uIiULWD1Fj+IVoY3ZvgivoYOiEFBJ9lbb4teg9m5UT/A\n" +
            "aVDTWuHzbspVlbiVe+qyB77C2daWzNyx6UYBPLOo4r0t0c91kbNE5lgjZ7xz6los\n" +
            "0N1U8vq91EFSeQJoSQ62XWavYmlCLmdNT6BNfgh4icLsT7Vr1QMX9jznJtTPxdXy\n" +
            "tSdHvpSpULsqJ016l0dtmONcK3z9mj5N5z0k1tg1AH970TGYOe2aUcSxIRDMXDOP\n" +
            "yzEfjwARAQABwsD2BBgBCgAgFiEE0aZuGiOxgsmYD3iM+/zIKgFeczAFAl2lnPIC\n" +
            "GwwACgkQ+/zIKgFeczDp/wv/boLfh2SMF99PMyPkF3Obwy0Xrs5id4nhNAzDv7jU\n" +
            "gvitVxIqEiGT/dR3mSdpG0/Z5/X7kXrqH39E9A4nn628HCEEBxRZK6kqdSt1VplB\n" +
            "qdia1LFxVXY8v35ASI03e3OW6FpY7/+sALEn4r9ldCUjPBBVOk2F8bMBoxVX3Ol/\n" +
            "e7STXiK1y/pqUpjz6stm87XAgh5FkuZTS1kMPke1YO9RXusgUjVa6gtv4pmBtifc\n" +
            "5aMI8dV1Ot1nYKqdlsbdJfDprAf1vNEtX0ReRuEgx7PR14JV16j7AUWSWHz/lUrZ\n" +
            "vS+T/7CownF+lrWUe8kuhvM4/1++uzCyv3YwDb6T3TVZ4hJHuoTNwjQV2DwDIUAT\n" +
            "FoQrpXKM/tJcYvC9+KzDfg7G5mveqbHVK5+7i2gfdesHtAk3xfKqpuwbFQIGpaJ/\n" +
            "1FIrjGPNFN7nqI96JIkk4hyIw/2LaV0j4qAvJzJ4O8agGPQcIs7eBVoF7i5tWuPk\n" +
            "qOFfY9U0Ql3ddlHNpdkTZoAx\n" +
            "=6mfA\n" +
            "-----END PGP PUBLIC KEY BLOCK-----";

		public override string Name
		{
			get { return "IgnoreMarkerPacketInCertificatesTest"; }
		}

        public override void PerformTest()
        {
            ArmoredInputStream armorIn = new ArmoredInputStream(
                new MemoryStream(Encoding.UTF8.GetBytes(CERT_WITH_MARKER), false));
            PgpObjectFactory objectFactory = new PgpObjectFactory(armorIn);

            PgpPublicKeyRing certificate = (PgpPublicKeyRing)objectFactory.NextPgpObject();
            IsEquals("Bob Babbage <bob@openpgp.example>", First(certificate.GetPublicKey().GetUserIds()));
            var publicKeys = certificate.GetPublicKeys();
            var publicKeyEnum = publicKeys.GetEnumerator();
            IsTrue(publicKeyEnum.MoveNext());
            PgpPublicKey primaryKey = (PgpPublicKey)publicKeyEnum.Current;
            IsEquals(new BigInteger("FBFCC82A015E7330", 16).LongValue, primaryKey.KeyId);
            var signatures = primaryKey.GetSignatures();
            IsEquals(1, Count(signatures));

            IsTrue(publicKeyEnum.MoveNext());
            PgpPublicKey subkey = (PgpPublicKey)publicKeyEnum.Current;
            IsEquals(new BigInteger("7C2FAA4DF93C37B2", 16).LongValue, subkey.KeyId);
            signatures = subkey.GetSignatures();
            IsEquals(1, Count(signatures));
        }

		[Test]
		public void TestFunction()
		{
			string resultText = Perform().ToString();

			Assert.AreEqual(Name + ": Okay", resultText);
		}

        private int Count<T>(IEnumerable<T> e)
        {
            int count = 0;
            foreach (T t in e)
            {
                ++count;
            }
            return count;
        }

        private T First<T>(IEnumerable<T> e)
        {
            var enumerator = e.GetEnumerator();
            IsTrue(enumerator.MoveNext());
            return enumerator.Current;
        }
    }
}
