using NUnit.Framework;
using Org.BouncyCastle.Security;
using Org.BouncyCastle.Utilities;
using Org.BouncyCastle.Utilities.Encoders;
using Org.BouncyCastle.Utilities.Test;
using System;
using System.IO;
using System.Linq;
using System.Runtime.Serialization.Formatters;
using System.Text;

namespace Org.BouncyCastle.Bcpg.OpenPgp.Tests
{
    [TestFixture]
    public class PgpInteroperabilityTestSuite
        : SimpleTest
    {
        // v4 EdDSA/ECDH key "Alice" from "OpenPGP Example Keys and Certificates"
        // https://www.ietf.org/archive/id/draft-bre-openpgp-samples-01.html#name-alices-ed25519-samples
        private static readonly byte[] alicePubkey = Base64.Decode(
            "mDMEXEcE6RYJKwYBBAHaRw8BAQdArjWwk3FAqyiFbFBKT4TzXcVBqPTB3gmzlC/U" +
            "b7O1u120JkFsaWNlIExvdmVsYWNlIDxhbGljZUBvcGVucGdwLmV4YW1wbGU+iJAE" +
            "ExYIADgCGwMFCwkIBwIGFQoJCAsCBBYCAwECHgECF4AWIQTrhbtfozp14V6UTmPy" +
            "MVUMT0fjjgUCXaWfOgAKCRDyMVUMT0fjjukrAPoDnHBSogOmsHOsd9qGsiZpgRnO" +
            "dypvbm+QtXZqth9rvwD9HcDC0tC+PHAsO7OTh1S1TC9RiJsvawAfCPaQZoed8gK4" +
            "OARcRwTpEgorBgEEAZdVAQUBAQdAQv8GIa2rSTzgqbXCpDDYMiKRVitCsy203x3s" +
            "E9+eviIDAQgHiHgEGBYIACAWIQTrhbtfozp14V6UTmPyMVUMT0fjjgUCXEcE6QIb" +
            "DAAKCRDyMVUMT0fjjlnQAQDFHUs6TIcxrNTtEZFjUFm1M0PJ1Dng/cDW4xN80fsn" +
            "0QEA22Kr7VkCjeAEC08VSTeV+QFsmz55/lntWkwYWhmvOgE=");

        private static readonly byte[] aliceSecretkey = Base64.Decode(
            "lFgEXEcE6RYJKwYBBAHaRw8BAQdArjWwk3FAqyiFbFBKT4TzXcVBqPTB3gmzlC/U" +
            "b7O1u10AAP9XBeW6lzGOLx7zHH9AsUDUTb2pggYGMzd0P3ulJ2AfvQ4RtCZBbGlj" +
            "ZSBMb3ZlbGFjZSA8YWxpY2VAb3BlbnBncC5leGFtcGxlPoiQBBMWCAA4AhsDBQsJ" +
            "CAcCBhUKCQgLAgQWAgMBAh4BAheAFiEE64W7X6M6deFelE5j8jFVDE9H444FAl2l" +
            "nzoACgkQ8jFVDE9H447pKwD6A5xwUqIDprBzrHfahrImaYEZzncqb25vkLV2arYf" +
            "a78A/R3AwtLQvjxwLDuzk4dUtUwvUYibL2sAHwj2kGaHnfICnF0EXEcE6RIKKwYB" +
            "BAGXVQEFAQEHQEL/BiGtq0k84Km1wqQw2DIikVYrQrMttN8d7BPfnr4iAwEIBwAA" +
            "/3/xFPG6U17rhTuq+07gmEvaFYKfxRB6sgAYiW6TMTpQEK6IeAQYFggAIBYhBOuF" +
            "u1+jOnXhXpROY/IxVQxPR+OOBQJcRwTpAhsMAAoJEPIxVQxPR+OOWdABAMUdSzpM" +
            "hzGs1O0RkWNQWbUzQ8nUOeD9wNbjE3zR+yfRAQDbYqvtWQKN4AQLTxVJN5X5AWyb" +
            "Pnn+We1aTBhaGa86AQ==");

        // v4 RSA-3072 key "Bob" from "OpenPGP Example Keys and Certificates"
        // https://www.ietf.org/archive/id/draft-bre-openpgp-samples-01.html#name-bobs-rsa-3072-samples
        private static readonly byte[] bobPubkey = Base64.Decode(
            "mQGNBF2lnPIBDAC5cL9PQoQLTMuhjbYvb4Ncuuo0bfmgPRFywX53jPhoFf4Zg6mv" +
            "/seOXpgecTdOcVttfzC8ycIKrt3aQTiwOG/ctaR4Bk/t6ayNFfdUNxHWk4WCKzdz" +
            "/56fW2O0F23qIRd8UUJp5IIlN4RDdRCtdhVQIAuzvp2oVy/LaS2kxQoKvph/5pQ/" +
            "5whqsyroEWDJoSV0yOb25B/iwk/pLUFoyhDG9bj0kIzDxrEqW+7Ba8nocQlecMF3" +
            "X5KMN5kp2zraLv9dlBBpWW43XktjcCZgMy20SouraVma8Je/ECwUWYUiAZxLIlMv" +
            "9CurEOtxUw6N3RdOtLmYZS9uEnn5y1UkF88o8Nku890uk6BrewFzJyLAx5wRZ4F0" +
            "qV/yq36UWQ0JB/AUGhHVPdFf6pl6eaxBwT5GXvbBUibtf8YI2og5RsgTWtXfU7eb" +
            "SGXrl5ZMpbA6mbfhd0R8aPxWfmDWiIOhBufhMCvUHh1sApMKVZnvIff9/0Dca3wb" +
            "vLIwa3T4CyshfT0AEQEAAbQhQm9iIEJhYmJhZ2UgPGJvYkBvcGVucGdwLmV4YW1w" +
            "bGU+iQHOBBMBCgA4AhsDBQsJCAcCBhUKCQgLAgQWAgMBAh4BAheAFiEE0aZuGiOx" +
            "gsmYD3iM+/zIKgFeczAFAl2lnvoACgkQ+/zIKgFeczBvbAv/VNk90a6hG8Od9xTz" +
            "XxH5YRFUSGfIA1yjPIVOnKqhMwps2U+sWE3urL+MvjyQRlyRV8oY9IOhQ5Esm6DO" +
            "ZYrTnE7qVETm1ajIAP2OFChEc55uH88x/anpPOXOJY7S8jbn3naC9qad75BrZ+3g" +
            "9EBUWiy5p8TykP05WSnSxNRt7vFKLfEB4nGkehpwHXOVF0CRNwYle42bg8lpmdXF" +
            "DcCZCi+qEbafmTQzkAqyzS3nCh3IAqq6Y0kBuaKLm2tSNUOlZbD+OHYQNZ5Jix7c" +
            "ZUzs6Xh4+I55NRWl5smrLq66yOQoFPy9jot/Qxikx/wP3MsAzeGaZSEPc0fHp5G1" +
            "6rlGbxQ3vl8/usUV7W+TMEMljgwd5x8POR6HC8EaCDfVnUBCPi/Gv+egLjsIbPJZ" +
            "ZEroiE40e6/UoCiQtlpQB5exPJYSd1Q1txCwueih99PHepsDhmUQKiACszNU+RRo" +
            "zAYau2VdHqnRJ7QYdxHDiH49jPK4NTMyb/tJh2TiIwcmsIpGuQGNBF2lnPIBDADW" +
            "ML9cbGMrp12CtF9b2P6z9TTT74S8iyBOzaSvdGDQY/sUtZXRg21HWamXnn9sSXvI" +
            "DEINOQ6A9QxdxoqWdCHrOuW3ofneYXoG+zeKc4dC86wa1TR2q9vW+RMXSO4uImA+" +
            "Uzula/6k1DogDf28qhCxMwG/i/m9g1c/0aApuDyKdQ1PXsHHNlgd/Dn6rrd5y2AO" +
            "baifV7wIhEJnvqgFXDN2RXGjLeCOHV4Q2WTYPg/S4k1nMXVDwZXrvIsA0YwIMgIT" +
            "86Rafp1qKlgPNbiIlC1g9RY/iFaGN2b4Ir6GDohBQSfZW2+LXoPZuVE/wGlQ01rh" +
            "827KVZW4lXvqsge+wtnWlszcselGATyzqOK9LdHPdZGzROZYI2e8c+paLNDdVPL6" +
            "vdRBUnkCaEkOtl1mr2JpQi5nTU+gTX4IeInC7E+1a9UDF/Y85ybUz8XV8rUnR76U" +
            "qVC7KidNepdHbZjjXCt8/Zo+Tec9JNbYNQB/e9ExmDntmlHEsSEQzFwzj8sxH48A" +
            "EQEAAYkBtgQYAQoAIBYhBNGmbhojsYLJmA94jPv8yCoBXnMwBQJdpZzyAhsMAAoJ" +
            "EPv8yCoBXnMw6f8L/26C34dkjBffTzMj5Bdzm8MtF67OYneJ4TQMw7+41IL4rVcS" +
            "KhIhk/3Ud5knaRtP2ef1+5F66h9/RPQOJ5+tvBwhBAcUWSupKnUrdVaZQanYmtSx" +
            "cVV2PL9+QEiNN3tzluhaWO//rACxJ+K/ZXQlIzwQVTpNhfGzAaMVV9zpf3u0k14i" +
            "tcv6alKY8+rLZvO1wIIeRZLmU0tZDD5HtWDvUV7rIFI1WuoLb+KZgbYn3OWjCPHV" +
            "dTrdZ2CqnZbG3SXw6awH9bzRLV9EXkbhIMez0deCVdeo+wFFklh8/5VK2b0vk/+w" +
            "qMJxfpa1lHvJLobzOP9fvrswsr92MA2+k901WeISR7qEzcI0Fdg8AyFAExaEK6Vy" +
            "jP7SXGLwvfisw34OxuZr3qmx1Sufu4toH3XrB7QJN8XyqqbsGxUCBqWif9RSK4xj" +
            "zRTe56iPeiSJJOIciMP9i2ldI+KgLycyeDvGoBj0HCLO3gVaBe4ubVrj5KjhX2PV" +
            "NEJd3XZRzaXZE2aAMQ==");

        private static readonly byte[] bobSecretkey = Base64.Decode(
            "lQVYBF2lnPIBDAC5cL9PQoQLTMuhjbYvb4Ncuuo0bfmgPRFywX53jPhoFf4Zg6mv" +
            "/seOXpgecTdOcVttfzC8ycIKrt3aQTiwOG/ctaR4Bk/t6ayNFfdUNxHWk4WCKzdz" +
            "/56fW2O0F23qIRd8UUJp5IIlN4RDdRCtdhVQIAuzvp2oVy/LaS2kxQoKvph/5pQ/" +
            "5whqsyroEWDJoSV0yOb25B/iwk/pLUFoyhDG9bj0kIzDxrEqW+7Ba8nocQlecMF3" +
            "X5KMN5kp2zraLv9dlBBpWW43XktjcCZgMy20SouraVma8Je/ECwUWYUiAZxLIlMv" +
            "9CurEOtxUw6N3RdOtLmYZS9uEnn5y1UkF88o8Nku890uk6BrewFzJyLAx5wRZ4F0" +
            "qV/yq36UWQ0JB/AUGhHVPdFf6pl6eaxBwT5GXvbBUibtf8YI2og5RsgTWtXfU7eb" +
            "SGXrl5ZMpbA6mbfhd0R8aPxWfmDWiIOhBufhMCvUHh1sApMKVZnvIff9/0Dca3wb" +
            "vLIwa3T4CyshfT0AEQEAAQAL/RZqbJW2IqQDCnJi4Ozm++gPqBPiX1RhTWSjwxfM" +
            "cJKUZfzLj414rMKm6Jh1cwwGY9jekROhB9WmwaaKT8HtcIgrZNAlYzANGRCM4TLK" +
            "3VskxfSwKKna8l+s+mZglqbAjUg3wmFuf9Tj2xcUZYmyRm1DEmcN2ZzpvRtHgX7z" +
            "Wn1mAKUlSDJZSQks0zjuMNbupcpyJokdlkUg2+wBznBOTKzgMxVNC9b2g5/tMPUs" +
            "hGGWmF1UH+7AHMTaS6dlmr2ZBIyogdnfUqdNg5sZwsxSNrbglKP4sqe7X61uEAIQ" +
            "bD7rT3LonLbhkrj3I8wilUD8usIwt5IecoHhd9HziqZjRCc1BUBkboUEoyedbDV4" +
            "i4qfsFZ6CEWoLuD5pW7dEp0M+WeuHXO164Rc+LnH6i1VQrpb1Okl4qO6ejIpIjBI" +
            "1t3GshtUu/mwGBBxs60KBX5g77mFQ9lLCRj8lSYqOsHRKBhUp4qM869VA+fD0BRP" +
            "fqPT0I9IH4Oa/A3jYJcg622GwQYA1LhnP208Waf6PkQSJ6kyr8ymY1yVh9VBE/g6" +
            "fRDYA+pkqKnw9wfH2Qho3ysAA+OmVOX8Hldg+Pc0Zs0e5pCavb0En8iFLvTA0Q2E" +
            "LR5rLue9uD7aFuKFU/VdcddY9Ww/vo4k5p/tVGp7F8RYCFn9rSjIWbfvvZi1q5Tx" +
            "+akoZbga+4qQ4WYzB/obdX6SCmi6BndcQ1QdjCCQU6gpYx0MddVERbIp9+2SXDyL" +
            "hpxjSyz+RGsZi/9UAshT4txP4+MZBgDfK3ZqtW+h2/eMRxkANqOJpxSjMyLO/FXN" +
            "WxzTDYeWtHNYiAlOwlQZEPOydZFty9IVzzNFQCIUCGjQ/nNyhw7adSgUk3+BXEx/" +
            "MyJPYY0BYuhLxLYcrfQ9nrhaVKxRJj25SVHj2ASsiwGJRZW4CC3uw40OYxfKEvNC" +
            "mer/VxM3kg8qqGf9KUzJ1dVdAvjyx2Hz6jY2qWCyRQ6IMjWHyd43C4r3jxooYKUC" +
            "YnstRQyb/gCSKahveSEjo07CiXMr88UGALwzEr3npFAsPW3osGaFLj49y1oRe11E" +
            "he9gCHFm+fuzbXrWmdPjYU5/ZdqdojzDqfu4ThfnipknpVUM1o6MQqkjM896FHm8" +
            "zbKVFSMhEP6DPHSCexMFrrSgN03PdwHTO6iBaIBBFqmGY01tmJ03SxvSpiBPON9P" +
            "NVvy/6UZFedTq8A07OUAxO62YUSNtT5pmK2vzs3SAZJmbFbMh+NN204TRI72GlqT" +
            "t5hcfkuv8hrmwPS/ZR6q312mKQ6w/1pqO9qitCFCb2IgQmFiYmFnZSA8Ym9iQG9w" +
            "ZW5wZ3AuZXhhbXBsZT6JAc4EEwEKADgCGwMFCwkIBwIGFQoJCAsCBBYCAwECHgEC" +
            "F4AWIQTRpm4aI7GCyZgPeIz7/MgqAV5zMAUCXaWe+gAKCRD7/MgqAV5zMG9sC/9U" +
            "2T3RrqEbw533FPNfEflhEVRIZ8gDXKM8hU6cqqEzCmzZT6xYTe6sv4y+PJBGXJFX" +
            "yhj0g6FDkSyboM5litOcTupURObVqMgA/Y4UKERznm4fzzH9qek85c4ljtLyNufe" +
            "doL2pp3vkGtn7eD0QFRaLLmnxPKQ/TlZKdLE1G3u8Uot8QHicaR6GnAdc5UXQJE3" +
            "BiV7jZuDyWmZ1cUNwJkKL6oRtp+ZNDOQCrLNLecKHcgCqrpjSQG5oouba1I1Q6Vl" +
            "sP44dhA1nkmLHtxlTOzpeHj4jnk1FaXmyasurrrI5CgU/L2Oi39DGKTH/A/cywDN" +
            "4ZplIQ9zR8enkbXquUZvFDe+Xz+6xRXtb5MwQyWODB3nHw85HocLwRoIN9WdQEI+" +
            "L8a/56AuOwhs8llkSuiITjR7r9SgKJC2WlAHl7E8lhJ3VDW3ELC56KH308d6mwOG" +
            "ZRAqIAKzM1T5FGjMBhq7ZV0eqdEntBh3EcOIfj2M8rg1MzJv+0mHZOIjByawikad" +
            "BVgEXaWc8gEMANYwv1xsYyunXYK0X1vY/rP1NNPvhLyLIE7NpK90YNBj+xS1ldGD" +
            "bUdZqZeef2xJe8gMQg05DoD1DF3GipZ0Ies65beh+d5hegb7N4pzh0LzrBrVNHar" +
            "29b5ExdI7i4iYD5TO6Vr/qTUOiAN/byqELEzAb+L+b2DVz/RoCm4PIp1DU9ewcc2" +
            "WB38Ofqut3nLYA5tqJ9XvAiEQme+qAVcM3ZFcaMt4I4dXhDZZNg+D9LiTWcxdUPB" +
            "leu8iwDRjAgyAhPzpFp+nWoqWA81uIiULWD1Fj+IVoY3ZvgivoYOiEFBJ9lbb4te" +
            "g9m5UT/AaVDTWuHzbspVlbiVe+qyB77C2daWzNyx6UYBPLOo4r0t0c91kbNE5lgj" +
            "Z7xz6los0N1U8vq91EFSeQJoSQ62XWavYmlCLmdNT6BNfgh4icLsT7Vr1QMX9jzn" +
            "JtTPxdXytSdHvpSpULsqJ016l0dtmONcK3z9mj5N5z0k1tg1AH970TGYOe2aUcSx" +
            "IRDMXDOPyzEfjwARAQABAAv9F2CwsjS+Sjh1M1vegJbZjei4gF1HHpEM0K0PSXsp" +
            "SfVvpR4AoSJ4He6CXSMWg0ot8XKtDuZoV9jnJaES5UL9pMAD7JwIOqZm/DYVJM5h" +
            "OASCh1c356/wSbFbzRHPtUdZO9Q30WFNJM5pHbCJPjtNoRmRGkf71RxtvHBzy7np" +
            "Ga+W6U/NVKHw0i0CYwMI0YlKDakYW3Pm+QL+gHZFvngGweTod0f9l2VLLAmeQR/c" +
            "+EZs7lNumhuZ8mXcwhUc9JQIhOkpO+wreDysEFkAcsKbkQP3UDUsA1gFx9pbMzT0" +
            "tr1oZq2a4QBtxShHzP/ph7KLpN+6qtjks3xB/yjTgaGmtrwM8tSe0wD1RwXS+/1o" +
            "BHpXTnQ7TfeOGUAu4KCoOQLv6ELpKWbRBLWuiPwMdbGpvVFALO8+kvKAg9/r+/ny" +
            "zM2GQHY+J3Jh5JxPiJnHfXNZjIKLbFbIPdSKNyJBuazXW8xIa//mEHMI5OcvsZBK" +
            "clAIp7LXzjEjKXIwHwDcTn9pBgDpdOKTHOtJ3JUKx0rWVsDH6wq6iKV/FTVSY5jl" +
            "zN+puOEsskF1Lfxn9JsJihAVO3yNsp6RvkKtyNlFazaCVKtDAmkjoh60XNxcNRqr" +
            "gCnwdpbgdHP6v/hvZY54ZaJjz6L2e8unNEkYLxDt8cmAyGPgH2XgL7giHIp9jrsQ" +
            "aS381gnYwNX6wE1aEikgtY91nqJjwPlibF9avSyYQoMtEqM/1UjTjB2KdD/MitK5" +
            "fP0VpvuXpNYZedmyq4UOMwdkiNMGAOrfmOeT0olgLrTMT5H97Cn3Yxbk13uXHNu/" +
            "ZUZZNe8s+QtuLfUlKAJtLEUutN33TlWQY522FV0m17S+b80xJib3yZVJteVurrh5" +
            "HSWHAM+zghQAvCesg5CLXa2dNMkTCmZKgCBvfDLZuZbjFwnwCI6u/NhOY9egKuUf" +
            "SA/je/RXaT8m5VxLYMxwqQXKApzD87fv0tLPlVIEvjEsaf992tFEFSNPcG1l/jpd" +
            "5AVXw6kKuf85UkJtYR1x2MkQDrqY1QX/XMw00kt8y9kMZUre19aCArcmor+hDhRJ" +
            "E3Gt4QJrD9z/bICESw4b4z2DbgD/Xz9IXsA/r9cKiM1h5QMtXvuhyfVeM01enhxM" +
            "GbOH3gjqqGNKysx0UODGEwr6AV9hAd8RWXMchJLaExK9J5SRawSg671ObAU24SdY" +
            "vMQ9Z4kAQ2+1ReUZzf3ogSMRZtMT+d18gT6L90/y+APZIaoArLPhebIAGq39HLmJ" +
            "26x3z0WAgrpA1kNsjXEXkoiZGPLKIGoe3hqJAbYEGAEKACAWIQTRpm4aI7GCyZgP" +
            "eIz7/MgqAV5zMAUCXaWc8gIbDAAKCRD7/MgqAV5zMOn/C/9ugt+HZIwX308zI+QX" +
            "c5vDLReuzmJ3ieE0DMO/uNSC+K1XEioSIZP91HeZJ2kbT9nn9fuReuoff0T0Dief" +
            "rbwcIQQHFFkrqSp1K3VWmUGp2JrUsXFVdjy/fkBIjTd7c5boWljv/6wAsSfiv2V0" +
            "JSM8EFU6TYXxswGjFVfc6X97tJNeIrXL+mpSmPPqy2bztcCCHkWS5lNLWQw+R7Vg" +
            "71Fe6yBSNVrqC2/imYG2J9zlowjx1XU63Wdgqp2Wxt0l8OmsB/W80S1fRF5G4SDH" +
            "s9HXglXXqPsBRZJYfP+VStm9L5P/sKjCcX6WtZR7yS6G8zj/X767MLK/djANvpPd" +
            "NVniEke6hM3CNBXYPAMhQBMWhCulcoz+0lxi8L34rMN+Dsbma96psdUrn7uLaB91" +
            "6we0CTfF8qqm7BsVAgalon/UUiuMY80U3ueoj3okiSTiHIjD/YtpXSPioC8nMng7" +
            "xqAY9Bwizt4FWgXuLm1a4+So4V9j1TRCXd12Uc2l2RNmgDE=");

        // v4 DSA/ElGamal key "Carol" from "OpenPGP interoperability test suite"
        // https://tests.sequoia-pgp.org/#Encrypt-Decrypt_roundtrip_with_key__Carol_
        private static readonly byte[] carolPubkey = Base64.Decode(
            "xsPuBF3+CmgRDADZhdKTM3ms3XpXnQke83FgaIBtP1g1qhqpCfg50WiPS0kjiMC0" +
            "OJz2vh59nusbBLzgI//Y1VMhKfIWYbqMcIY+lWbseHjl52rqW6AaJ0TH4NgVt7vh" +
            "yVeJt0k/NnxvNhMd0587KXmfpDxrwBqc/l5cVB+p0rL8vs8kxojHXAi5V3koM0Uj" +
            "REWs5Jpj/XU9LhEoyXZkeJC/pes1u6UKoFYn7dFIP49Kkd1kb+1bNfdPYtA0JpcG" +
            "zYgeMNOvdWJwn43dNhxoeuXfmAEhA8LdzT0C0O+7akXOKWrfhXJ8MTBqvPgWZYx7" +
            "MNuQx/ejIMZHl+Iaf7hG976ILH+NCGiKkhidd9GIuA/WteHiQbXLyfiQ4n8P12q9" +
            "+4dq6ybUM65tnozRyyN+1m3rU2a/+Ly3JCh4TeO27w+cxMWkaeHyTQaJVMbMbDpX" +
            "duVd32MA33UVNH5/KXMVczVi5asVjuKDSojJDV1QwX8izZNl1t+AI0L3balCabV0" +
            "SFhlfnBEUj1my1sBAMOSO/I67BvBS3IPHZWXHjgclhs26mPzRlZLryAUWR2DDACH" +
            "5fx+yUAdZ8Vu/2zWTHxwWJ/X6gGTLqa9CmfDq5UDqYFFzuWwN4HJ+ryOuak1CGwS" +
            "KJUBSA75HExbv0naWg+suy+pEDvF0VALPU9VUkSQtHyR10YO2FWOe3AEtpbYDRwp" +
            "dr1ZwEbb3L6IGQ5i/4CNHbJ2u3yUeXsDNAvrpVSEcIjA01RPCOKmf58SDZp4yDdP" +
            "xGhM8w6a18+fdQr22f2cJ0xgfPlbzFbO+FUsEgKvn6QTLhbaYw4zs7rdQDejWHV8" +
            "2hP4K+rb9FwknYdV9uo4m77MgGlU+4yvJnGEYaL3jwjI3bH9aooNOl6XbvVAzNzo" +
            "mYmaTO7mp6xFAu43yuGyd9K+1E4k7CQTROxTZ+RdtQjV95hSsEmMg792nQvDSBW4" +
            "xwfOQ7pf3kC7r9fm8u9nBlEN12HsbQ8Yvux/ld5q5RaIlD19jzfVR6+hJzbj2ZnU" +
            "yQs4ksAfIHTzTdLttRxS9lTRTkVx2vbUnoSBy6TYF1mf6nRPpSm1riZxnkR4+BQL" +
            "/0rUAxwegTNIG/5M612s2a45QvYK1turZ7spI1RGitJUIjBXUuR76jIsyqagIhBl" +
            "5nEsQ4HLv8OQ3EgJ5T9gldLFpHNczLxBQnnNwfPoD2e0kC/iy0rfiNX8HWpTgQpb" +
            "zAosLj5/E0iNlildynIhuqBosyRWFqGva0O6qioL90srlzlfKCloe9R9w3HizjCb" +
            "f59yEspuJt9iHVNOPOW2Wj5ub0KTiJPp9vBmrFaB79/IlgojpQoYvQ77Hx5A9CJq" +
            "paMCHGOW6Uz9euN1ozzETEkIPtL8XAxcogfpe2JKE1uS7ugxsKEGEDfxOQFKAGV0" +
            "XFtIx50vFCr2vQro0WB858CGN47dCxChhNUxNtGc11JNEkNv/X7hKtRf/5VCmnaz" +
            "GWwNK47cqZ7GJfEBnElD7s/tQvTC5Qp7lg9gEt47TUX0bjzUTCxNvLosuKL9+J1W" +
            "ln1myRpff/5ZOAnZTPHR+AbX4bRB4sK5zijQe4139Dn2oRYK+EIYoBAxFxSOzehP" +
            "IcKKBB8RCAA8BQJd/gppAwsJCgkQm6eJ3HbWhJoEFQoJCAIWAQIXgAIbAwIeARYh" +
            "BHH/2gBECeXdsMPo8Zunidx21oSaAABihQD/VWnF1HbBhP+kLwWsqxuYjEslEsM2" +
            "UQPeKGK9an8HZ78BAJPaiL3OpuOmsIoCfOghhMZOKXjIV+Z57LwaMw7FQfPgzSZD" +
            "YXJvbCBPbGRzdHlsZSA8Y2Fyb2xAb3BlbnBncC5leGFtcGxlPsKKBBMRCAA8BQJd" +
            "/gppAwsJCgkQm6eJ3HbWhJoEFQoJCAIWAQIXgAIbAwIeARYhBHH/2gBECeXdsMPo" +
            "8Zunidx21oSaAABQTAD/ZMXAvSbKaMJJpAfwp1C7KAj6K2k2CAz5jwUXyGf1+jUA" +
            "/2iAMiX1XcLy3n0L8ytzge8/UAFHafBl4rn4DmUugfhjzsPMBF3+CmgQDADZhdKT" +
            "M3ms3XpXnQke83FgaIBtP1g1qhqpCfg50WiPS0kjiMC0OJz2vh59nusbBLzgI//Y" +
            "1VMhKfIWYbqMcIY+lWbseHjl52rqW6AaJ0TH4NgVt7vhyVeJt0k/NnxvNhMd0587" +
            "KXmfpDxrwBqc/l5cVB+p0rL8vs8kxojHXAi5V3koM0UjREWs5Jpj/XU9LhEoyXZk" +
            "eJC/pes1u6UKoFYn7dFIP49Kkd1kb+1bNfdPYtA0JpcGzYgeMNOvdWJwn43dNhxo" +
            "euXfmAEhA8LdzT0C0O+7akXOKWrfhXJ8MTBqvPgWZYx7MNuQx/ejIMZHl+Iaf7hG" +
            "976ILH+NCGiKkhidd9GIuA/WteHiQbXLyfiQ4n8P12q9+4dq6ybUM65tnozRyyN+" +
            "1m3rU2a/+Ly3JCh4TeO27w+cxMWkaeHyTQaJVMbMbDpXduVd32MA33UVNH5/KXMV" +
            "czVi5asVjuKDSojJDV1QwX8izZNl1t+AI0L3balCabV0SFhlfnBEUj1my1sMAIfl" +
            "/H7JQB1nxW7/bNZMfHBYn9fqAZMupr0KZ8OrlQOpgUXO5bA3gcn6vI65qTUIbBIo" +
            "lQFIDvkcTFu/SdpaD6y7L6kQO8XRUAs9T1VSRJC0fJHXRg7YVY57cAS2ltgNHCl2" +
            "vVnARtvcvogZDmL/gI0dsna7fJR5ewM0C+ulVIRwiMDTVE8I4qZ/nxINmnjIN0/E" +
            "aEzzDprXz591CvbZ/ZwnTGB8+VvMVs74VSwSAq+fpBMuFtpjDjOzut1AN6NYdXza" +
            "E/gr6tv0XCSdh1X26jibvsyAaVT7jK8mcYRhovePCMjdsf1qig06Xpdu9UDM3OiZ" +
            "iZpM7uanrEUC7jfK4bJ30r7UTiTsJBNE7FNn5F21CNX3mFKwSYyDv3adC8NIFbjH" +
            "B85Dul/eQLuv1+by72cGUQ3XYextDxi+7H+V3mrlFoiUPX2PN9VHr6EnNuPZmdTJ" +
            "CziSwB8gdPNN0u21HFL2VNFORXHa9tSehIHLpNgXWZ/qdE+lKbWuJnGeRHj4FAv+" +
            "MQaafW0uHF+N8MDm8UWPvf4Vd0UJ0UpIjRWl2hTV+BHkNfvZlBRhhQIphNiKRe/W" +
            "ap0f/lW2Gm2uS0KgByjjNXEzTiwrte2GX65M6F6Lz8N31kt1Iig1xGOuv+6HmxTN" +
            "R8gL2K5PdJeJn8PTJWrRS7+BY8Hdkgb+wVpzE5cCvpFiG/P0yqfBdLWxVPlPI7dc" +
            "hDkmx4iAhHJX9J/gX/hC6L3AzPNJqNPAKy20wYp/ruTbbwBolW/4ikWij460JrvB" +
            "sm6Sp81A3ebaiN9XkJygLOyhGyhMieGulCYz6AahAFcECtPXGTcordV1mJth8yjF" +
            "4gZfDQyg0nMW4Yr49yeFXcRMUw1yzN3Q9v2zzqDuFi2lGYTXYmVqLYzM9KbLO2Wx" +
            "E/21xnBjLsl09l/FdA/bhdZq3t4/apbFOeQQ/j/AphvzWbsJnhG9Q7+d3VoDlz0g" +
            "FiSduCYIAAq8dUOJNjrUTkZsL1pOIjhYjCMi2uiKS6RQkT6nvuumPF/D/VTnUGeZ" +
            "wooEGBEIADwFAl3+CmkDCwkKCRCbp4ncdtaEmgQVCgkIAhYBAheAAhsMAh4BFiEE" +
            "cf/aAEQJ5d2ww+jxm6eJ3HbWhJoAAEEpAP91hFqmcb2ZqVcaRDMSVmhkEcFIRmpH" +
            "vDoQtVn8sArWqwEAi8HwbMhL+YwRItRZDknpC4vFjTHVMd1zMrz/JyeuT9k="
            );

        // v6 Ed25519/X25519 key from RFC 9580
        // https://www.rfc-editor.org/rfc/rfc9580#name-sample-version-6-certificat
        // https://www.rfc-editor.org/rfc/rfc9580#name-sample-version-6-secret-key
        private static readonly byte[] v6Certificate = Base64.Decode(
            "xioGY4d/4xsAAAAg+U2nu0jWCmHlZ3BqZYfQMxmZu52JGggkLq2EVD34laPCsQYf" +
            "GwoAAABCBYJjh3/jAwsJBwUVCg4IDAIWAAKbAwIeCSIhBssYbE8GCaaX5NUt+mxy" +
            "KwwfHifBilZwj2Ul7Ce62azJBScJAgcCAAAAAK0oIBA+LX0ifsDm185Ecds2v8lw" +
            "gyU2kCcUmKfvBXbAf6rhRYWzuQOwEn7E/aLwIwRaLsdry0+VcallHhSu4RN6HWaE" +
            "QsiPlR4zxP/TP7mhfVEe7XWPxtnMUMtf15OyA51YBM4qBmOHf+MZAAAAIIaTJINn" +
            "+eUBXbki+PSAld2nhJh/LVmFsS+60WyvXkQ1wpsGGBsKAAAALAWCY4d/4wKbDCIh" +
            "BssYbE8GCaaX5NUt+mxyKwwfHifBilZwj2Ul7Ce62azJAAAAAAQBIKbpGG2dWTX8" +
            "j+VjFM21J0hqWlEg+bdiojWnKfA5AQpWUWtnNwDEM0g12vYxoWM8Y81W+bHBw805" +
            "I8kWVkXU6vFOi+HWvv/ira7ofJu16NnoUkhclkUrk0mXubZvyl4GBg==");

        private static readonly byte[] v6UnlockedSecretKey = Base64.Decode(
            "xUsGY4d/4xsAAAAg+U2nu0jWCmHlZ3BqZYfQMxmZu52JGggkLq2EVD34laMAGXKB" +
            "exK+cH6NX1hs5hNhIB00TrJmosgv3mg1ditlsLfCsQYfGwoAAABCBYJjh3/jAwsJ" +
            "BwUVCg4IDAIWAAKbAwIeCSIhBssYbE8GCaaX5NUt+mxyKwwfHifBilZwj2Ul7Ce6" +
            "2azJBScJAgcCAAAAAK0oIBA+LX0ifsDm185Ecds2v8lwgyU2kCcUmKfvBXbAf6rh" +
            "RYWzuQOwEn7E/aLwIwRaLsdry0+VcallHhSu4RN6HWaEQsiPlR4zxP/TP7mhfVEe" +
            "7XWPxtnMUMtf15OyA51YBMdLBmOHf+MZAAAAIIaTJINn+eUBXbki+PSAld2nhJh/" +
            "LVmFsS+60WyvXkQ1AE1gCk95TUR3XFeibg/u/tVY6a//1q0NWC1X+yui3O24wpsG" +
            "GBsKAAAALAWCY4d/4wKbDCIhBssYbE8GCaaX5NUt+mxyKwwfHifBilZwj2Ul7Ce6" +
            "2azJAAAAAAQBIKbpGG2dWTX8j+VjFM21J0hqWlEg+bdiojWnKfA5AQpWUWtnNwDE" +
            "M0g12vYxoWM8Y81W+bHBw805I8kWVkXU6vFOi+HWvv/ira7ofJu16NnoUkhclkUr" +
            "k0mXubZvyl4GBg==");

        // v5 key "Emma" from "OpenPGP interoperability test suite"
        // https://tests.sequoia-pgp.org/#Inline_Sign-Verify_roundtrip_with_key__Emma_
        private static readonly byte[] v5Certificate = Base64.Decode(
            "mDcFXJH05BYAAAAtCSsGAQQB2kcPAQEHQFhZlVcVVtwf+21xNQPX+ecMJJBL0MPd" +
            "fj75iux+my8QtBhlbW1hLmdvbGRtYW5AZXhhbXBsZS5uZXSIlgUTFggASCIhBRk0" +
            "e8mHJGQCX5nfPsLgAA7ZiEiS4fez6kyUAJFZVptUBQJckfTkAhsDBQsJCAcCAyIC" +
            "AQYVCgkICwIEFgIDAQIeBwIXgAAA9cAA/jiR3yMsZMeEQ40u6uzEoXa6UXeV/S3w" +
            "wJAXRJy9M8s0AP9vuL/7AyTfFXwwzSjDnYmzS0qAhbLDQ643N+MXGBJ2Bbg8BVyR" +
            "9OQSAAAAMgorBgEEAZdVAQUBAQdA+nysrzml2UCweAqtpDuncSPlvrcBWKU0yfU0" +
            "YvYWWAoDAQgHiHoFGBYIACwiIQUZNHvJhyRkAl+Z3z7C4AAO2YhIkuH3s+pMlACR" +
            "WVabVAUCXJH05AIbDAAAOSQBAP4BOOIR/sGLNMOfeb5fPs/02QMieoiSjIBnijho" +
            "b2U5AQC+RtOHCHx7TcIYl5/Uyoi+FOvPLcNw4hOv2nwUzSSVAw==");

        private static readonly byte[] v5UnlockedSecretKey = Base64.Decode(
            "lGEFXJH05BYAAAAtCSsGAQQB2kcPAQEHQFhZlVcVVtwf+21xNQPX+ecMJJBL0MPd" +
            "fj75iux+my8QAAAAAAAiAQCHZ1SnSUmWqxEsoI6facIVZQu6mph3cBFzzTvcm5lA" +
            "Ng5ctBhlbW1hLmdvbGRtYW5AZXhhbXBsZS5uZXSIlgUTFggASCIhBRk0e8mHJGQC" +
            "X5nfPsLgAA7ZiEiS4fez6kyUAJFZVptUBQJckfTkAhsDBQsJCAcCAyICAQYVCgkI" +
            "CwIEFgIDAQIeBwIXgAAA9cAA/jiR3yMsZMeEQ40u6uzEoXa6UXeV/S3wwJAXRJy9" +
            "M8s0AP9vuL/7AyTfFXwwzSjDnYmzS0qAhbLDQ643N+MXGBJ2BZxmBVyR9OQSAAAA" +
            "MgorBgEEAZdVAQUBAQdA+nysrzml2UCweAqtpDuncSPlvrcBWKU0yfU0YvYWWAoD" +
            "AQgHAAAAAAAiAP9OdAPppjU1WwpqjIItkxr+VPQRT8Zm/Riw7U3F6v3OiBFHiHoF" +
            "GBYIACwiIQUZNHvJhyRkAl+Z3z7C4AAO2YhIkuH3s+pMlACRWVabVAUCXJH05AIb" +
            "DAAAOSQBAP4BOOIR/sGLNMOfeb5fPs/02QMieoiSjIBnijhob2U5AQC+RtOHCHx7" +
            "TcIYl5/Uyoi+FOvPLcNw4hOv2nwUzSSVAw==");

        private static readonly char[] emptyPassphrase = Array.Empty<char>();

        private static PgpSignatureGenerator CreateAndInitPgpSignatureGenerator(PgpSecretKey signingKey, HashAlgorithmTag hashAlgo, char[] passphrase)
        {
            PgpSignatureGenerator generator = new PgpSignatureGenerator(signingKey.PublicKey.Algorithm, hashAlgo);
            PgpPrivateKey privKey = signingKey.ExtractPrivateKey(passphrase);
            generator.InitSign(PgpSignature.CanonicalTextDocument, privKey, new SecureRandom());

            return generator;
        }

        private static PgpPublicKeyRingBundle CreateBundle(params PgpPublicKeyRing[] keyrings)
        {
            using (MemoryStream ms = new MemoryStream())
            {
                foreach (var keyring in keyrings)
                {
                    keyring.Encode(ms);
                }
                return new PgpPublicKeyRingBundle(ms.ToArray());
            }
        }
        private static PgpSecretKeyRingBundle CreateBundle(params PgpSecretKeyRing[] keyrings)
        {
            using (MemoryStream ms = new MemoryStream())
            {
                foreach (var keyring in keyrings)
                {
                    keyring.Encode(ms);
                }
                return new PgpSecretKeyRingBundle(ms.ToArray());
            }
        }

        private void VerifyMultipleInlineSignaturesTest(byte[] message, PgpPublicKeyRingBundle bundle, bool shouldFail = false)
        {
            PgpObjectFactory factory = new PgpObjectFactory(message);
            PgpOnePassSignatureList opss = factory.NextPgpObject() as PgpOnePassSignatureList;
            for (int i = 0; i < opss.Count; i++)
            {
                PgpOnePassSignature ops = opss[i];
                ops.InitVerify(bundle.GetPublicKey(ops.KeyId));
            }

            PgpLiteralData lit = factory.NextPgpObject() as PgpLiteralData;
            using (Stream dIn = lit.GetInputStream())
            {

                byte[] buffer = new byte[30];
                int bytesRead;
                while ((bytesRead = dIn.Read(buffer, 0, buffer.Length)) > 0)
                {
                    for (int i = 0; i < opss.Count; i++)
                    {
                        opss[i].Update(buffer, 0, bytesRead);
                    }
                }
            }

            PgpSignatureList sigs = factory.NextPgpObject() as PgpSignatureList;
            IsEquals(opss.Count, sigs.Count);
            int sigCount = sigs.Count - 1;
            for (int i = 0; i <= sigCount; i++)
            {
                IsTrue(shouldFail != opss[i].Verify(sigs[sigCount - i]));
            }
        }

        [Test]
        public void MultiplePkeskTest()
        {
            // Encrypt-Decrypt roundtrip with multiple keys: the plaintext
            // "Hello World :)" is encrypted with the X25519 sample key from
            // Appendix A.3 of RFC 9580 and the 'Alice' ECDH key from
            // "OpenPGP Example Keys and Certificates"
            byte[] message = Base64.Decode(
                "wVQDEsg/HnBvYwgZaeKxsIieN+FvNLxmgMfRKJZGKt8vAa5BYX2k0QAetCMpCQbE" +
                "mvXtq2XatB3H8NG7zlY2dyYKcHAK0xvgAo8YbinpCZ+xOciOkmDBXgNHZva51fIe" +
                "thIBB0CRPS2kBUVTTtVLGjBKVCmc+KoPTzUXqVpPJdgiPmNvGTBME7unL3IP2CdO" +
                "hL+uO3LVBJGfRy3JJDH1SIQhQ7oS47AFIOjpG0R0CBtf8M6dzwDSPwG1BrsfRn86" +
                "mFm666ZINIHL1IDH1HQVF5OYxcRRVFjTJhms03+nu6N8I6Vy2G5yekVb1Vh2tM39" +
                "/aGWVXTHJw==");

            PgpSecretKeyRingBundle bundle = CreateBundle(
                new PgpSecretKeyRing(aliceSecretkey),
                new PgpSecretKeyRing(v6UnlockedSecretKey));

            byte[] plaintext = Encoding.UTF8.GetBytes("Hello World :)");
            PgpObjectFactory factory = new PgpObjectFactory(message);
            PgpEncryptedDataList encDataList = factory.NextPgpObject() as PgpEncryptedDataList;
            FailIf("invalid PgpEncryptedDataList", encDataList is null);

            IsEquals(2, encDataList.Count);

            // decrypt with RFC 9580 sample X25519 key
            var encData = encDataList[0] as PgpPublicKeyEncryptedData;
            FailIf("invalid PgpPublicKeyEncryptedData", encData is null);
            PgpSecretKey secKey = bundle.GetSecretKey(encData.KeyId);
            PgpPrivateKey privKey = secKey.ExtractPrivateKey(emptyPassphrase);
            using (var stream = encData.GetDataStream(privKey))
            {
                factory = new PgpObjectFactory(stream);
                PgpLiteralData lit = factory.NextPgpObject() as PgpLiteralData;
                using (var ms = new MemoryStream())
                {
                    lit.GetDataStream().CopyTo(ms);
                    var decrypted = ms.ToArray();
                    IsTrue(Arrays.AreEqual(plaintext, decrypted));
                }
            }

            // decrypt with 'Alice' ECDH key
            factory = new PgpObjectFactory(message);
            encDataList = factory.NextPgpObject() as PgpEncryptedDataList;
            encData = encDataList[1] as PgpPublicKeyEncryptedData;
            FailIf("invalid PgpPublicKeyEncryptedData", encData is null);
            secKey = bundle.GetSecretKey(encData.KeyId);
            privKey = secKey.ExtractPrivateKey(emptyPassphrase);
            using (var stream = encData.GetDataStream(privKey))
            {
                factory = new PgpObjectFactory(stream);
                PgpLiteralData lit = factory.NextPgpObject() as PgpLiteralData;
                using (var ms = new MemoryStream())
                {
                    lit.GetDataStream().CopyTo(ms);
                    var decrypted = ms.ToArray();
                    IsTrue(Arrays.AreEqual(plaintext, decrypted));
                }
            }

        }

        [Test]
        public void MultipleInlineSignatureTest()
        {
            // Verify Inline Signature with multiple keys:
            // v6 key from RFC 9580 and v4 key "Alice" from "OpenPGP Example Keys and Certificates"
            // https://tests.sequoia-pgp.org/#Inline_Sign_with_minimal_key_from_RFC9760_and_key__Alice___verify_with_key_from_RFC9760

            // inline signed message generated by GopenPGP 3.0.0-alpha
            byte[] message = Base64.Decode(
                "xEYGAAobIPdza3bN03j7U7LE/Q/46kHCmsfVx2UmTPsNpUk/V/UWyxhsTwYJppfk" +
                "1S36bHIrDB8eJ8GKVnCPZSXsJ7rZrMkAxA0DAAoW8jFVDE9H444ByxRiAAAAAABI" +
                "ZWxsbyBXb3JsZCA6KcJ1BAAWCgAnBQJl4HbKCRDyMVUMT0fjjhYhBOuFu1+jOnXh" +
                "XpROY/IxVQxPR+OOAACKGAEAsQpg3dNdO4C9eMGn1jvVTjP0r2welMFD68dFU5d8" +
                "nq8A+gNFdJbX0PP0vNx/kIxpilbdssnF+a04CdVpAkwXmaYPwpgGABsKAAAAKQUC" +
                "ZeB2yiKhBssYbE8GCaaX5NUt+mxyKwwfHifBilZwj2Ul7Ce62azJAAAAACB3IPdz" +
                "a3bN03j7U7LE/Q/46kHCmsfVx2UmTPsNpUk/V/UWJsjxFqBQXqDFAaOjiv8oabeX" +
                "qvELkq1bKLb9fJ+ASfZW9FyI1ORHdCrI5zEnpfrFe4Id+xg9N39MTGq+OoPeDA==");

            PgpPublicKeyRingBundle bundle = CreateBundle(
                new PgpPublicKeyRing(alicePubkey),
                new PgpPublicKeyRing(v6Certificate));

            VerifyMultipleInlineSignaturesTest(message, bundle);

            // inline signed message generated by PGPy 0.6.0+dkg-crypto-refresh
            message = Base64.Decode(
                "xA0DAAoW8jFVDE9H444AxEYGAAobIFWUOmg2wsfVON4qIM1sWUPd9223ANjaMnHT" +
                "Mvad9EfVyxhsTwYJppfk1S36bHIrDB8eJ8GKVnCPZSXsJ7rZrMkByxRiAGXgds5I" +
                "ZWxsbyBXb3JsZCA6KcKYBgAbCgAAACkFgmXgds4iIQbLGGxPBgmml+TVLfpscisM" +
                "Hx4nwYpWcI9lJewnutmsyQAAAACSWCBVlDpoNsLH1TjeKiDNbFlD3fdttwDY2jJx" +
                "0zL2nfRH1aouTY4WN/3DFsfP8yFg/BE7Ssaikt7bbXtBSH/AldOtyM1myiFsP+yx" +
                "8Img2A7eq9+wKTLjhPHl7zSh7y9KEATCdQQAFgoAHQWCZeB2zhYhBOuFu1+jOnXh" +
                "XpROY/IxVQxPR+OOAAoJEPIxVQxPR+OOgDcBAOz0kSpV4/F9Exxdq6oYlHZdsX5U" +
                "n9QpjmJVjo7bsMGDAQCd3PA5joXmfoKQhtQT5Qm1dhjfv/c89oPzdjQYmVLnCg==");

            VerifyMultipleInlineSignaturesTest(message, bundle);
        }

        [Test]
        public void GenerateAndVerifyMultipleInlineSignatureTest()
        {
            // Inline Sign-Verify roundtrip test with multiple keys:
            // v6 key from RFC 9580 and v4 key "Alice" from "OpenPGP Example Keys and Certificates"
            byte[] data = Encoding.UTF8.GetBytes("Hello World :)");
            byte[] message;

            PgpSecretKey[] signingKeys = new PgpSecretKey[] {
                new PgpSecretKeyRing(v6UnlockedSecretKey).GetSecretKey(),
                new PgpSecretKeyRing(aliceSecretkey).GetSecretKey()
            };

            PgpSignatureGenerator[] generators = new PgpSignatureGenerator[] {
                CreateAndInitPgpSignatureGenerator(signingKeys[0], HashAlgorithmTag.Sha384, emptyPassphrase),
                CreateAndInitPgpSignatureGenerator(signingKeys[1], HashAlgorithmTag.Sha256, emptyPassphrase)
            };

            using (MemoryStream ms = new MemoryStream())
            {
                using (BcpgOutputStream bcOut = new BcpgOutputStream(ms, newFormatOnly: true))
                {
                    int sigCount  = generators.Length;
                    int count = 1;
                    foreach (PgpSignatureGenerator generator in generators)
                    {
                        generator.GenerateOnePassVersion(count != sigCount).Encode(bcOut);
                        count++;
                    }

                    PgpLiteralDataGenerator lGen = new PgpLiteralDataGenerator();
                    DateTime modificationTime = DateTime.UtcNow;
                    using (var lOut = lGen.Open(
                        new UncloseableStream(bcOut),
                        PgpLiteralData.Utf8,
                        "_CONSOLE",
                        data.Length,
                        modificationTime))
                    {
                        lOut.Write(data, 0, data.Length);

                        foreach (PgpSignatureGenerator generator in generators)
                        {
                            generator.Update(data);
                        }
                    }

                    foreach (PgpSignatureGenerator generator in generators.Reverse())
                    {
                        generator.Generate().Encode(bcOut);
                    }
                }

                message = ms.ToArray();
            }

            PgpPublicKeyRingBundle bundle = CreateBundle(
                new PgpPublicKeyRing(alicePubkey),
                new PgpPublicKeyRing(v6Certificate));

            VerifyMultipleInlineSignaturesTest(message, bundle);

            //corrupt data;
            message[95] = 0x50;
            VerifyMultipleInlineSignaturesTest(message, bundle, shouldFail: true);
        }

        private void VerifyMultipleDetachedSignaturesTest(byte[] signaturePacket, byte[] data, PgpPublicKeyRingBundle bundle, bool shouldFail = false)
        {
            PgpObjectFactory factory = new PgpObjectFactory(signaturePacket);
            PgpSignatureList sigs = factory.NextPgpObject() as PgpSignatureList;

            IsEquals(sigs.Count, 2);
            for (int i = 0; i < sigs.Count; i++)
            {
                PgpSignature sig = sigs[i];
                sig.InitVerify(bundle.GetPublicKey(sig.KeyId));
                sig.Update(data);

                IsTrue(shouldFail != sig.Verify());
            }
        }

        [Test]
        public void MultipleDetachedSignatureTest()
        {
            // Verify Detached Signature with multiple keys:
            // v6 key from RFC 9580 and v4 key "Alice" from "OpenPGP Example Keys and Certificates"
            // https://tests.sequoia-pgp.org/#Detached_Sign_with_minimal_key_from_RFC9760_and_key__Alice___verify_with_key_from_RFC9760

            byte[] data = Encoding.UTF8.GetBytes("Hello World :)");
            byte[] corruptedData = Encoding.UTF8.GetBytes("Hello World :(");

            PgpPublicKeyRingBundle bundle = CreateBundle(
                new PgpPublicKeyRing(alicePubkey),
                new PgpPublicKeyRing(v6Certificate));

            // Detached Signature generated by GopenPGP 3.0.0-alpha
            byte[] signaturePacket = Base64.Decode(
                "wpgGABsKAAAAKQUCZeB2zCKhBssYbE8GCaaX5NUt+mxyKwwfHifBilZwj2Ul7Ce6" +
                "2azJAAAAAEPPIIh5xfXDp5Zmfa7KJ0S+3Z+RBO9j5AC33ZRAwGgWKVuBts2H+I0k" +
                "GlIQXoyX+2LnurlGQGxZRqwk/z2d4Tk8oAA62CuJ318aZdo8Z4utdmHvsWlluAWl" +
                "lh0XdZ5l/qBNC8J1BAAWCgAnBQJl4HbMCRDyMVUMT0fjjhYhBOuFu1+jOnXhXpRO" +
                "Y/IxVQxPR+OOAABPnQEA881lXU6DUMYbXx3rmGa5qSQld9pHxzRYtBT/WCfkzVwA" +
                "/0/PN5jncrytAiEjb6YwuZuTVjJdTy6xtzuH+XALdREG");

            VerifyMultipleDetachedSignaturesTest(signaturePacket, data, bundle);
            VerifyMultipleDetachedSignaturesTest(signaturePacket, corruptedData, bundle, shouldFail: true);

            // Detached Signature generated by PGPy 0.6.0+dkg-crypto-refresh
            signaturePacket = Base64.Decode(
                "wpgGABsKAAAAKQWCZeB20SIhBssYbE8GCaaX5NUt+mxyKwwfHifBilZwj2Ul7Ce6" +
                "2azJAAAAADUkIIqFiPBBvz4Uqsug38k/hVaFdHoHfy82ESRfutwk1ch+TaG8Kk2I" +
                "7IMcrzKKSp60I7MEGb5CUCzeeM4v883yXlzZhwiBl+enR8kHxcVZzH+z7aS3OptN" +
                "mrcay8CfwzHJD8J1BAAWCgAdBYJl4HbRFiEE64W7X6M6deFelE5j8jFVDE9H444A" +
                "CgkQ8jFVDE9H447lbQEAx8hE9sbx1s8kMwuuEUtvoayJyz6R3PyQAIGH72g9XNcA" +
                "/32a6SYBHAHl8HOrlkZWzUwaIyhOcI5jN6ppiKRZAL8O");

            VerifyMultipleDetachedSignaturesTest(signaturePacket, data, bundle);
            VerifyMultipleDetachedSignaturesTest(signaturePacket, corruptedData, bundle, shouldFail: true);
        }


        [Test]
        public void GenerateAndVerifyMultipleDetachedSignatureTest()
        {
            // Inline Sign-Verify roundtrip test with multiple keys:
            // v6 key from RFC 9580 and v4 key "Alice" from "OpenPGP Example Keys and Certificates"

            byte[] data = Encoding.UTF8.GetBytes("Hello World :)");
            byte[] corruptedData = Encoding.UTF8.GetBytes("Hello World :(");
            byte[] signaturePacket;

            PgpSecretKey[] signingKeys = new PgpSecretKey[] {
                new PgpSecretKeyRing(v6UnlockedSecretKey).GetSecretKey(),
                new PgpSecretKeyRing(aliceSecretkey).GetSecretKey()
            };

            PgpSignatureGenerator[] generators = new PgpSignatureGenerator[] {
                CreateAndInitPgpSignatureGenerator(signingKeys[0], HashAlgorithmTag.Sha3_512, emptyPassphrase),
                CreateAndInitPgpSignatureGenerator(signingKeys[1], HashAlgorithmTag.Sha224, emptyPassphrase)
            };

            using (MemoryStream ms = new MemoryStream())
            {
                using (BcpgOutputStream bcOut = new BcpgOutputStream(ms, newFormatOnly: true))
                {
                    foreach (PgpSignatureGenerator generator in generators)
                    {
                        generator.Update(data);
                        generator.Generate().Encode(bcOut);
                    }
                }

                signaturePacket = ms.ToArray();
            }
            
            PgpPublicKeyRingBundle bundle = CreateBundle(
                new PgpPublicKeyRing(alicePubkey),
                new PgpPublicKeyRing(v6Certificate));

            VerifyMultipleDetachedSignaturesTest(signaturePacket, data, bundle);
            VerifyMultipleDetachedSignaturesTest(signaturePacket, corruptedData, bundle, shouldFail: true);
        }

        [Test]
        public void Version5KeyParsingTest()
        {
            string uid = "emma.goldman@example.net";
            PgpPublicKeyRing pubRing = new PgpPublicKeyRing(v5Certificate);
            PgpPublicKey[] pubKeys = pubRing.GetPublicKeys().ToArray();
            IsEquals("wrong number of public keys", pubKeys.Length, 2);

            PgpPublicKey masterKey = pubKeys[0];
            PgpPublicKey subKey = pubKeys[1];

            IsTrue(masterKey.IsMasterKey);
            IsTrue(subKey.IsEncryptionKey);
            IsEquals(masterKey.Algorithm, PublicKeyAlgorithmTag.EdDsa_Legacy);
            IsEquals(subKey.Algorithm, PublicKeyAlgorithmTag.ECDH);

            IsTrue(masterKey.GetUserIds().Contains(uid));
            IsTrue(!masterKey.GetUserIds().Contains("emma.g@example.net"));

            IsEquals(masterKey.KeyId, 0x19347BC987246402);
            IsEquals((ulong)subKey.KeyId, 0xE4557C2B02FFBF4B);
            IsTrue(AreEqual(masterKey.GetFingerprint(), Hex.Decode("19347BC9872464025F99DF3EC2E0000ED9884892E1F7B3EA4C94009159569B54")));
            IsTrue(AreEqual(subKey.GetFingerprint(), Hex.Decode("E4557C2B02FFBF4B04F87401EC336AF7133D0F85BE7FD09BAEFD9CAEB8C93965")));

            // verify v5 self sig
            PgpSignature signature = masterKey.GetSignaturesForId(uid).ToArray()[0];
            IsEquals(signature.Version, SignaturePacket.Version5);
            IsEquals(signature.SignatureType, PgpSignature.PositiveCertification);
            signature.InitVerify(masterKey);
            IsTrue(signature.VerifyCertification(uid, masterKey));

            // verify subkey binding sig
            signature = subKey.GetSignatures().ToArray()[0];
            IsEquals(signature.Version, SignaturePacket.Version5);
            IsEquals(signature.SignatureType, PgpSignature.SubkeyBinding);
            signature.InitVerify(masterKey);
            IsTrue(signature.VerifyCertification(masterKey, subKey));
        }

        [Test]
        public void Version5InlineSignatureTest()
        {
            // Verify v5 Inline Signature generated by OpenPGP.js 5.5.0
            // https://tests.sequoia-pgp.org/#Inline_Sign-Verify_roundtrip_with_key__Emma_
            byte[] message = Base64.Decode(
                "xA0DAQoWGTR7yYckZAIByxR1AGXgdslIZWxsbyBXb3JsZCA6KcJ3BQEWCgAp" +
                "BQJl4HbJIiEFGTR7yYckZAJfmd8+wuAADtmISJLh97PqTJQAkVlWm1QAADsI" +
                "AQD7aH9a0GKcHdFThMsOQ88xAM5PiqPyDV1A/K23rPN28wD/QoPa1yEE3Y2R" +
                "ZtqtH6jAymdyIwtsa5wLvzUjTmP5OQo=");

            PgpPublicKeyRing pubRing = new PgpPublicKeyRing(v5Certificate);
            PgpPublicKey signer = pubRing.GetPublicKey();

            PgpObjectFactory factory = new PgpObjectFactory(message);

            PgpOnePassSignatureList opss = factory.NextPgpObject() as PgpOnePassSignatureList;
            IsEquals(opss.Count, 1);
            PgpOnePassSignature ops = opss[0];
            IsEquals(ops.Version, OnePassSignaturePacket.Version3);

            ops.InitVerify(signer);
            PgpLiteralData literal = factory.NextPgpObject() as PgpLiteralData;
            using (Stream dIn = literal.GetInputStream())
            {
                byte[] buffer = new byte[30];
                int bytesRead;
                while ((bytesRead = dIn.Read(buffer, 0, buffer.Length)) > 0)
                {
                    ops.Update(buffer, 0, bytesRead);
                }
            }

            PgpSignatureList sigs = factory.NextPgpObject() as PgpSignatureList;
            IsEquals(sigs.Count, 1);
            byte[] metadata = literal.GetMetadata(sigs[0].Version);
            IsTrue(ops.Verify(sigs[0], metadata));
        }

        [Test]
        public void SeipdVersion2WithMultipleMethodsTest()
        {
            // Encrypt-Decrypt roundtrip V6 SKESK/PKESK, V2 SEIPD, AES-256 in EAX mode
            // multiple different passwords and public keys with different algorithms
            // and S2K schemes
            byte[] largePlaintext = new byte[50000];
            Arrays.Fill(largePlaintext, (byte)'A');
            byte[] enc;

            byte[][] passwords = new byte[][]
            {
                Encoding.UTF8.GetBytes("password"),
                Encoding.UTF8.GetBytes("drowssap"),
                Encoding.UTF8.GetBytes("P@ssw0rd")
            };

            var alice = new PgpPublicKeyRing(alicePubkey).GetPublicKeys().First(k => k.IsEncryptionKey);
            var bob = new PgpPublicKeyRing(bobPubkey).GetPublicKeys().First(k => k.IsEncryptionKey);
            var v6 = new PgpPublicKeyRing(v6Certificate).GetPublicKeys().First(k => k.IsEncryptionKey);
            var carol = new PgpPublicKeyRing(carolPubkey).GetPublicKeys().First(k => k.IsEncryptionKey);

            PgpPrivateKey[] privateKeys = new PgpPrivateKey[]
            {
                new PgpSecretKeyRing(aliceSecretkey).GetSecretKey(alice.KeyId).ExtractPrivateKey(emptyPassphrase),
                new PgpSecretKeyRing(bobSecretkey).GetSecretKey(bob.KeyId).ExtractPrivateKey(emptyPassphrase),
                new PgpSecretKeyRing(v6UnlockedSecretKey).GetSecretKey(v6.KeyId).ExtractPrivateKey(emptyPassphrase)
            };

            var gen = new PgpEncryptedDataGenerator(SymmetricKeyAlgorithmTag.Aes256, AeadAlgorithmTag.Eax);
            gen.AddMethodRaw(passwords[0], S2k.Argon2Parameters.UniversallyRecommendedParameters());
            gen.AddMethodRaw(passwords[1], S2k.Argon2Parameters.MemoryConstrainedParameters());
            gen.AddMethodRaw(passwords[2], HashAlgorithmTag.Sha256);
            gen.AddMethod(alice);
            gen.AddMethod(bob);
            gen.AddMethod(v6);

            // Check constraint: An implementation MUST NOT generate ElGamal v6 PKESKs.
            // https://www.rfc-editor.org/rfc/rfc9580#name-algorithm-specific-fields-fo
            Assert.Throws<PgpException>(() =>
            {
                gen.AddMethod(carol);
            });

            using (MemoryStream ms = new MemoryStream())
            {
                byte[] buffer = new byte[3000];
                using (Stream cOut = gen.Open(ms, buffer))
                {
                    using (BcpgOutputStream bcOut = new BcpgOutputStream(cOut, newFormatOnly: true))
                    {
                        PgpLiteralDataGenerator literalDataGen = new PgpLiteralDataGenerator();
                        DateTime modificationTime = DateTime.UtcNow;

                        using (Stream lOut = literalDataGen.Open(
                            new UncloseableStream(bcOut),
                            PgpLiteralData.Utf8,
                            PgpLiteralData.Console,
                            largePlaintext.Length,
                            modificationTime))
                        {
                            lOut.Write(largePlaintext, 0, largePlaintext.Length);
                        }
                    }
                }
                enc = ms.ToArray();
            }

            // decrypt
            for (int i = 0; i < passwords.Length; i++)
            {
                PgpObjectFactory factory = new PgpObjectFactory(enc);
                PgpEncryptedDataList encDataList = factory.NextPgpObject() as PgpEncryptedDataList;
                PgpPbeEncryptedData encData = encDataList[i] as PgpPbeEncryptedData;
                using (Stream stream = encData.GetDataStreamRaw(passwords[i]))
                {
                    factory = new PgpObjectFactory(stream);
                    PgpLiteralData lit = factory.NextPgpObject() as PgpLiteralData;
                    using (MemoryStream ms = new MemoryStream())
                    {
                        lit.GetDataStream().CopyTo(ms);
                        byte[] decrypted = ms.ToArray();
                        IsTrue(Arrays.AreEqual(largePlaintext, decrypted));
                    }
                }
            }

            for (int i = 0; i < privateKeys.Length; i++)
            {
                PgpObjectFactory factory = new PgpObjectFactory(enc);
                PgpEncryptedDataList encDataList = factory.NextPgpObject() as PgpEncryptedDataList;
                PgpPublicKeyEncryptedData encData = encDataList[3+i] as PgpPublicKeyEncryptedData;
                
                using (Stream stream = encData.GetDataStream(privateKeys[i]))
                    {
                        factory = new PgpObjectFactory(stream);
                        PgpLiteralData lit = factory.NextPgpObject() as PgpLiteralData;
                        using (MemoryStream ms = new MemoryStream())
                        {
                            lit.GetDataStream().CopyTo(ms);
                            byte[] decrypted = ms.ToArray();
                            IsTrue(Arrays.AreEqual(largePlaintext, decrypted));
                        }
                    }
            }
        }

        public override string Name => "PgpInteroperabilityTestSuite";

        public override void PerformTest()
        {
            MultiplePkeskTest();
            SeipdVersion2WithMultipleMethodsTest();

            MultipleInlineSignatureTest();
            GenerateAndVerifyMultipleInlineSignatureTest();

            MultipleDetachedSignatureTest();
            GenerateAndVerifyMultipleDetachedSignatureTest();

            Version5KeyParsingTest();
            Version5InlineSignatureTest();
        }
    }
}
