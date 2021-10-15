using System;
using System.IO;

using NUnit.Framework;

using Org.BouncyCastle.Utilities;
using Org.BouncyCastle.Utilities.Encoders;
using Org.BouncyCastle.Utilities.IO;
using Org.BouncyCastle.Utilities.Test;

namespace Org.BouncyCastle.Bcpg.OpenPgp.Tests
{
    [TestFixture]
    public class ArmoredInputStreamTest
        : SimpleTest
    {
        private static readonly byte[] bogusData = Hex.Decode(
            "ed864b3c622d5d71d43e5bd77876e81bfaaba8522f64cb494dc897daa3494f7da598f5907b758b72394fbefea77b86a16865e7bf" +
            "b8f5bb46bb0d2db4a99a6a4542b9040a0e4f74b8e202c4eb255e8a81a59be9c0d5d2c593b8b512c9bdc75a243cb0992b5a885889" +
            "a4a3d3d70e1fcb415d4f718e8230b11895e3706314912554d7c19dafb733df7d02e9a2f42492139648618b1943af9e2941bd0e42" +
            "73b58de9b734d15a793a6d7673b3e90dedebc2a479965680de61880dddea25c0168237a6e52846e6a5aa9fb9161ac7a3996315cf" +
            "7d391cb86e86cce44e2a353b68cf84d3ac49eddde9a040180533af4aade92de7a03c1982020a2591141aeffd2ad07ffbc0d0a303" +
            "710763f47317a5c468d18e69e4094945060f707778cd65b4e94c2e27b5e5a8f4d510e01c9f84b22e1c59486a9b72552682833a07" +
            "23995febde56a59d31b60b2cdac00efbf693ac27607c8c4a502749bc7bde65ec80c661aadada4611e3093607d8c7927bf4b29ea9" +
            "0481a4616952abb88cb2f4ad78c2e94ba9193f0d0dac17d972ed0b6a738a11a6f27a3a5857e9a0746c5acb2a33ea05491e23db39" +
            "657549b5b1a341f2088232b5c72c1a3fcce6dd8b1ce8ade51977521e473b6b208458ce513606daf47689c9a239e161cc592f070f" +
            "395a2b964547954516651fc122a781b336d3ddc529c37c16022e6882ba52a6ff9ffd1e362971096997053e916953ca6146eb9973" +
            "a28663074692fa3d216b4f169d20e32655602461dce525db1d94b9c43620e05a9e2d3465bb7ed0c07493738434bcf058a73b22ab" +
            "0fd6ade1b995b3129d791e3f3a9446d35d9fe521ba5f196f98e7b637132aaa2df424ddb4e372cb70ede1eacdf0b454de91ae279f" +
            "ec3c16e268f262a169a2d9ecb27ac1ae177fa6f31f63991179b35e5a48d5cd0e369f50f92cf0327bde1cbd8125201b0c0e4c9242" +
            "d416cf48a9ac9c367ab424999fdf3cf5faac259b302b68c417f1461380a57d4f6a5bad8e60ac2140af53f3b44b2e4a44383e597e" +
            "f0d7594d2f8c74346a7759b13364bf7abe08663ed4d2ab92bd60231d71e63c125739c446c048e76b7157c644ad6e136f3078c79a" +
            "27d505af22b25706c4cf1aec5cb9578e0d0f0471fabdbfc4504a4f971b2c68a4af75ff9a438b1e4c3507dd93c38dc8caa43e87c3" +
            "95e27d9b23402671e1a8a6f9563ba8e9d00d2f99d77d25bdda2ac4fe363db138a6eeea4ec1a5ae104cc30b9e4f468799335157da" +
            "a9f4c310ef0806ef1803d81db84f58b45639a1749c705594cf5dbbe6109af4711eb080af4edd0d0386c09676b705d3a0ccad5cc7" +
            "b5f289a884ce649b5b00b46ad33ee43b0db8c0202cf1fdde4c3b61d5fec99e3024016ccdb0ff2d321f08781d08e4312de38245eb" +
            "bc2af032d2a59e36be6467bc23456b4ac178d36cf9f45df5e833a1981ed1a1032679ea0a");

        private static readonly string badHeaderData1 =
              "-----BEGIN PGP MESSAGE-----\n"
            + "Version: BCPG v1.32\n"
            + "Comment: A dummy message\n"
            + "Comment actually not really as there is no colon"
            + " \t \t\n"
            + "SGVsbG8gV29ybGQh\n"
            + "=d9Xi\n"
            + "-----END PGP MESSAGE-----\n";

        private static readonly string badHeaderData2 =
              "-----BEGIN PGP MESSAGE-----\n"
            + "Comment actually not really as there is no colon"
            + " \t \t\n"
            + "SGVsbG8gV29ybGQh\n"
            + "=d9Xi\n"
            + "-----END PGP MESSAGE-----\n";

        // See https://tests.sequoia-pgp.org/#Mangled_ASCII_Armored_Key (Blank line with '\t\r\v\f')
        public static readonly string ARMOR_WITH_BACKSLASH_T_R_V_F = "" +
            "-----BEGIN PGP PRIVATE KEY BLOCK-----\n" +
            "Comment: Bob's OpenPGP Transferable Secret Key\n" +
            " \t\n" +
            "\u000B\f\n" +
            "lQVYBF2lnPIBDAC5cL9PQoQLTMuhjbYvb4Ncuuo0bfmgPRFywX53jPhoFf4Zg6mv\n" +
            "/seOXpgecTdOcVttfzC8ycIKrt3aQTiwOG/ctaR4Bk/t6ayNFfdUNxHWk4WCKzdz\n" +
            "/56fW2O0F23qIRd8UUJp5IIlN4RDdRCtdhVQIAuzvp2oVy/LaS2kxQoKvph/5pQ/\n" +
            "5whqsyroEWDJoSV0yOb25B/iwk/pLUFoyhDG9bj0kIzDxrEqW+7Ba8nocQlecMF3\n" +
            "X5KMN5kp2zraLv9dlBBpWW43XktjcCZgMy20SouraVma8Je/ECwUWYUiAZxLIlMv\n" +
            "9CurEOtxUw6N3RdOtLmYZS9uEnn5y1UkF88o8Nku890uk6BrewFzJyLAx5wRZ4F0\n" +
            "qV/yq36UWQ0JB/AUGhHVPdFf6pl6eaxBwT5GXvbBUibtf8YI2og5RsgTWtXfU7eb\n" +
            "SGXrl5ZMpbA6mbfhd0R8aPxWfmDWiIOhBufhMCvUHh1sApMKVZnvIff9/0Dca3wb\n" +
            "vLIwa3T4CyshfT0AEQEAAQAL/RZqbJW2IqQDCnJi4Ozm++gPqBPiX1RhTWSjwxfM\n" +
            "cJKUZfzLj414rMKm6Jh1cwwGY9jekROhB9WmwaaKT8HtcIgrZNAlYzANGRCM4TLK\n" +
            "3VskxfSwKKna8l+s+mZglqbAjUg3wmFuf9Tj2xcUZYmyRm1DEmcN2ZzpvRtHgX7z\n" +
            "Wn1mAKUlSDJZSQks0zjuMNbupcpyJokdlkUg2+wBznBOTKzgMxVNC9b2g5/tMPUs\n" +
            "hGGWmF1UH+7AHMTaS6dlmr2ZBIyogdnfUqdNg5sZwsxSNrbglKP4sqe7X61uEAIQ\n" +
            "bD7rT3LonLbhkrj3I8wilUD8usIwt5IecoHhd9HziqZjRCc1BUBkboUEoyedbDV4\n" +
            "i4qfsFZ6CEWoLuD5pW7dEp0M+WeuHXO164Rc+LnH6i1VQrpb1Okl4qO6ejIpIjBI\n" +
            "1t3GshtUu/mwGBBxs60KBX5g77mFQ9lLCRj8lSYqOsHRKBhUp4qM869VA+fD0BRP\n" +
            "fqPT0I9IH4Oa/A3jYJcg622GwQYA1LhnP208Waf6PkQSJ6kyr8ymY1yVh9VBE/g6\n" +
            "fRDYA+pkqKnw9wfH2Qho3ysAA+OmVOX8Hldg+Pc0Zs0e5pCavb0En8iFLvTA0Q2E\n" +
            "LR5rLue9uD7aFuKFU/VdcddY9Ww/vo4k5p/tVGp7F8RYCFn9rSjIWbfvvZi1q5Tx\n" +
            "+akoZbga+4qQ4WYzB/obdX6SCmi6BndcQ1QdjCCQU6gpYx0MddVERbIp9+2SXDyL\n" +
            "hpxjSyz+RGsZi/9UAshT4txP4+MZBgDfK3ZqtW+h2/eMRxkANqOJpxSjMyLO/FXN\n" +
            "WxzTDYeWtHNYiAlOwlQZEPOydZFty9IVzzNFQCIUCGjQ/nNyhw7adSgUk3+BXEx/\n" +
            "MyJPYY0BYuhLxLYcrfQ9nrhaVKxRJj25SVHj2ASsiwGJRZW4CC3uw40OYxfKEvNC\n" +
            "mer/VxM3kg8qqGf9KUzJ1dVdAvjyx2Hz6jY2qWCyRQ6IMjWHyd43C4r3jxooYKUC\n" +
            "YnstRQyb/gCSKahveSEjo07CiXMr88UGALwzEr3npFAsPW3osGaFLj49y1oRe11E\n" +
            "he9gCHFm+fuzbXrWmdPjYU5/ZdqdojzDqfu4ThfnipknpVUM1o6MQqkjM896FHm8\n" +
            "zbKVFSMhEP6DPHSCexMFrrSgN03PdwHTO6iBaIBBFqmGY01tmJ03SxvSpiBPON9P\n" +
            "NVvy/6UZFedTq8A07OUAxO62YUSNtT5pmK2vzs3SAZJmbFbMh+NN204TRI72GlqT\n" +
            "t5hcfkuv8hrmwPS/ZR6q312mKQ6w/1pqO9qitCFCb2IgQmFiYmFnZSA8Ym9iQG9w\n" +
            "ZW5wZ3AuZXhhbXBsZT6JAc4EEwEKADgCGwMFCwkIBwIGFQoJCAsCBBYCAwECHgEC\n" +
            "F4AWIQTRpm4aI7GCyZgPeIz7/MgqAV5zMAUCXaWe+gAKCRD7/MgqAV5zMG9sC/9U\n" +
            "2T3RrqEbw533FPNfEflhEVRIZ8gDXKM8hU6cqqEzCmzZT6xYTe6sv4y+PJBGXJFX\n" +
            "yhj0g6FDkSyboM5litOcTupURObVqMgA/Y4UKERznm4fzzH9qek85c4ljtLyNufe\n" +
            "doL2pp3vkGtn7eD0QFRaLLmnxPKQ/TlZKdLE1G3u8Uot8QHicaR6GnAdc5UXQJE3\n" +
            "BiV7jZuDyWmZ1cUNwJkKL6oRtp+ZNDOQCrLNLecKHcgCqrpjSQG5oouba1I1Q6Vl\n" +
            "sP44dhA1nkmLHtxlTOzpeHj4jnk1FaXmyasurrrI5CgU/L2Oi39DGKTH/A/cywDN\n" +
            "4ZplIQ9zR8enkbXquUZvFDe+Xz+6xRXtb5MwQyWODB3nHw85HocLwRoIN9WdQEI+\n" +
            "L8a/56AuOwhs8llkSuiITjR7r9SgKJC2WlAHl7E8lhJ3VDW3ELC56KH308d6mwOG\n" +
            "ZRAqIAKzM1T5FGjMBhq7ZV0eqdEntBh3EcOIfj2M8rg1MzJv+0mHZOIjByawikad\n" +
            "BVgEXaWc8gEMANYwv1xsYyunXYK0X1vY/rP1NNPvhLyLIE7NpK90YNBj+xS1ldGD\n" +
            "bUdZqZeef2xJe8gMQg05DoD1DF3GipZ0Ies65beh+d5hegb7N4pzh0LzrBrVNHar\n" +
            "29b5ExdI7i4iYD5TO6Vr/qTUOiAN/byqELEzAb+L+b2DVz/RoCm4PIp1DU9ewcc2\n" +
            "WB38Ofqut3nLYA5tqJ9XvAiEQme+qAVcM3ZFcaMt4I4dXhDZZNg+D9LiTWcxdUPB\n" +
            "leu8iwDRjAgyAhPzpFp+nWoqWA81uIiULWD1Fj+IVoY3ZvgivoYOiEFBJ9lbb4te\n" +
            "g9m5UT/AaVDTWuHzbspVlbiVe+qyB77C2daWzNyx6UYBPLOo4r0t0c91kbNE5lgj\n" +
            "Z7xz6los0N1U8vq91EFSeQJoSQ62XWavYmlCLmdNT6BNfgh4icLsT7Vr1QMX9jzn\n" +
            "JtTPxdXytSdHvpSpULsqJ016l0dtmONcK3z9mj5N5z0k1tg1AH970TGYOe2aUcSx\n" +
            "IRDMXDOPyzEfjwARAQABAAv9F2CwsjS+Sjh1M1vegJbZjei4gF1HHpEM0K0PSXsp\n" +
            "SfVvpR4AoSJ4He6CXSMWg0ot8XKtDuZoV9jnJaES5UL9pMAD7JwIOqZm/DYVJM5h\n" +
            "OASCh1c356/wSbFbzRHPtUdZO9Q30WFNJM5pHbCJPjtNoRmRGkf71RxtvHBzy7np\n" +
            "Ga+W6U/NVKHw0i0CYwMI0YlKDakYW3Pm+QL+gHZFvngGweTod0f9l2VLLAmeQR/c\n" +
            "+EZs7lNumhuZ8mXcwhUc9JQIhOkpO+wreDysEFkAcsKbkQP3UDUsA1gFx9pbMzT0\n" +
            "tr1oZq2a4QBtxShHzP/ph7KLpN+6qtjks3xB/yjTgaGmtrwM8tSe0wD1RwXS+/1o\n" +
            "BHpXTnQ7TfeOGUAu4KCoOQLv6ELpKWbRBLWuiPwMdbGpvVFALO8+kvKAg9/r+/ny\n" +
            "zM2GQHY+J3Jh5JxPiJnHfXNZjIKLbFbIPdSKNyJBuazXW8xIa//mEHMI5OcvsZBK\n" +
            "clAIp7LXzjEjKXIwHwDcTn9pBgDpdOKTHOtJ3JUKx0rWVsDH6wq6iKV/FTVSY5jl\n" +
            "zN+puOEsskF1Lfxn9JsJihAVO3yNsp6RvkKtyNlFazaCVKtDAmkjoh60XNxcNRqr\n" +
            "gCnwdpbgdHP6v/hvZY54ZaJjz6L2e8unNEkYLxDt8cmAyGPgH2XgL7giHIp9jrsQ\n" +
            "aS381gnYwNX6wE1aEikgtY91nqJjwPlibF9avSyYQoMtEqM/1UjTjB2KdD/MitK5\n" +
            "fP0VpvuXpNYZedmyq4UOMwdkiNMGAOrfmOeT0olgLrTMT5H97Cn3Yxbk13uXHNu/\n" +
            "ZUZZNe8s+QtuLfUlKAJtLEUutN33TlWQY522FV0m17S+b80xJib3yZVJteVurrh5\n" +
            "HSWHAM+zghQAvCesg5CLXa2dNMkTCmZKgCBvfDLZuZbjFwnwCI6u/NhOY9egKuUf\n" +
            "SA/je/RXaT8m5VxLYMxwqQXKApzD87fv0tLPlVIEvjEsaf992tFEFSNPcG1l/jpd\n" +
            "5AVXw6kKuf85UkJtYR1x2MkQDrqY1QX/XMw00kt8y9kMZUre19aCArcmor+hDhRJ\n" +
            "E3Gt4QJrD9z/bICESw4b4z2DbgD/Xz9IXsA/r9cKiM1h5QMtXvuhyfVeM01enhxM\n" +
            "GbOH3gjqqGNKysx0UODGEwr6AV9hAd8RWXMchJLaExK9J5SRawSg671ObAU24SdY\n" +
            "vMQ9Z4kAQ2+1ReUZzf3ogSMRZtMT+d18gT6L90/y+APZIaoArLPhebIAGq39HLmJ\n" +
            "26x3z0WAgrpA1kNsjXEXkoiZGPLKIGoe3hqJAbYEGAEKACAWIQTRpm4aI7GCyZgP\n" +
            "eIz7/MgqAV5zMAUCXaWc8gIbDAAKCRD7/MgqAV5zMOn/C/9ugt+HZIwX308zI+QX\n" +
            "c5vDLReuzmJ3ieE0DMO/uNSC+K1XEioSIZP91HeZJ2kbT9nn9fuReuoff0T0Dief\n" +
            "rbwcIQQHFFkrqSp1K3VWmUGp2JrUsXFVdjy/fkBIjTd7c5boWljv/6wAsSfiv2V0\n" +
            "JSM8EFU6TYXxswGjFVfc6X97tJNeIrXL+mpSmPPqy2bztcCCHkWS5lNLWQw+R7Vg\n" +
            "71Fe6yBSNVrqC2/imYG2J9zlowjx1XU63Wdgqp2Wxt0l8OmsB/W80S1fRF5G4SDH\n" +
            "s9HXglXXqPsBRZJYfP+VStm9L5P/sKjCcX6WtZR7yS6G8zj/X767MLK/djANvpPd\n" +
            "NVniEke6hM3CNBXYPAMhQBMWhCulcoz+0lxi8L34rMN+Dsbma96psdUrn7uLaB91\n" +
            "6we0CTfF8qqm7BsVAgalon/UUiuMY80U3ueoj3okiSTiHIjD/YtpXSPioC8nMng7\n" +
            "xqAY9Bwizt4FWgXuLm1a4+So4V9j1TRCXd12Uc2l2RNmgDE=\n" +
            "=miES\n" +
            "-----END PGP PRIVATE KEY BLOCK-----";

        private static readonly string ASCII_ARMOR_CRC_MISMATCH = "" +
            "-----BEGIN PGP MESSAGE-----\n" +
            "Version: FlowCrypt 5.0.4 Gmail Encryption flowcrypt.com\n" +
            "Comment: Seamlessly send, receive and search encrypted email\n" +
            "\n" +
            "wcFMA+ADv/5v4RgKAQ/+K2rrAqhjMe9FLCfklI9Y30Woktg0Q/xe71EVw6WO\n" +
            "tVD/VK+xv4CHzi+HojtE0U2F+vqoPSO0q5TN9giKPMTiK25PnCzfd7Q+zXiF\n" +
            "j+5RSHTVJxC62qLHhtKsAQtC4asub8cQIFXbZz3Ns4+7jKtSWPcRqhKTurWv\n" +
            "XVH0YAFJDsFYo26r2V9c+Ie0uoQPx8graEGpKO9GtoQjXMKK32oApuBSSlmS\n" +
            "Q+nxyxMx1V+gxP4qgGBCxqkBFRYB/Ve6ygNHL1KxxCVTEw9pgnxJscn89Iio\n" +
            "dO6qZ9EgIV0PVQN0Yw033MTgAhCHunlE/qXvDxib4tdihoNsLN0q5kdOeiMW\n" +
            "+ntm3kphjMpQ6TMCUGtdS7UmvnadZ+dh5s785M8S9oY64mQd6QuYA2iy1IQv\n" +
            "q3zpW4/ba2gqL36qCCw/OaruXpQ4NeBr3hMaJQjWgeSuMsQnNGYUn5Nn1+9X\n" +
            "wtlithO8eLi3M1dg19dpDky8CacWfGgHD7SNsZ2zqFqyd1qtdFcit5ynQUHS\n" +
            "IiJKeUknGv1dQAnPPJ1FdXyyqC/VDBZG6CNdnxjonmQDRh1YlqNwSnmrR/Sy\n" +
            "X7n+nGra+/0EHJW6ohaSdep2jAwJDelq/DI1lqiN16ZXJ2/WH6pItA9tmkLU\n" +
            "61QUz6qwPAnd0t6iy/YkOi2/s1+dwC0DwOcZoUPF8bTBwUwDS1ov/OYtlQEB\n" +
            "D/46rCPRZrX34ipseTkZxtw3YPhbNkNHo95Mzh9lpeaaZIqtUg2yiFUnhwLi\n" +
            "tYwyBCkXCb92l1GXXxGSmvSLDSKfQfIpZ0rV5j50MYKIpjSeJZyH/3qP+JXv\n" +
            "Z47GsTp0z5/oNau5XQwuhLhUtRoZd1WS9ahSJ1akiKeYJroLbTg10fjL25yp\n" +
            "iaoV16SqKA1H/JOuj6lT5z1nuez35JjeSpUc7ksdot60ZovMfWC+OGRnkYKb\n" +
            "7KxFd7uaxL6uOBOFyvRxYeohKd73aVkiKpcWd4orI18FhlftFNAwIdsmfzNc\n" +
            "mzTHZaUl89iYxEKR6ae6AKws1wzLq0noarsf2eKBVbTSfmK3S3xFqduKINnc\n" +
            "e5Yb3F5adSj1dUjm1BZ4aqzsgKyBb+J8keG9ESsnFOyxOIUXDM1nIo1IOgzC\n" +
            "M928Jb9GVa+uhdXRrb5cLjTihTusJN0I8oJrwKkwIpCJVgPMdDLkeubrMBQ4\n" +
            "fbpl4V76sOU2Nx+6nG2FnFBFBFohOL+0nTK5/6Ns9ateN7K9VP++QcoeqfPk\n" +
            "IUO3+lCZW+trTSvvFId3ziUVsPTeuAS+7nxSMfWZ/K9Ci6QV/Xnx3F/qSmuS\n" +
            "AUm4zPQ1EjZf1N/5K+vhcCTN4MMx406VlqtedkXL2KPwZ6jDS/ww8RfcmPnD\n" +
            "s94ct0WCZZtNlnQq+5h0ybwTJNLC2QFyrhhPqztVY95n9La2Mw5WITCWzg/d\n" +
            "IBUceW/OwHYtePyaSQkCnegDw/2mN2/GC8d0OlwULcTYG6uVenGv2UOUbCr3\n" +
            "Pfy/Eb/VqUEZK00PdvVQV7FWYAshuTFPTqidph04CgQvBpi3SDEEo8SkEIFS\n" +
            "/iEeRQaWjFEXKUI3FwKXPJQWvFpbrXBOAjnxXXbAFYOLxdydmq1GVl9Mm3GU\n" +
            "Clc9g6t9vaYDBPx2gN562/CM/nT8Vq45VHe79XkrrcHDwLn7yeHJScNFsib+\n" +
            "VvwTPoUftlhC/ai21D403TsJpm7ZmPcDjagoIcXrS/lN03z79RBmSKFtYiXW\n" +
            "4obkKSGow61vMBh2/XLVYKJKpYKm/GnVlJxA0zQVl558x8I/nAMaxSzwx+ZY\n" +
            "waVU/s5PLZ7Ghg3MOguiRTlflKUQyL0A7NR46OjFgUnHAZRxr4KO3GoxVPy4\n" +
            "XLeS4+Wl68s7QlV6WF1IKCHWEUMEeRRea2/OvvlS/oLs2MNNWDemlJ4SiXHf\n" +
            "xINU38Txo84A00NALbKppsSyy9Gwj//rO/FcerupkfeuOm9nHFwIQeeC5bWD\n" +
            "mmRlC90r2jY8gM/v3Jjy9h8PbXWxh9MUpc7/kAcTwdGlMxiVjE29p065qTRr\n" +
            "Oi6sJ7pWuYTfWldZqTVmaBjlv0zuXQ8Eo8o/USvoTs+oihYIMcqReqdeqr/N\n" +
            "e+sDtYKRg/LKp/JJ5nAQzVMP67DxkgwLNxx0ijBLysaQmvRlsiYWayxZB1Xd\n" +
            "BxA2bjZRvsmww+hgSKNlcsiubJGBqfqvgmlebZuJHHSC1L6mdMYgcihKmYAj\n" +
            "p+HFLyqgyeRVMdjRHcrEdxNPG4fJmlk1bYiVQQ4XAd72w+AHS/seZ5HzbAK0\n" +
            "omuHYUD5PTEqZ1K9JObSsh3XMUkJK+z3BnrOxnTOOyG2r+4FxizH6rfz/Pgg\n" +
            "sPxqxE9ELUlgQe8plcPFge6aN9tUoSe+vMtDaEAqKw9JwofBF7jlxTqMMvQC\n" +
            "gWbn9x3W5o4VrnpjYGtPl8sh1QREu0A+0PUJAKL4A3GSMYRouGewLSMNJlOg\n" +
            "/0pPF6qB+Fi4GJ7ju5C07tfr9z9UqRj09kDXJuoJd95NdSiCz6ndugn6gs8B\n" +
            "Qf/XPxZVefeMLiB6p8pG0iZ/jcJjyYJLtTg6kA+1/ffmJPfH/76ZA9dgEJLj\n" +
            "/W2u0Lp4NY8cwqcXuGKgl72TVJ34Iawl35Y0yr47k/7Y1vEQ5Q3bT7HP5A==\n" +
            "=FdCC\n" +
            "-----END PGP MESSAGE-----";

    public static readonly string KEY_WITH_MISSING_CRC = "-----BEGIN PGP PRIVATE KEY BLOCK-----\n" +
            "Comment: Bob's OpenPGP Transferable Secret Key\n" +
            "\n" +
            "lQVYBF2lnPIBDAC5cL9PQoQLTMuhjbYvb4Ncuuo0bfmgPRFywX53jPhoFf4Zg6mv\n" +
            "/seOXpgecTdOcVttfzC8ycIKrt3aQTiwOG/ctaR4Bk/t6ayNFfdUNxHWk4WCKzdz\n" +
            "/56fW2O0F23qIRd8UUJp5IIlN4RDdRCtdhVQIAuzvp2oVy/LaS2kxQoKvph/5pQ/\n" +
            "5whqsyroEWDJoSV0yOb25B/iwk/pLUFoyhDG9bj0kIzDxrEqW+7Ba8nocQlecMF3\n" +
            "X5KMN5kp2zraLv9dlBBpWW43XktjcCZgMy20SouraVma8Je/ECwUWYUiAZxLIlMv\n" +
            "9CurEOtxUw6N3RdOtLmYZS9uEnn5y1UkF88o8Nku890uk6BrewFzJyLAx5wRZ4F0\n" +
            "qV/yq36UWQ0JB/AUGhHVPdFf6pl6eaxBwT5GXvbBUibtf8YI2og5RsgTWtXfU7eb\n" +
            "SGXrl5ZMpbA6mbfhd0R8aPxWfmDWiIOhBufhMCvUHh1sApMKVZnvIff9/0Dca3wb\n" +
            "vLIwa3T4CyshfT0AEQEAAQAL/RZqbJW2IqQDCnJi4Ozm++gPqBPiX1RhTWSjwxfM\n" +
            "cJKUZfzLj414rMKm6Jh1cwwGY9jekROhB9WmwaaKT8HtcIgrZNAlYzANGRCM4TLK\n" +
            "3VskxfSwKKna8l+s+mZglqbAjUg3wmFuf9Tj2xcUZYmyRm1DEmcN2ZzpvRtHgX7z\n" +
            "Wn1mAKUlSDJZSQks0zjuMNbupcpyJokdlkUg2+wBznBOTKzgMxVNC9b2g5/tMPUs\n" +
            "hGGWmF1UH+7AHMTaS6dlmr2ZBIyogdnfUqdNg5sZwsxSNrbglKP4sqe7X61uEAIQ\n" +
            "bD7rT3LonLbhkrj3I8wilUD8usIwt5IecoHhd9HziqZjRCc1BUBkboUEoyedbDV4\n" +
            "i4qfsFZ6CEWoLuD5pW7dEp0M+WeuHXO164Rc+LnH6i1VQrpb1Okl4qO6ejIpIjBI\n" +
            "1t3GshtUu/mwGBBxs60KBX5g77mFQ9lLCRj8lSYqOsHRKBhUp4qM869VA+fD0BRP\n" +
            "fqPT0I9IH4Oa/A3jYJcg622GwQYA1LhnP208Waf6PkQSJ6kyr8ymY1yVh9VBE/g6\n" +
            "fRDYA+pkqKnw9wfH2Qho3ysAA+OmVOX8Hldg+Pc0Zs0e5pCavb0En8iFLvTA0Q2E\n" +
            "LR5rLue9uD7aFuKFU/VdcddY9Ww/vo4k5p/tVGp7F8RYCFn9rSjIWbfvvZi1q5Tx\n" +
            "+akoZbga+4qQ4WYzB/obdX6SCmi6BndcQ1QdjCCQU6gpYx0MddVERbIp9+2SXDyL\n" +
            "hpxjSyz+RGsZi/9UAshT4txP4+MZBgDfK3ZqtW+h2/eMRxkANqOJpxSjMyLO/FXN\n" +
            "WxzTDYeWtHNYiAlOwlQZEPOydZFty9IVzzNFQCIUCGjQ/nNyhw7adSgUk3+BXEx/\n" +
            "MyJPYY0BYuhLxLYcrfQ9nrhaVKxRJj25SVHj2ASsiwGJRZW4CC3uw40OYxfKEvNC\n" +
            "mer/VxM3kg8qqGf9KUzJ1dVdAvjyx2Hz6jY2qWCyRQ6IMjWHyd43C4r3jxooYKUC\n" +
            "YnstRQyb/gCSKahveSEjo07CiXMr88UGALwzEr3npFAsPW3osGaFLj49y1oRe11E\n" +
            "he9gCHFm+fuzbXrWmdPjYU5/ZdqdojzDqfu4ThfnipknpVUM1o6MQqkjM896FHm8\n" +
            "zbKVFSMhEP6DPHSCexMFrrSgN03PdwHTO6iBaIBBFqmGY01tmJ03SxvSpiBPON9P\n" +
            "NVvy/6UZFedTq8A07OUAxO62YUSNtT5pmK2vzs3SAZJmbFbMh+NN204TRI72GlqT\n" +
            "t5hcfkuv8hrmwPS/ZR6q312mKQ6w/1pqO9qitCFCb2IgQmFiYmFnZSA8Ym9iQG9w\n" +
            "ZW5wZ3AuZXhhbXBsZT6JAc4EEwEKADgCGwMFCwkIBwIGFQoJCAsCBBYCAwECHgEC\n" +
            "F4AWIQTRpm4aI7GCyZgPeIz7/MgqAV5zMAUCXaWe+gAKCRD7/MgqAV5zMG9sC/9U\n" +
            "2T3RrqEbw533FPNfEflhEVRIZ8gDXKM8hU6cqqEzCmzZT6xYTe6sv4y+PJBGXJFX\n" +
            "yhj0g6FDkSyboM5litOcTupURObVqMgA/Y4UKERznm4fzzH9qek85c4ljtLyNufe\n" +
            "doL2pp3vkGtn7eD0QFRaLLmnxPKQ/TlZKdLE1G3u8Uot8QHicaR6GnAdc5UXQJE3\n" +
            "BiV7jZuDyWmZ1cUNwJkKL6oRtp+ZNDOQCrLNLecKHcgCqrpjSQG5oouba1I1Q6Vl\n" +
            "sP44dhA1nkmLHtxlTOzpeHj4jnk1FaXmyasurrrI5CgU/L2Oi39DGKTH/A/cywDN\n" +
            "4ZplIQ9zR8enkbXquUZvFDe+Xz+6xRXtb5MwQyWODB3nHw85HocLwRoIN9WdQEI+\n" +
            "L8a/56AuOwhs8llkSuiITjR7r9SgKJC2WlAHl7E8lhJ3VDW3ELC56KH308d6mwOG\n" +
            "ZRAqIAKzM1T5FGjMBhq7ZV0eqdEntBh3EcOIfj2M8rg1MzJv+0mHZOIjByawikad\n" +
            "BVgEXaWc8gEMANYwv1xsYyunXYK0X1vY/rP1NNPvhLyLIE7NpK90YNBj+xS1ldGD\n" +
            "bUdZqZeef2xJe8gMQg05DoD1DF3GipZ0Ies65beh+d5hegb7N4pzh0LzrBrVNHar\n" +
            "29b5ExdI7i4iYD5TO6Vr/qTUOiAN/byqELEzAb+L+b2DVz/RoCm4PIp1DU9ewcc2\n" +
            "WB38Ofqut3nLYA5tqJ9XvAiEQme+qAVcM3ZFcaMt4I4dXhDZZNg+D9LiTWcxdUPB\n" +
            "leu8iwDRjAgyAhPzpFp+nWoqWA81uIiULWD1Fj+IVoY3ZvgivoYOiEFBJ9lbb4te\n" +
            "g9m5UT/AaVDTWuHzbspVlbiVe+qyB77C2daWzNyx6UYBPLOo4r0t0c91kbNE5lgj\n" +
            "Z7xz6los0N1U8vq91EFSeQJoSQ62XWavYmlCLmdNT6BNfgh4icLsT7Vr1QMX9jzn\n" +
            "JtTPxdXytSdHvpSpULsqJ016l0dtmONcK3z9mj5N5z0k1tg1AH970TGYOe2aUcSx\n" +
            "IRDMXDOPyzEfjwARAQABAAv9F2CwsjS+Sjh1M1vegJbZjei4gF1HHpEM0K0PSXsp\n" +
            "SfVvpR4AoSJ4He6CXSMWg0ot8XKtDuZoV9jnJaES5UL9pMAD7JwIOqZm/DYVJM5h\n" +
            "OASCh1c356/wSbFbzRHPtUdZO9Q30WFNJM5pHbCJPjtNoRmRGkf71RxtvHBzy7np\n" +
            "Ga+W6U/NVKHw0i0CYwMI0YlKDakYW3Pm+QL+gHZFvngGweTod0f9l2VLLAmeQR/c\n" +
            "+EZs7lNumhuZ8mXcwhUc9JQIhOkpO+wreDysEFkAcsKbkQP3UDUsA1gFx9pbMzT0\n" +
            "tr1oZq2a4QBtxShHzP/ph7KLpN+6qtjks3xB/yjTgaGmtrwM8tSe0wD1RwXS+/1o\n" +
            "BHpXTnQ7TfeOGUAu4KCoOQLv6ELpKWbRBLWuiPwMdbGpvVFALO8+kvKAg9/r+/ny\n" +
            "zM2GQHY+J3Jh5JxPiJnHfXNZjIKLbFbIPdSKNyJBuazXW8xIa//mEHMI5OcvsZBK\n" +
            "clAIp7LXzjEjKXIwHwDcTn9pBgDpdOKTHOtJ3JUKx0rWVsDH6wq6iKV/FTVSY5jl\n" +
            "zN+puOEsskF1Lfxn9JsJihAVO3yNsp6RvkKtyNlFazaCVKtDAmkjoh60XNxcNRqr\n" +
            "gCnwdpbgdHP6v/hvZY54ZaJjz6L2e8unNEkYLxDt8cmAyGPgH2XgL7giHIp9jrsQ\n" +
            "aS381gnYwNX6wE1aEikgtY91nqJjwPlibF9avSyYQoMtEqM/1UjTjB2KdD/MitK5\n" +
            "fP0VpvuXpNYZedmyq4UOMwdkiNMGAOrfmOeT0olgLrTMT5H97Cn3Yxbk13uXHNu/\n" +
            "ZUZZNe8s+QtuLfUlKAJtLEUutN33TlWQY522FV0m17S+b80xJib3yZVJteVurrh5\n" +
            "HSWHAM+zghQAvCesg5CLXa2dNMkTCmZKgCBvfDLZuZbjFwnwCI6u/NhOY9egKuUf\n" +
            "SA/je/RXaT8m5VxLYMxwqQXKApzD87fv0tLPlVIEvjEsaf992tFEFSNPcG1l/jpd\n" +
            "5AVXw6kKuf85UkJtYR1x2MkQDrqY1QX/XMw00kt8y9kMZUre19aCArcmor+hDhRJ\n" +
            "E3Gt4QJrD9z/bICESw4b4z2DbgD/Xz9IXsA/r9cKiM1h5QMtXvuhyfVeM01enhxM\n" +
            "GbOH3gjqqGNKysx0UODGEwr6AV9hAd8RWXMchJLaExK9J5SRawSg671ObAU24SdY\n" +
            "vMQ9Z4kAQ2+1ReUZzf3ogSMRZtMT+d18gT6L90/y+APZIaoArLPhebIAGq39HLmJ\n" +
            "26x3z0WAgrpA1kNsjXEXkoiZGPLKIGoe3hqJAbYEGAEKACAWIQTRpm4aI7GCyZgP\n" +
            "eIz7/MgqAV5zMAUCXaWc8gIbDAAKCRD7/MgqAV5zMOn/C/9ugt+HZIwX308zI+QX\n" +
            "c5vDLReuzmJ3ieE0DMO/uNSC+K1XEioSIZP91HeZJ2kbT9nn9fuReuoff0T0Dief\n" +
            "rbwcIQQHFFkrqSp1K3VWmUGp2JrUsXFVdjy/fkBIjTd7c5boWljv/6wAsSfiv2V0\n" +
            "JSM8EFU6TYXxswGjFVfc6X97tJNeIrXL+mpSmPPqy2bztcCCHkWS5lNLWQw+R7Vg\n" +
            "71Fe6yBSNVrqC2/imYG2J9zlowjx1XU63Wdgqp2Wxt0l8OmsB/W80S1fRF5G4SDH\n" +
            "s9HXglXXqPsBRZJYfP+VStm9L5P/sKjCcX6WtZR7yS6G8zj/X767MLK/djANvpPd\n" +
            "NVniEke6hM3CNBXYPAMhQBMWhCulcoz+0lxi8L34rMN+Dsbma96psdUrn7uLaB91\n" +
            "6we0CTfF8qqm7BsVAgalon/UUiuMY80U3ueoj3okiSTiHIjD/YtpXSPioC8nMng7\n" +
            "xqAY9Bwizt4FWgXuLm1a4+So4V9j1TRCXd12Uc2l2RNmgDE=\n" +
            "-----END PGP PRIVATE KEY BLOCK-----";

        public override string Name
        {
            get { return "ArmoredInputStream"; }
        }

        public override void PerformTest()
        {
            try
            {
                PgpObjectFactory pgpObjectFactoryOfTestFile = new PgpObjectFactory(
                    new ArmoredInputStream(new MemoryStream(
                        Arrays.Concatenate(
                            Strings.ToByteArray("-----BEGIN PGP MESSAGE-----\n" + "Version: BCPG v1.32\n\n"),
                            bogusData),
                        false)));
                pgpObjectFactoryOfTestFile.NextPgpObject(); // <-- EXCEPTION HERE
                Fail("no exception");
            }
            catch (IOException e)
            {
                IsTrue("invalid armor".Equals(e.Message));
            }

            try
            {
                PgpObjectFactory pgpObjectFactoryOfTestFile = new PgpObjectFactory(
                    new ArmoredInputStream(new MemoryStream(
                        Strings.ToByteArray(badHeaderData1),
                        false)));
                Fail("no exception");
            }
            catch (IOException e)
            {
                IsTrue("invalid armor header".Equals(e.Message));
            }

            try
            {
                PgpObjectFactory pgpObjectFactoryOfTestFile = new PgpObjectFactory(
                    new ArmoredInputStream(new MemoryStream(
                        Strings.ToByteArray(badHeaderData2),
                        false)));
                Fail("no exception");
            }
            catch (IOException e)
            {
                IsTrue("invalid armor header".Equals(e.Message));
            }

            DoBackslashTrvfTest();
            DoCrcErrorGetsThrownTest();
            DoIgnoreMissingCrcTest();
        }

        public void DoBackslashTrvfTest()
        {
            MemoryStream bIn = new MemoryStream(Strings.ToByteArray(ARMOR_WITH_BACKSLASH_T_R_V_F), false);
            ArmoredInputStream armor = new ArmoredInputStream(bIn);

            try
            {
                PgpSecretKeyRing secretKey = new PgpSecretKeyRing(armor);
            }
            catch (IOException e)
            {
                Fail("Cannot parse armor containing blank line with '\\t\\r\\v\\f'.", e);
            }
        }

        private void DoCrcErrorGetsThrownTest()
        {
            MemoryStream bytesIn = new MemoryStream(Strings.ToByteArray(ASCII_ARMOR_CRC_MISMATCH), false);
            ArmoredInputStream armorIn = new ArmoredInputStream(bytesIn);
            MemoryStream bytesOut = new MemoryStream();

            try
            {
                Streams.PipeAll(armorIn, bytesOut);
                Fail("Expected IOException to be thrown due to CRC mismatch.");
            }
            catch (IOException e)
            {
                IsEquals("crc check failed in armored message.", e.Message);
            }
        }

        private void DoIgnoreMissingCrcTest()
        {
            MemoryStream data = new MemoryStream(Strings.ToByteArray(KEY_WITH_MISSING_CRC), false);
            ArmoredInputStream armorIn = new ArmoredInputStream(data);

            try
            {
                Streams.Drain(armorIn);
            }
            catch (IOException e)
            {
                Fail("Missing CRC sum must be ignored.", e);
            }

            data.Position = 0L;
            armorIn = new ArmoredInputStream(data);
            armorIn.SetDetectMissingCrc(false);

            try
            {
                Streams.Drain(armorIn);
            }
            catch (IOException e)
            {
                Fail("Missing CRC sum must be ignored.", e);
            }

            data.Position = 0L;
            armorIn = new ArmoredInputStream(data);
            armorIn.SetDetectMissingCrc(true);

            try
            {
                Streams.Drain(armorIn);
                Fail("Missing CRC sum MUST NOT be ignored.");
            }
            catch (IOException e)
            {
                IsEquals("crc check not found", e.Message);
                // expected
            }
        }

        public static void Main(string[] args)
        {
            RunTest(new ArmoredInputStreamTest());
        }

        [Test]
        public void TestFunction()
        {
            string resultText = Perform().ToString();

            Assert.AreEqual(Name + ": Okay", resultText);
        }
    }
}
