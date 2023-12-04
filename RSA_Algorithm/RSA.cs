using System.Numerics;
using System.Text;

namespace RSA_Algorithm;

public class RSA
{
    private static BigInteger GetGreatestCommonDivisor(BigInteger a, BigInteger b)
    {
        while (b != 0)
        {
            (a, b) = (b, a % b);
        }

        return a;
    }

    private static BigInteger MultiplicativeInverse(BigInteger a, BigInteger n)
    {
        BigInteger t = 0;
        BigInteger newT = 1;
        var r = n;
        var newR = a;

        while (newR != 0)
        {
            var quotient = r / newR;
            (t, newT) = (newT, t - quotient * newT);
            (r, newR) = (newR, r - quotient * newR);
        }

        if (t < 0)
        {
            t = t + n;
        }

        return t;
    }

    private static bool IsPrime(int number)
    {
        if (number <= 1) return false;
        if (number == 2) return true;
        if (number % 2 == 0) return false;

        var boundary = (int)Math.Floor(Math.Sqrt(number));

        for (var i = 3; i <= boundary; i += 2)
            if (number % i == 0)
                return false;

        return true;
    }

    #region Large prime numbers generation

    private static readonly int[] FirstPrimeNumbers =
    {
        2, 3, 5, 7, 11, 13, 17, 19, 23, 29,
        31, 37, 41, 43, 47, 53, 59, 61, 67,
        71, 73, 79, 83, 89, 97, 101, 103,
        107, 109, 113, 127, 131, 137, 139,
        149, 151, 157, 163, 167, 173, 179,
        181, 191, 193, 197, 199, 211, 223,
        227, 229, 233, 239, 241, 251, 257,
        263, 269, 271, 277, 281, 283, 293,
        307, 311, 313, 317, 331, 337, 347, 349
    };

    private static BigInteger GetNBitRandomNumber(int n)
    {
        var rand = new Random();

        var min = (BigInteger)Math.Pow(2, n - 1) + 1;
        var max = (BigInteger)Math.Pow(2, n) - 1;
        
        return rand.NextBigInteger(min, max + 1);
    }

    private static BigInteger GetLowLevelPrime(int n)
    {
        while (true)
        {
            var primeCandidate = GetNBitRandomNumber(n);

            foreach (int divisor in FirstPrimeNumbers)
            {
                if (primeCandidate % divisor == 0 && divisor * divisor <= primeCandidate)
                    break;
                return primeCandidate;
            }
        }
    }
    
    private static bool TrialComposite(BigInteger roundTester, BigInteger evenComponent, BigInteger millerRabinCandidate, int maxDivisionsByTwo)
    {
        if (BigInteger.ModPow(roundTester, evenComponent, millerRabinCandidate) == 1)
            return false;

        for (int i = 0; i < maxDivisionsByTwo; i++)
        {
            if (BigInteger.ModPow(roundTester, (1 << i) * evenComponent, millerRabinCandidate) == millerRabinCandidate - 1)
                return false;
        }

        return true;
    }

    static bool IsMillerRabinPassed(BigInteger millerRabinCandidate)
    {
        int maxDivisionsByTwo = 0;
        BigInteger evenComponent = millerRabinCandidate - 1;

        while (evenComponent % 2 == 0)
        {
            evenComponent >>= 1;
            maxDivisionsByTwo += 1;
        }

        // Количество проверок
        int numberOfRabinTrials = 20;
        for (int i = 0; i < (numberOfRabinTrials); i++)
        {
            var rand = new Random();
            BigInteger roundTester = rand.NextBigInteger(2, millerRabinCandidate);

            if (TrialComposite(roundTester, evenComponent, millerRabinCandidate, maxDivisionsByTwo))
                return false;
        }

        return true;
    }

    private static BigInteger GetBigPrimeNumber(int bits = 256)
    {
        while (true)
        {
            var primeCandidate = GetLowLevelPrime(bits);
            if (!IsMillerRabinPassed(primeCandidate))
            {
                continue;
            }
            return primeCandidate;
        }
    }

    #endregion

    public static ((BigInteger e, BigInteger n), (BigInteger d, BigInteger n)) GenerateKeypair(int bits = 256)
    {
        BigInteger p = GetBigPrimeNumber(bits);
        BigInteger q = GetBigPrimeNumber(bits);
        
        while (p == q)
        {
            q = GetBigPrimeNumber(bits);
        }

        var random = new Random();

        var n = p * q;

        var phi = (p - 1) * (q - 1);

        var e = random.NextBigInteger(1, phi);
        var g = GetGreatestCommonDivisor(e, phi);
        while (g != 1)
        {
            e = random.NextBigInteger(1, phi);
            g = GetGreatestCommonDivisor(e, phi);
        }

        var d = MultiplicativeInverse(e, phi);

        return ((e, n), (d, n));
    }

    public static string Encrypt((BigInteger key, BigInteger n) pk, string plainMessage)
    {
        var message = new BigInteger(Encoding.UTF8.GetBytes(plainMessage));
        
        if (message >= pk.n)
        {
            throw new InvalidOperationException("Message is too long for given key size.");
        }
        
        var encryptedMessage = BigInteger.ModPow(message, pk.key, pk.n);

        return Convert.ToBase64String(encryptedMessage.ToByteArray());
    }

    public static string Decrypt((BigInteger key, BigInteger n) pk, string cipherMessage)
    {
        var encryptedMessage = new BigInteger(Convert.FromBase64String(cipherMessage));
        
        if (encryptedMessage >= pk.n)
        {
            throw new InvalidOperationException("Cipher message is too large for given key size.");
        }
        
        var decryptedMessage = BigInteger.ModPow(encryptedMessage, pk.key, pk.n);

        return Encoding.UTF8.GetString(decryptedMessage.ToByteArray());
    }
}