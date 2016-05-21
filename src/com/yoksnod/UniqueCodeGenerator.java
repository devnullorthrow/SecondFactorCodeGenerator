package com.yoksnod;

import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;
import java.lang.reflect.UndeclaredThrowableException;
import java.math.BigInteger;
import java.security.GeneralSecurityException;
import java.text.DateFormat;
import java.text.SimpleDateFormat;
import java.util.Date;
import java.util.TimeZone;

public class UniqueCodeGenerator {



    /*    Time (UTC format)
    *     public static final long[] TEST_TIME = new long[]{
            1970-01-01 00:00:59
            2005-03-18 01:58:29
            2005-03-18 01:58:31
            2009-02-13 23:31:30
            2033-05-18 03:33:20
            2603-10-11 11:33:20
            */
    public static final long[] TEST_TIME = new long[]{
            9L,
            1000000009L,
            1000000011L,
            1234567890L,
            1888888888L,
            9876543210L,
            19999999999L};

    public static final String DELIMITER_LEFT = "|===============|=======================|";
    public static final String DELIMITER_RIGHT = "==================|========|========|";
    public static final String DATE_FORMAT = "yyyy-MM-dd HH:mm:ss";
    public static final String UTC = "UTC";
    public static final int RADIX = 16;
    public static final String DEFAULT_DIGITS = "8";
    public static final int HEX_COUNT = 16;

    private UniqueCodeGenerator() {
    }

    private static byte[] calcHmacSha(String cryptoAlgorithm,
                                      byte[] keyBytes,
                                      byte[] message) {
        try {
            final Mac hmac;
            hmac = Mac.getInstance(cryptoAlgorithm);
            SecretKeySpec macKey =
                    new SecretKeySpec(keyBytes, "RAW");
            hmac.init(macKey);
            return hmac.doFinal(message);
        } catch (GeneralSecurityException gse) {
            throw new UndeclaredThrowableException(gse);
        }
    }


    private static byte[] convertHexToBytes(String hexRepresetnation) {

        byte[] binaryArray = new BigInteger(String.format("10%s", hexRepresetnation), RADIX).toByteArray();

        byte[] result = new byte[binaryArray.length - 1];
        System.arraycopy(binaryArray, 1, result, 0, result.length);
        return result;
    }

    private static final int[] DIGITS_POWER
            // 0  1   2    3     4      5       6        7         8
            = {1, 10, 100, 1000, 10000, 100000, 1000000, 10000000, 100000000};

    public static String generateSequence(String seed,
                                          String time,
                                          String digits,
                                          String cryptoAlgorithm) {
        int codeDigits = Integer.decode(digits);
        String result = null;

        while (time.length() < HEX_COUNT){
            time = "0" + time;
        }

        // Get the HEX in a Byte[]
        byte[] msgBytes = convertHexToBytes(time);
        byte[] seedBytes = convertHexToBytes(seed);


        byte[] hash = calcHmacSha(cryptoAlgorithm, seedBytes, msgBytes);

        // put selected bytes into result int
        int offset = hash[hash.length - 1] & 15;

        int binary =
                ((hash[offset] & 127) << 24) |
                        ((hash[offset + 1] & 255) << 16) |
                        ((hash[offset + 2] & 255) << 8) |
                        (hash[offset + 3] & 255);

        int sequence = binary % DIGITS_POWER[codeDigits];

        result = String.valueOf(sequence);
        while (result.length() < codeDigits) {
            result = "0" + result;
        }
        return result;
    }

    public static void main(String[] args) {
        // Seed for HMAC-SHA1 - 20 bytes
        String seed =
                "2342334546547565345543510547767678767676";
        // Seed for HMAC-SHA256 - 32 bytes
        String seed32 =
                "2342334546547565345543510547767678767676" +
                "234233454654756534554351";
        // Seed for HMAC-SHA512 - 64 bytes
        String seed64 =
                "2342334546547565345543510547767678767676" +
                "2342334546547565345543510547767678767676" +
                "2342334546547565345543510547767678767676" +
                "23423345";
        long offset = 30;

        String steps;
        DateFormat date = new SimpleDateFormat(DATE_FORMAT);
        date.setTimeZone(TimeZone.getTimeZone(UTC));


        try {
            System.out.println(
                    DELIMITER_LEFT +
                            DELIMITER_RIGHT);
            System.out.println(
                    "|    Time(sec)  |     Time   (UTC)      " +
                            "|    time(Hex)     |  Seq   |  Mode  |");
            System.out.println(
                    DELIMITER_LEFT +
                            DELIMITER_RIGHT);

            for (long each : TEST_TIME) {
                long timeResult = (each) / offset;
                steps = Long.toHexString(timeResult).toUpperCase();
                while (steps.length() < 16){
                    steps = String.format("0%s", steps);
                }
                String formatted = String.format("%1$-11s", each);
                String utc = date.format(new Date(each * 1000));
                System.out.print("|  " + formatted + "  |  " + utc +
                        "  | " + steps + " |");
                System.out.println(generateSequence(seed, steps, DEFAULT_DIGITS,
                        "HmacSHA1") + "| SHA1   |");
                System.out.print("|  " + formatted + "  |  " + utc +
                        "  | " + steps + " |");
                System.out.println(generateSequence(seed32, steps, DEFAULT_DIGITS,
                        "HmacSHA256") + "| SHA256 |");
                System.out.print("|  " + formatted + "  |  " + utc +
                        "  | " + steps + " |");
                System.out.println(generateSequence(seed64, steps, DEFAULT_DIGITS,
                        "HmacSHA512") + "| SHA512 |");

                System.out.println(
                        DELIMITER_LEFT +
                                DELIMITER_RIGHT);

            }
        } catch (Exception e) {
            System.out.println("Error : " + e);
        }
    }
}