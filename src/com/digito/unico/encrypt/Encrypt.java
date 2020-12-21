package com.digito.unico.encrypt;


import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.Base64;
import javax.crypto.Cipher;

public class Encrypt {

    enum Action {
        GENERATE_KEYS, DECRYPT, ENCRYPT;
    }

    public static void main (String args[]) {
        Action action = validateAction(args);

        if(action == Action.GENERATE_KEYS) {
            generateAndPrintKeys();
        } else if (action == Action.DECRYPT) {
            decryptText(args[1], args[2]);
        } else if (action == Action.ENCRYPT) {
            encryptText(args[1], args[2]);
        } else {
            printMsgErrorInvalidArgs();
        }
    }


    private static void generateAndPrintKeys() {
        KeyPairGenerator keyPairGenerator;
        try {
            keyPairGenerator = KeyPairGenerator.getInstance("RSA");
        } catch (Exception e) {
            throw new RuntimeException("Erro ao gerar chaves publica e privada. " + e.getMessage());
        }
        keyPairGenerator.initialize(2048);
        KeyPair keyPair = keyPairGenerator.generateKeyPair();
        PrivateKey privateKey = keyPair.getPrivate();
        PublicKey publicKey = keyPair.getPublic();

        byte[] publicString = Base64.getEncoder().encode(publicKey.getEncoded());
        byte[] privateString = Base64.getEncoder().encode(privateKey.getEncoded());

        System.out.println("\n\nChave privada:\n\n" + new String(privateString) + "\n");
        System.out.println("Chave publica:\n\n" + new String(publicString) + "\n");
    }

    private static void decryptText (String encryptedText, String privateKey) {
        PrivateKey privateKeyFromStr = generatePrivateKeyFromString(privateKey);
        String descryptedText = decryptMessage(encryptedText, privateKeyFromStr);
        System.out.println("\n\nTexto:\n\n" + descryptedText);
    }

    private static void encryptText(String plainText, String publicKey) {
        PublicKey publicKeyFromStr = generatePublicKeyFromString(publicKey);
        String encryptedText = encryptMessage(plainText, publicKeyFromStr);
        System.out.println("\n\nTexto criptografado:\n\n" + encryptedText);
    }

    private static PrivateKey generatePrivateKeyFromString (String privateKey) {
        byte [] pkcs8EncodedBytes = Base64.getDecoder().decode(privateKey);

        PKCS8EncodedKeySpec keySpec = new PKCS8EncodedKeySpec(pkcs8EncodedBytes);
        KeyFactory kf;
        PrivateKey privKey;

        try {
            kf = KeyFactory.getInstance("RSA");
            privKey = kf.generatePrivate(keySpec);
        } catch (Exception e) {
            throw new RuntimeException("Erro ao gerar chave privada. " + e.getMessage());
        }

        return privKey;
    }

    private static PublicKey generatePublicKeyFromString (String publicKey) {
        PublicKey pubKey;
        try {
            KeyFactory kf = KeyFactory.getInstance("RSA");
            X509EncodedKeySpec keySpecX509 = new X509EncodedKeySpec(Base64.getDecoder().decode(publicKey));
            pubKey = kf.generatePublic(keySpecX509);
        } catch (Exception e) {
            throw new RuntimeException("Erro ao gerar chave publica. " + e.getMessage());
        }

        return pubKey;
    }

    private static String decryptMessage(String encryptedText, PrivateKey privateKey) {
        Cipher cipher;
        try {
            cipher = Cipher.getInstance("RSA");
            cipher.init(Cipher.DECRYPT_MODE, privateKey);
            return new String(cipher.doFinal(Base64.getDecoder().decode(encryptedText)));
        } catch (Exception e) {
            throw new RuntimeException("Erro descriptografar o texto. " + e.getMessage());
        }
    }

    private static String encryptMessage(String plainText, PublicKey publicKey) {
        Cipher cipher;
        try {
            cipher = Cipher.getInstance("RSA");
            cipher.init(Cipher.ENCRYPT_MODE, publicKey);
            return Base64.getEncoder().encodeToString(cipher.doFinal(plainText.getBytes()));
        } catch (Exception e) {
            throw new RuntimeException("Erro descriptografar o texto. " + e.getMessage());
        }
    }

    private static void printMsgErrorInvalidArgs() {
        StringBuilder sb = new StringBuilder();
        sb.append("\n\nErro! Acoes permitidas:\n\n")
                .append("Descriptografar: -d <textoEncriptado> <chavePrivada>\n")
                .append("Criptografar: -c <texto> <chavePublic>\n")
                .append("Gerar chaves: -g");

        System.out.println(sb.toString());
    }

    private static Action validateAction (String args[]) {

        if(args.length == 3 && args[0].equals("-d")) {
            return Action.DECRYPT;
        } else if(args.length == 3 && args[0].equals("-c")) {
            return Action.ENCRYPT;
        } else if (args.length == 1 && args[0].equals("-g")) {
            return Action.GENERATE_KEYS ;
        } else {
            return null;
        }
    }
}
