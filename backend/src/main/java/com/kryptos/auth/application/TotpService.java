package com.kryptos.auth.application;

import java.io.ByteArrayOutputStream;
import java.security.SecureRandom;
import java.util.Base64;

import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;

import org.springframework.stereotype.Service;

import com.google.zxing.BarcodeFormat;
import com.google.zxing.client.j2se.MatrixToImageWriter;
import com.google.zxing.common.BitMatrix;
import com.google.zxing.qrcode.QRCodeWriter;

@Service
public class TotpService {

    private static final int SECRET_LENGTH = 32;
    private static final String ALGORITHM = "HmacSHA1";
    private static final int TIME_STEP = 30;
    private static final int CODE_LENGTH = 6;

    public String generateSecret() {
        byte[] buffer = new byte[SECRET_LENGTH];
        new SecureRandom().nextBytes(buffer);
        return Base64.getEncoder().encodeToString(buffer);
    }

    public String generateQrCode(String secret, String username, String issuer) {
        try {
            String otpauth = String.format("otpauth://totp/%s:%s?secret=%s&issuer=%s",
                    issuer, username, secret, issuer);

            QRCodeWriter writer = new QRCodeWriter();
            BitMatrix matrix = writer.encode(otpauth, BarcodeFormat.QR_CODE, 300, 300);

            ByteArrayOutputStream outputStream = new ByteArrayOutputStream();
            MatrixToImageWriter.writeToStream(matrix, "PNG", outputStream);

            return "data:image/png;base64," + Base64.getEncoder().encodeToString(outputStream.toByteArray());
        } catch (Exception e) {
            throw new RuntimeException("Failed to generate QR code", e);
        }
    }

    public boolean validate(String secret, String code) {
        if (secret == null || code == null) {
            return false;
        }

        long timeIndex = System.currentTimeMillis() / 1000 / TIME_STEP;

        for (int i = -1; i <= 1; i++) {
            if (generateCode(secret, timeIndex + i).equals(code)) {
                return true;
            }
        }

        return false;
    }

    private String generateCode(String secret, long timeIndex) {
        try {
            byte[] secretBytes = Base64.getDecoder().decode(secret);
            byte[] timeBytes = new byte[8];
            for (int i = 7; i >= 0; i--) {
                timeBytes[i] = (byte) (timeIndex & 0xFF);
                timeIndex >>= 8;
            }

            Mac mac = Mac.getInstance(ALGORITHM);
            mac.init(new SecretKeySpec(secretBytes, 0, secretBytes.length, ALGORITHM));
            byte[] hash = mac.doFinal(timeBytes);

            int offset = hash[hash.length - 1] & 0x0F;
            int truncated = ((hash[offset] & 0x7F) << 24) |
                    ((hash[offset + 1] & 0xFF) << 16) |
                    ((hash[offset + 2] & 0xFF) << 8) |
                    (hash[offset + 3] & 0xFF);

            int code = truncated % (int) Math.pow(10, CODE_LENGTH);
            return String.format("%0" + CODE_LENGTH + "d", code);
        } catch (Exception e) {
            throw new RuntimeException("Failed to generate TOTP code", e);
        }
    }
}
