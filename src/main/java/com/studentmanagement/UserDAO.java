
package com.studentmanagement;

import java.sql.Connection;
import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.sql.SQLException;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.SecureRandom;
import java.security.GeneralSecurityException;
import java.util.Base64;

import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.PBEKeySpec;

public class UserDAO {

    private static final int ITERATIONS = 600000;
    private static final int KEY_LENGTH = 256;
    private static final int SALT_LENGTH = 16;

    public User login(String username, String password) {

        if (username == null || password == null) {
            return null;
        }

        String sql = "SELECT * FROM users WHERE username = ?";

        try (
            Connection con = DBConnection.getConnection();
            PreparedStatement ps = con.prepareStatement(sql)
        ) {
            ps.setString(1, username);

            try (ResultSet rs = ps.executeQuery()) {

                if (rs.next()) {

                    String storedHash = rs.getString("password");

                    if (!verifyPassword(password, storedHash)) {
                        return null;
                    }

                    User user = new User();
                    user.setUserId(rs.getInt("user_id"));
                    user.setUsername(rs.getString("username"));
                    user.setRole(rs.getString("role"));

                    return user;
                }
            }

        } catch (SQLException e) {
            System.err.println("Login database error");
            e.printStackTrace();
        }

        return null;
    }

    public static String hashPassword(String password) {

        byte[] salt = new byte[SALT_LENGTH];
        new SecureRandom().nextBytes(salt);

        byte[] hash = deriveKey(password, salt, ITERATIONS);

        return "pbkdf2_sha256:" + ITERATIONS + ":"
                + Base64.getEncoder().encodeToString(salt)
                + ":"
                + Base64.getEncoder().encodeToString(hash);
    }

    public static boolean verifyPassword(
            String password, String storedHash) {

        if (password == null || storedHash == null) {
            return false;
        }

        try {
            String[] parts = storedHash.split(":");

            if (parts.length != 4 ||
                    !parts[0].equals("pbkdf2_sha256")) {
                return false;
            }

            int iterations = Integer.parseInt(parts[1]);

            if (iterations < 100000 ||
                    iterations > 1000000) {
                return false;
            }

            byte[] salt = Base64.getDecoder().decode(parts[2]);
            byte[] expected = Base64.getDecoder().decode(parts[3]);

            if (salt.length != SALT_LENGTH ||
                    expected.length != KEY_LENGTH / 8) {
                return false;
            }

            byte[] actual = deriveKey(
                    password, salt, iterations);

            return MessageDigest.isEqual(expected, actual);

        } catch (IllegalArgumentException e) {
            return false;
        }
    }

    private static byte[] deriveKey(
            String password, byte[] salt, int iterations) {

        PBEKeySpec spec = new PBEKeySpec(
                password.toCharArray(),
                salt,
                iterations,
                KEY_LENGTH
        );

        try {
            SecretKeyFactory factory =
                    SecretKeyFactory.getInstance(
                            "PBKDF2WithHmacSHA256");

            return factory.generateSecret(spec).getEncoded();

        } catch (GeneralSecurityException e) {
            throw new IllegalStateException(
                    "Password hashing failed", e);

        } finally {
            spec.clearPassword();
        }
    }
}
