package com.home.jwtValidator;

import io.jsonwebtoken.Claims;
import io.jsonwebtoken.ExpiredJwtException;
import io.jsonwebtoken.Jws;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.MalformedJwtException;
import io.jsonwebtoken.UnsupportedJwtException;
import io.jsonwebtoken.security.Keys;
import io.jsonwebtoken.security.SignatureException;

import java.nio.charset.StandardCharsets;
import java.time.Instant;
import java.time.ZoneOffset;
import java.time.format.DateTimeFormatter;
import java.util.Date;

public class JwtValidatorApp {

    // Секрет для HMAC-SHA256 (минимум 32 символа / 256 бит)
    private static final String SECRET_KEY = "a-string-secret-at-least-256-bits-long";

    private static final String TOKEN_TO_VALIDATE =
            "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiYWRtaW4iOnRydWUsImlhdCI6MTUxNjIzOTAyMn0.KMUFsIDTnFmyG3nMiGM6H9FNFUROf3wh7SmqJp-QV30";

    public static void main(String[] args) {
        System.out.println("══════════════════════════════════════════");
        System.out.println("🔐 НАЧАЛО ВАЛИДАЦИИ JWT ТОКЕНА");
        System.out.println("══════════════════════════════════════════\n");

        System.out.println("📝 Шаг 1: Проверка формата JWT (Header.Payload.Signature)...");
        if (TOKEN_TO_VALIDATE == null || TOKEN_TO_VALIDATE.isBlank()) {
            System.out.println("❌ Ошибка: Токен пуст или null.");
            return;
        }
        String[] parts = TOKEN_TO_VALIDATE.trim().split("\\.");
        if (parts.length != 3) {
            System.out.println("❌ Ошибка: Токен не является валидным JWT (ожидается 3 части, найдено: " + parts.length + ").");
            return;
        }
        System.out.println("✅ Формат корректен. Обнаружены Header, Payload, Signature.\n");

        System.out.println("🔑 Шаг 2: Инициализация ключа подписи...");
        byte[] keyBytes = SECRET_KEY.getBytes(StandardCharsets.UTF_8);
        if (keyBytes.length < 32) {
            System.out.println("❌ Ошибка: Секретный ключ слишком короткий (< 32 символа). Требуется минимум 256 бит.");
            return;
        }
        var signingKey = Keys.hmacShaKeyFor(keyBytes);
        System.out.println("✅ Ключ успешно сформирован (алгоритм: HMAC-SHA256).\n");

        System.out.println("🔍 Шаг 3: Парсинг и криптографическая проверка подписи...");
        try {
            Jws<Claims> jws = Jwts.parserBuilder()
                    .setSigningKey(signingKey)
                    .setAllowedClockSkewSeconds(30)
                    .build()
                    .parseClaimsJws(TOKEN_TO_VALIDATE);

            System.out.println("✅ Подпись верна. Целостность данных подтверждена.\n");

            System.out.println("⏱️  Шаг 4: Анализ пейлоада и проверка временных меток (UTC)...");
            Claims claims = jws.getBody();
            Instant now = Instant.now();
            DateTimeFormatter fmt = DateTimeFormatter.ofPattern("yyyy-MM-dd HH:mm:ss z").withZone(ZoneOffset.UTC);

            // Безопасный вывод стандартных клеймов
            System.out.println("   • Issuer (iss): " + (claims.getIssuer() == null ? "❌ Отсутствует" : claims.getIssuer()));
            System.out.println("   • Subject (sub): " + (claims.getSubject() == null ? "❌ Отсутствует" : claims.getSubject()));

            Date iatDate = claims.getIssuedAt();
            System.out.println("   • Issued At (iat): " + (iatDate == null ? "❌ Отсутствует" : fmt.format(iatDate.toInstant())));

            Date expDate = claims.getExpiration();
            if (expDate == null) {
                System.out.println("   • Expiration (exp): ❌ Отсутствует (токен бессрочный)");
                System.out.println("⚠️  Внимание: Токен не имеет срока действия. В production это критический риск безопасности.");
            } else {
                Instant expInstant = expDate.toInstant();
                System.out.println("   • Expiration (exp): " + fmt.format(expInstant));
                System.out.println("   • Текущее время сервера (UTC): " + fmt.format(now));

                if (expInstant.isBefore(now)) {
                    System.out.println("❌ Ошибка: Токен просрочен! (exp < current_time)");
                    return;
                }
                System.out.println("✅ Срок действия токена актуален.");
            }
            System.out.println();

            System.out.println("══════════════════════════════════════════");
            System.out.println("🟢 ВАЛИДАЦИЯ ПРОШЛА УСПЕШНО");
            System.out.println("══════════════════════════════════════════");
            System.out.println("📦 Полный пейлоад (Claims):");
            claims.forEach((k, v) -> System.out.println("   " + k + " = " + v));
            System.out.println("📌 Токен безопасен для использования в сессии.\n");

        } catch (ExpiredJwtException e) {
            System.out.println("❌ Ошибка: Токен просрочен. Время истечения: " + e.getClaims().getExpiration());
        } catch (UnsupportedJwtException e) {
            System.out.println("❌ Ошибка: Токен создан неподдерживаемым алгоритмом или форматом.");
        } catch (MalformedJwtException e) {
            System.out.println("❌ Ошибка: Нарушена структура JWT (некорректный base64url или повреждённые части).");
        } catch (SignatureException e) {
            System.out.println("❌ Ошибка: Подпись не совпадает! Токен изменён или сгенерирован другим ключом.");
        } catch (IllegalArgumentException e) {
            System.out.println("❌ Ошибка: Пустой или null токен передан на вход.");
        } catch (Exception e) {
            System.out.println("💥 Неожиданная ошибка: " + e.getClass().getSimpleName() + " → " + e.getMessage());
            e.printStackTrace();
        }
    }
}