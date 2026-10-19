package com.cybermonitor.evaluation;

import com.cybermonitor.evaluation.LabeledDataset.Attack;
import com.cybermonitor.model.LogEvent;

import java.time.Instant;
import java.util.ArrayList;
import java.util.Comparator;
import java.util.HashSet;
import java.util.List;
import java.util.Random;
import java.util.Set;
import java.util.UUID;

/**
 * Generates a labeled synthetic authentication-log dataset from a seed (same seed, same data).
 *
 * <p>Normal traffic: successful logins plus "forgetful users" who mistype their password 1 to 4
 * times before succeeding. Those users are deliberately included, because a rule that flags
 * "failures then success" will wrongly flag some of them: that is a real weakness worth measuring.
 *
 * <p>Injected attacks, each from its own external address:
 * <ul>
 *   <li>BRUTE_FORCE: 6 to 30 failed logins, 0 to 2 s apart, no success;</li>
 *   <li>COMPROMISE: 4 to 15 failures 0.5 to 3 s apart, then a successful login;</li>
 *   <li>LOW_AND_SLOW: 8 to 12 failures 20 to 60 s apart. Rules with a short window cannot see these.</li>
 * </ul>
 */
public class DatasetGenerator {

    public static final Instant START = Instant.parse("2026-01-01T08:00:00Z");
    private static final long HORIZON_SECONDS = 8 * 3600;
    private static final int USER_COUNT = 20;

    private final long seed;
    private final int normalLogins;
    private final int forgetfulSequences;
    private final int bruteForceAttacks;
    private final int compromiseAttacks;
    private final int lowAndSlowAttacks;

    public DatasetGenerator(long seed, int normalLogins, int forgetfulSequences, int bruteForceAttacks,
                            int compromiseAttacks, int lowAndSlowAttacks) {
        this.seed = seed;
        this.normalLogins = normalLogins;
        this.forgetfulSequences = forgetfulSequences;
        this.bruteForceAttacks = bruteForceAttacks;
        this.compromiseAttacks = compromiseAttacks;
        this.lowAndSlowAttacks = lowAndSlowAttacks;
    }

    /** The standard dataset size: 2000 normal logins, 60 forgetful users, 50 attacks. */
    public static DatasetGenerator standard(long seed) {
        return new DatasetGenerator(seed, 2000, 60, 25, 15, 10);
    }

    public LabeledDataset generate() {
        Random random = new Random(seed);
        List<LogEvent> events = new ArrayList<>();
        List<Attack> attacks = new ArrayList<>();

        for (int i = 0; i < normalLogins; i++) {
            int user = random.nextInt(USER_COUNT);
            events.add(event(random, START.plusMillis(randomMillis(random, HORIZON_SECONDS)),
                    internalIp(user), "LOGIN_OK", userName(user), "Login successful"));
        }
        for (int i = 0; i < forgetfulSequences; i++) {
            int user = random.nextInt(USER_COUNT);
            Instant time = START.plusMillis(randomMillis(random, HORIZON_SECONDS));
            int failures = 1 + random.nextInt(4);
            for (int f = 0; f < failures; f++) {
                events.add(event(random, time, internalIp(user), "LOGIN_FAILED", userName(user), "Invalid password"));
                time = time.plusMillis(2000 + random.nextInt(13_000));
            }
            events.add(event(random, time, internalIp(user), "LOGIN_OK", userName(user), "Login successful"));
        }

        int attackNumber = 0;
        for (int i = 0; i < bruteForceAttacks; i++) {
            attacks.add(attack(random, events, "BRUTE_FORCE", ++attackNumber,
                    6 + random.nextInt(25), 200, 2000, false));
        }
        for (int i = 0; i < compromiseAttacks; i++) {
            attacks.add(attack(random, events, "COMPROMISE", ++attackNumber,
                    4 + random.nextInt(12), 500, 3000, true));
        }
        for (int i = 0; i < lowAndSlowAttacks; i++) {
            attacks.add(attack(random, events, "LOW_AND_SLOW", ++attackNumber,
                    8 + random.nextInt(5), 20_000, 60_000, false));
        }

        events.sort(Comparator.comparing(LogEvent::timestamp).thenComparing(LogEvent::id));
        return new LabeledDataset(seed, events, attacks);
    }

    private Attack attack(Random random, List<LogEvent> events, String type, int number, int failures,
                          int minGapMillis, int maxGapMillis, boolean endsWithSuccess) {
        String ip = "203.0.113." + number; // external address, one per attack
        String user = random.nextBoolean() ? "root" : userName(random.nextInt(USER_COUNT));
        Instant time = START.plusMillis(randomMillis(random, HORIZON_SECONDS - 3600));
        Set<String> ids = new HashSet<>();
        for (int f = 0; f < failures; f++) {
            LogEvent failed = event(random, time, ip, "LOGIN_FAILED", user, "Invalid password");
            events.add(failed);
            ids.add(failed.id());
            time = time.plusMillis(minGapMillis + random.nextInt(maxGapMillis - minGapMillis + 1));
        }
        if (endsWithSuccess) {
            time = time.plusMillis(2000 + random.nextInt(18_000));
            LogEvent success = event(random, time, ip, "LOGIN_OK", user, "Login successful");
            events.add(success);
            ids.add(success.id());
        }
        return new Attack(type + "-" + number, type, ip, ids);
    }

    private LogEvent event(Random random, Instant time, String ip, String type, String user, String text) {
        time = time.truncatedTo(java.time.temporal.ChronoUnit.SECONDS); // the log format has 1 s resolution
        String raw = AuthLogFormat.format(time, "sshd", user, ip, type, text);
        return new LogEvent(new UUID(random.nextLong(), random.nextLong()).toString(), time, ip, type, user,
                null, "sshd: " + text, raw);
    }

    private static long randomMillis(Random random, long seconds) {
        return (long) (random.nextDouble() * seconds * 1000);
    }

    private static String userName(int index) {
        return "user" + (index + 1);
    }

    private static String internalIp(int userIndex) {
        return "10.0.1." + (userIndex + 10);
    }
}
