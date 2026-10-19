package com.cybermonitor.service;

import com.cybermonitor.exception.CyberShieldException;
import com.cybermonitor.parser.AuthLogParser;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.List;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

class LogImportServiceTest {

    private final LogImportService service = new LogImportService();
    private final AuthLogParser parser = new AuthLogParser();

    @Test
    void countsImportedIgnoredAndMalformedLinesSeparately() {
        List<String> lines = List.of(
                "# header",
                "",
                "2026-01-01 10:00:01 sshd user=a src=1.1.1.1 LOGIN_OK",
                "garbage",
                "2026-01-01 10:00:02 sshd user=a src=1.1.1.1 LOGIN_FAILED");

        ImportResult result = service.importLines("test.log", lines, parser);

        assertEquals(5, result.totalLines());
        assertEquals(2, result.ignoredLines());
        assertEquals(1, result.malformedLines());
        assertEquals(2, result.importedLines());
        assertEquals(5, result.importedLines() + result.ignoredLines() + result.malformedLines());
    }

    @Test
    void malformedSamplesNameTheLineNumberAndAreCapped() {
        List<String> lines = new ArrayList<>();
        lines.add("2026-01-01 10:00:01 sshd user=a src=1.1.1.1 LOGIN_OK");
        for (int i = 0; i < 25; i++) {
            lines.add("bad line " + i);
        }

        ImportResult result = service.importLines("test.log", lines, parser);

        assertEquals(25, result.malformedLines());
        assertEquals(LogImportService.MAX_MALFORMED_SAMPLES, result.malformedSamples().size());
        assertTrue(result.malformedSamples().get(0).startsWith("line 2:"));
    }

    @Test
    void emptyInputGivesAnEmptyResult() {
        ImportResult result = service.importLines("empty.log", List.of(), parser);

        assertEquals(0, result.totalLines());
        assertTrue(result.events().isEmpty());
    }

    @Test
    void readsARealFileFromDisk(@TempDir Path folder) throws Exception {
        Path file = folder.resolve("auth.log");
        Files.writeString(file, "2026-01-01 10:00:01 sshd user=a src=1.1.1.1 LOGIN_OK\nnot valid\n");

        ImportResult result = service.importFile(file, parser);

        assertEquals("auth.log", result.fileName());
        assertEquals(1, result.importedLines());
        assertEquals(1, result.malformedLines());
    }

    @Test
    void invalidUtf8BytesDoNotCrashTheImport(@TempDir Path folder) throws Exception {
        Path file = folder.resolve("bytes.log");
        byte[] prefix = "2026-01-01 10:00:01 sshd user=a src=1.1.1.1 LOGIN_OK caf".getBytes("UTF-8");
        byte[] bytes = new byte[prefix.length + 2];
        System.arraycopy(prefix, 0, bytes, 0, prefix.length);
        bytes[prefix.length] = (byte) 0xC3; // a broken UTF-8 sequence
        bytes[prefix.length + 1] = (byte) 0x28;
        Files.write(file, bytes);

        ImportResult result = service.importFile(file, parser);

        assertEquals(1, result.importedLines());
    }

    @Test
    void aMissingFileIsReportedClearly(@TempDir Path folder) {
        assertThrows(CyberShieldException.class, () -> service.importFile(folder.resolve("nope.log"), parser));
    }

    @Test
    void theBundledSampleFileImportsAsDocumented() {
        ImportResult result = service.importFile(Path.of("data/sample/auth_sample.log"), parser);

        assertEquals(2, result.malformedLines());
        assertEquals(22, result.importedLines());
    }
}
